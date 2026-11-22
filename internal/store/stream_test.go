package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// seqMsg é uma mensagem com o metadado completo do JetStream (sequência, pendentes e instante no stream).
type seqMsg struct {
	fakeMsg
	md jetstream.MsgMetadata
}

func (m seqMsg) Metadata() (*jetstream.MsgMetadata, error) { return &m.md, nil }

func mdAt(seq uint64, published time.Time, pending uint64) *jetstream.MsgMetadata {
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: seq}, Timestamp: published, NumPending: pending}
}

// TestStreamLost: saltos de Sequence.Stream contam as mensagens que nunca chegaram; reentrega e a primeira
// mensagem depois da partida não contam (ADR 0041 item 3, task 243).
func TestStreamLost(t *testing.T) {
	var s streamStats
	now := time.Unix(0, base)
	var gaps []uint64
	for _, seq := range []uint64{100, 101, 104, 105, 102, 105, 106} {
		gaps = append(gaps, s.observe(mdAt(seq, now, 0), now))
	}
	if want := []uint64{0, 0, 2, 0, 0, 0, 0}; !slices.Equal(gaps, want) {
		t.Fatalf("gaps %v want %v", gaps, want)
	}
	if lost, _, _ := s.snapshot(); lost != 2 {
		t.Fatalf("lost %d", lost)
	}
}

// TestStreamHealthReasons: backlog acima de 5 s e perda nos últimos 5 min degradam o store, com motivo.
func TestStreamHealthReasons(t *testing.T) {
	var s streamStats
	t0 := time.Unix(0, base)
	s.observe(mdAt(1, t0.Add(-5*time.Second), 3), t0)
	if r := s.reasons(t0); len(r) != 0 {
		t.Fatalf("backlog of 5 s must not degrade: %v", r)
	}
	if _, b, p := s.snapshotAt(t0); b != 5 || p != 3 {
		t.Fatalf("backlog %v pending %d", b, p)
	}
	s.observe(mdAt(2, t0.Add(-6200*time.Millisecond), 2), t0)
	if r := s.reasons(t0); !slices.Equal(r, []string{"ingest backlog 6s"}) {
		t.Fatalf("reasons %v", r)
	}
	s.caughtUp()
	if r := s.reasons(t0); len(r) != 0 {
		t.Fatalf("caught up: %v", r)
	}
	s.observe(mdAt(5, t0, 0), t0) // 3 e 4 perdidas
	s.observe(mdAt(10, t0.Add(time.Minute), 0), t0.Add(time.Minute))
	s.caughtUp() // consumidor em dia: sem isso o backlog cresceria com a parede (task 338)
	if r := s.reasons(t0.Add(time.Minute)); !slices.Equal(r, []string{"stream lost 6 messages in 5m"}) {
		t.Fatalf("reasons %v", r)
	}
	if r := s.reasons(t0.Add(5*time.Minute + time.Second)); !slices.Equal(r, []string{"stream lost 4 messages in 5m"}) {
		t.Fatalf("first loss must leave the window: %v", r)
	}
	if r := s.reasons(t0.Add(6*time.Minute + time.Second)); len(r) != 0 {
		t.Fatalf("5 min after the last loss: %v", r)
	}
	if lost, _, _ := s.snapshot(); lost != 6 {
		t.Fatalf("counter must not decrease: %d", lost)
	}
}

// TestIngestReadsStreamMetadata: o ingest lê o metadado de cada mensagem do lote e expõe as três métricas.
func TestIngestReadsStreamMetadata(t *testing.T) {
	in, _ := newTestIngestor(t, nil)
	m := newStoreMetrics(metricsHealth, in.flows.open, nil)
	m.registerStream(&in.stream)
	in.SetMetrics(m)
	wall := time.Unix(0, base).Add(8 * time.Second)
	in.now = func() time.Time { return wall }
	msgs := []msgSource{
		seqMsg{batch(client, mirror, protoTCP, fullTCP[:2]), *mdAt(7, time.Unix(0, base), 40)},
		seqMsg{batch(client, mirror, protoTCP, fullTCP[2:4]), *mdAt(8, time.Unix(0, base), 39)},
		seqMsg{batch(client, mirror, protoTCP, fullTCP[4:6]), *mdAt(12, time.Unix(0, base).Add(time.Second), 30)},
	}
	if err := in.process(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if r := in.stream.reasons(wall); !slices.Equal(r, []string{"ingest backlog 7s", "stream lost 3 messages in 5m"}) {
		t.Fatalf("reasons %v", r)
	}
	in.stream.clock = func() time.Time { return wall }
	problems, err := testutil.GatherAndLint(m.reg, "fs_store_stream_lost_total", "fs_store_ingest_backlog_seconds", "fs_store_ingest_pending_messages")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint %s: %s", p.Metric, p.Text)
	}
	for name, want := range map[string]float64{
		"fs_store_stream_lost_total": 3, "fs_store_ingest_backlog_seconds": 7, "fs_store_ingest_pending_messages": 30,
	} {
		mfs, err := m.reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			found = true
			mt := mf.GetMetric()[0]
			v := mt.GetGauge().GetValue() + mt.GetCounter().GetValue()
			if v != want {
				t.Errorf("%s = %v want %v", name, v, want)
			}
		}
		if !found {
			t.Errorf("missing %s", name)
		}
	}
}

// TestStreamBacklogGrowsWhileStalled: sem mensagem nova processada e sem Fetch vazio, o backlog cresce com a
// parede (health e gauge) em vez de congelar no valor do último lote; um caughtUp zera; a recriação do stream
// também (task 338).
func TestStreamBacklogGrowsWhileStalled(t *testing.T) {
	var s streamStats
	t0 := time.Unix(0, base)
	s.observe(mdAt(1, t0.Add(-100*time.Millisecond), 0), t0)
	if r := s.reasons(t0); len(r) != 0 {
		t.Fatalf("ingest in step must not degrade: %v", r)
	}
	if _, b, _ := s.snapshotAt(t0.Add(10 * time.Second)); b < 10 || b > 10.2 {
		t.Fatalf("stalled backlog = %v, want ~10.1", b)
	}
	if r := s.reasons(t0.Add(10 * time.Second)); !slices.Equal(r, []string{"ingest backlog 10s"}) {
		t.Fatalf("stalled reasons %v", r)
	}
	s.caughtUp()
	if _, b, _ := s.snapshotAt(t0.Add(time.Minute)); b != 0 {
		t.Fatalf("backlog after caughtUp = %v", b)
	}
	if r := s.reasons(t0.Add(time.Minute)); len(r) != 0 {
		t.Fatalf("reasons after caughtUp %v", r)
	}
	s.observe(mdAt(2, t0.Add(time.Minute), 0), t0.Add(time.Minute))
	s.streamRecreated(t0.Add(time.Minute))
	if _, b, _ := s.snapshotAt(t0.Add(time.Hour)); b != 0 {
		t.Fatalf("backlog after stream recreated = %v", b)
	}
}
