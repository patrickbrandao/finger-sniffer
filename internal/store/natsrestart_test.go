package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// O Fetch falhando sem parar deixa o store degraded depois de fetchFailDegraded; a recriação do stream zera o
// rastreio de sequência (a sequência recomeça em 1 sem contar perda) e deixa "stream recreated" por 5 min (task 320).
func TestStreamStatsFetchFailingAndRecreated(t *testing.T) {
	var s streamStats
	t0 := time.Unix(1_800_000_000, 0)
	md := func(seq uint64) *jetstream.MsgMetadata {
		return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: seq}, Timestamp: t0}
	}
	s.observe(md(500), t0)
	s.fetchFailed(t0)
	if got := s.reasons(t0.Add(3 * time.Second)); len(got) != 0 {
		t.Errorf("falha curta já degradada: %v", got)
	}
	if got := strings.Join(s.reasons(t0.Add(7*time.Second)), ","); !strings.Contains(got, "ingest fetch failing 7s") {
		t.Errorf("sem o motivo da falha do Fetch: %q", got)
	}
	s.fetchOK()
	if got := s.reasons(t0.Add(8 * time.Second)); len(got) != 0 {
		t.Errorf("motivo depois de o Fetch voltar: %v", got)
	}

	s.streamRecreated(t0.Add(10 * time.Second))
	if gap := s.observe(md(1), t0.Add(11*time.Second)); gap != 0 {
		t.Errorf("recomeço da sequência contado como perda: %d", gap)
	}
	if gap := s.observe(md(3), t0.Add(12*time.Second)); gap != 1 {
		t.Errorf("salto depois da recriação: %d, quer 1", gap)
	}
	if got := strings.Join(s.reasons(t0.Add(time.Minute)), ","); !strings.Contains(got, "stream recreated in 5m") {
		t.Errorf("sem o motivo da recriação: %q", got)
	}
	if got := strings.Join(s.reasons(t0.Add(6*time.Minute)), ","); strings.Contains(got, "stream recreated") {
		t.Errorf("motivo da recriação depois de 5 min: %q", got)
	}
	if s.recreatedTotal() != 1 {
		t.Errorf("recreated = %d, quer 1", s.recreatedTotal())
	}
}

// fakeBatch é um MessageBatch sem mensagens, com o erro dado.
type fakeBatch struct{ err error }

func (b fakeBatch) Messages() <-chan jetstream.Msg {
	ch := make(chan jetstream.Msg)
	close(ch)
	return ch
}

func (b fakeBatch) Error() error { return b.err }

// fakeConsumer conta os Fetch e devolve lotes vazios com err.
type fakeConsumer struct {
	jetstream.Consumer
	err     error
	fetches atomic.Int64
}

func (c *fakeConsumer) Fetch(int, ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	c.fetches.Add(1)
	return fakeBatch{err: c.err}, nil
}

// Consumidor ausente (o erro vem em batch.Error(), não no retorno do Fetch): o laço espera entre as tentativas em
// vez de girar, e chama a recriação; quando ela funciona, passa a buscar no consumidor novo (task 320).
func TestIngestRecreatesConsumerAfterNoResponders(t *testing.T) {
	gone := &fakeConsumer{err: nats.ErrNoResponders}
	fresh := &fakeConsumer{}

	// recriação sempre falhando (NATS ainda sem JetStream): no máximo ~5 Fetch por segundo
	in, _ := newTestIngestor(t, nil)
	in.SetReopen(func(context.Context) (jetstream.Consumer, bool, error) {
		return nil, false, errors.New("jetstream not ready")
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := in.Run(ctx, gone); err != nil {
		t.Fatal(err)
	}
	cancel()
	if n := gone.fetches.Load(); n < 2 || n > 7 {
		t.Errorf("%d Fetch em 1 s com o consumidor ausente, quer entre 2 e 7", n)
	}

	// recriação funcionando: troca para o consumidor novo e registra a recriação
	gone.fetches.Store(0)
	in2, _ := newTestIngestor(t, nil)
	var reopens atomic.Int64
	in2.SetReopen(func(context.Context) (jetstream.Consumer, bool, error) {
		reopens.Add(1)
		return fresh, true, nil
	})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	if err := in2.Run(ctx2, gone); err != nil {
		t.Fatal(err)
	}
	if reopens.Load() != 1 || gone.fetches.Load() != 1 || fresh.fetches.Load() == 0 {
		t.Errorf("recriação %d, Fetch no antigo %d, no novo %d (quer 1, 1, >0)",
			reopens.Load(), gone.fetches.Load(), fresh.fetches.Load())
	}
	if in2.stream.recreatedTotal() != 1 {
		t.Errorf("recreated = %d, quer 1", in2.stream.recreatedTotal())
	}
}

// Reinício só do NATS com o store no ar (deploy que muda só o nats.conf): o FS_EVENTS em memória e o consumidor
// somem; o store os recria sozinho e um lote publicado depois do reinício chega ao banco, com o health degradado por
// "stream recreated" (task 320).
func TestIntegrationNATSRestart(t *testing.T) {
	port := freePort(t)
	ns := startNATS(t, port)
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_HEARTBEAT_INTERVAL", "100ms")
	t.Setenv("FS_LOG_LEVEL", "error")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	storeSvc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	_, path := testDB(t)
	apiPort := freePort(t)
	cfg := Config{
		DBPath: path, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", apiPort), Retention: "10m", MaxBytes: 1 << 30,
		DownAfter: 600 * time.Millisecond, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
		Ingest: IngestConfig{
			PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond,
			MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
		},
	}
	st := newTestStore(ctx, t, storeSvc, cfg)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = st.Run(ctx) }()
	defer wg.Wait()
	defer cancel()

	// publish publica um lote do cliente cli com tempos atuais (a folga de fechamento vence) e espera n conexões
	// encerradas no banco. Depois do reinício o stream pode ainda não existir: tenta de novo até ele voltar.
	publish := func(cli netip.AddrPort, n int) {
		t.Helper()
		nc, err := nats.Connect(storeSvc.NC.ConnectedUrl())
		if err != nil {
			t.Fatal(err)
		}
		defer nc.Close()
		js, _ := jetstream.New(nc)
		msg := batch(cli, mirror, protoTCP, fullTCP)
		shift := time.Now().UnixNano() - base
		var buf []byte
		_, _ = event.DecodePackets(msg.data, func(p event.Packet) error {
			p.TsNs += shift
			buf = event.AppendPacket(buf, p)
			return nil
		})
		eventually(t, 15*time.Second, func() bool {
			c, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			_, err := js.PublishMsg(c, natsMsg(event.SubjectCapturePacket, buf))
			return err == nil
		}, "publish into FS_EVENTS never succeeded")
		var got, all int
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			_ = st.db.QueryRow("SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL").Scan(&got)
			if got == n {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = st.db.QueryRow("SELECT count(*) FROM connections").Scan(&all)
		info := "sem stream"
		if s, err := js.Stream(ctx, StreamName); err == nil {
			if i, err := s.Info(ctx); err == nil {
				info = fmt.Sprintf("stream msgs=%d first=%d last=%d", i.State.Msgs, i.State.FirstSeq, i.State.LastSeq)
			}
			if c, err := s.Consumer(ctx, ConsumerName); err == nil {
				if ci, err := c.Info(ctx); err == nil {
					info += fmt.Sprintf(" consumer delivered=%d ack_floor=%d pending=%d", ci.Delivered.Stream, ci.AckFloor.Stream, ci.NumPending)
				}
			}
		}
		t.Fatalf("%d conexões encerradas no banco (%d no total), quer %d; recreated=%d; %s; motivos %v", got, all, n,
			st.ingest.stream.recreatedTotal(), info, st.ingest.stream.reasons(time.Now()))
	}

	eventually(t, 5*time.Second, func() bool { return storeSvc.NC.IsConnected() }, "store never connected")
	publish(client, 1)

	// reinício só do NATS, na mesma porta (o cliente do store reconecta sozinho)
	ns.Shutdown()
	ns.WaitForShutdown()
	ns2 := startNATS(t, port)
	defer ns2.Shutdown()
	eventually(t, 10*time.Second, func() bool { return storeSvc.NC.IsConnected() }, "store never reconnected")

	publish(client2, 2)
	if st.ingest.stream.recreatedTotal() != 1 {
		t.Errorf("recreated = %d, quer 1", st.ingest.stream.recreatedTotal())
	}
	if got := strings.Join(st.ingest.stream.reasons(time.Now()), ","); !strings.Contains(got, "stream recreated in 5m") {
		t.Errorf("health sem o motivo da recriação: %q", got)
	}
}
