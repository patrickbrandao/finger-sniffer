package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestConnIDReservedBeforeSYN: a requisição chega antes dos pacotes; a conexão criada por eles usa o ID reservado.
func TestConnIDReservedBeforeSYN(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	id, reserved := in.flows.connID(protoTCP, client, mirror, base, base)
	if !reserved || len(id) != 26 {
		t.Fatalf("id=%q reserved=%v", id, reserved)
	}
	// Repetir a pergunta devolve a mesma reserva.
	if again, _ := in.flows.connID(protoTCP, client, mirror, base, base+1); again != id {
		t.Fatalf("second request %q != %q", again, id)
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP))
	got, r := onlyConn(t, db)
	if got != id || r.ConnID != id {
		t.Fatalf("connection id %q (record %q), reserved %q", got, r.ConnID, id)
	}
	if in.flows.reservations() != 0 {
		t.Fatal("reservation must be consumed")
	}
}

// TestConnIDOpenConnection: conexão já aberta → mesmo ID, sem reserva; nos dois sentidos da 5-tupla.
func TestConnIDOpenConnection(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:4]))
	open := in.flows.byID
	if len(open) != 1 {
		t.Fatalf("open=%d", len(open))
	}
	var want string
	for id := range open {
		want = id
	}
	id, reserved := in.flows.connID(protoTCP, client, mirror, base, base)
	if id != want || reserved {
		t.Fatalf("id=%q reserved=%v want %q", id, reserved, want)
	}
	if id2, _ := in.flows.connID(protoTCP, mirror, client, base, base); id2 != want {
		t.Fatalf("reverse direction %q", id2)
	}
	if in.flows.reservations() != 0 {
		t.Fatal("no reservation expected")
	}
	// Outro protocolo com a mesma tupla não é a mesma conexão.
	if _, reserved := in.flows.connID(protoUDP, client, mirror, base, base); !reserved {
		t.Fatal("udp must reserve")
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[4:]))
	if got, _ := onlyConn(t, db); got != want {
		t.Fatal(got)
	}
}

// TestConnIDClosingConnectionReserves: a conexão anterior já fechou; o accept novo recebe uma reserva, usada pela
// conexão que reusa a 5-tupla.
func TestConnIDClosingConnectionReserves(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 1100, batch(client, mirror, protoTCP, fullTCP)) // fechou, ainda na folga
	id, reserved := in.flows.connID(protoTCP, client, mirror, base+1100e6, base+1100e6)
	if !reserved {
		t.Fatal("closing connection must not be reused")
	}
	second := make([]pkt, len(fullTCP))
	for i, p := range fullTCP {
		p.ms += 1200
		second[i] = p
	}
	run(t, in, 10_000, batch(client, mirror, protoTCP, second))
	if n := count(t, db, "SELECT count(*) FROM connections WHERE conn_id = ?", id); n != 1 {
		t.Fatalf("second connection must use the reserved id: %d", n)
	}
}

// TestConnIDReservationExpires: reserva sem uso some depois de 30 s e não afeta a conexão seguinte.
func TestConnIDReservationExpires(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	id, _ := in.flows.connID(protoTCP, client, mirror, base, base)
	_ = in.flows.due(base + int64(29*time.Second))
	if in.flows.reservations() != 1 {
		t.Fatal("reservation must survive 29 s")
	}
	_ = in.flows.due(base + int64(31*time.Second))
	if in.flows.reservations() != 0 {
		t.Fatal("expired reservation must be removed")
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP))
	if got, _ := onlyConn(t, db); got == id {
		t.Fatal("expired reservation used")
	}

	// Vencida mas ainda não limpa: pacote depois do prazo também não usa a reserva.
	in2, db2 := newTestIngestor(t, nil)
	late := make([]pkt, len(fullTCP))
	for i, p := range fullTCP {
		p.ms += 40_000
		late[i] = p
	}
	id2, _ := in2.flows.connID(protoTCP, client, mirror, base, base)
	if err := in2.process(context.Background(), []msgSource{batch(client, mirror, protoTCP, late)}); err != nil {
		t.Fatal(err)
	}
	if err := in2.Finalize(context.Background(), in2.flows.due(base+60_000e6)); err != nil {
		t.Fatal(err)
	}
	if got, _ := onlyConn(t, db2); got == id2 {
		t.Fatal("reservation used after expiry")
	}
}

func TestParseConnIDRequest(t *testing.T) {
	ok := `{"flow":{"l4":"tcp","src_ip":"::ffff:192.0.2.10","src_port":41234,"dst_ip":"172.233.24.85","dst_port":7700},"ts":"2026-11-07T12:00:00.000000001Z"}`
	l4, cli, srv, ts, err := parseConnIDRequest([]byte(ok))
	if err != nil || l4 != protoTCP || cli != client || srv != mirror || ts != base+1 {
		t.Fatalf("%d %v %v %d %v", l4, cli, srv, ts, err)
	}
	for _, bad := range []string{
		`{`,
		`{"flow":{"l4":"sctp","src_ip":"1.1.1.1","src_port":1,"dst_ip":"1.1.1.1","dst_port":1}}`,
		`{"flow":{"l4":"udp","src_ip":"x","src_port":1,"dst_ip":"1.1.1.1","dst_port":1}}`,
		`{"flow":{"l4":"udp","src_ip":"1.1.1.1","src_port":0,"dst_ip":"1.1.1.1","dst_port":1}}`,
		`{"flow":{"l4":"udp","src_ip":"1.1.1.1","src_port":1,"dst_ip":"1.1.1.1","dst_port":70000}}`,
	} {
		if _, _, _, _, err := parseConnIDRequest([]byte(bad)); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

// TestIntegrationConnID: o web pede o conn_id antes de o store ver os pacotes; o ID devolvido é o conn_id do
// registro em /connections. Request/reply ACME com o stream ativo recebe só a resposta do responder.
func TestIntegrationConnID(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storeSvc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	_, path := testDB(t)
	port := freePort(t)
	cfg := Config{
		DBPath: path, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", port), Retention: "10m", MaxBytes: 1 << 30,
		DownAfter: time.Minute, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
		Ingest: IngestConfig{
			PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond,
			MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
		},
	}
	st, err := New(ctx, storeSvc, cfg, []byte("openapi: 3.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = st.Run(ctx) }()

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	eventually(t, 5*time.Second, func() bool {
		s, err := js.Stream(ctx, StreamName)
		return err == nil && s.CachedInfo() != nil
	}, "stream not created")

	// Os pacotes usam o relógio atual (a reserva vale 30 s a partir da chegada da requisição).
	shift := time.Now().UnixNano() - base
	flow := event.Flow{L4: "tcp", SrcIP: client.Addr().String(), SrcPort: int(client.Port()), DstIP: mirror.Addr().String(), DstPort: int(mirror.Port())}
	var rep event.ConnIDReply
	eventually(t, 5*time.Second, func() bool {
		rep, err = service.RequestConnID(ctx, nc, flow, time.Unix(0, base+shift))
		return err == nil
	}, "conn_id request never answered")
	if !rep.Reserved {
		t.Fatalf("%+v", rep)
	}

	var buf []byte
	_, _ = event.DecodePackets(batch(client, mirror, protoTCP, fullTCP).data, func(p event.Packet) error {
		p.TsNs += shift
		buf = event.AppendPacket(buf, p)
		return nil
	})
	if _, err := js.Publish(ctx, event.SubjectCapturePacket, buf); err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/connections/%s", port, rep.ConnID)
	eventually(t, 10*time.Second, func() bool {
		resp, err := http.Get(url) //nolint:noctx,gosec // teste
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var r connectionJSON
		return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&r) == nil && r.ConnID == rep.ConnID
	}, "reserved conn_id never appeared in /connections")

	// Com a conexão aberta ou fechada, a mesma 5-tupla não gera erro; o stream não guarda os request/reply.
	responder, err := nc.Subscribe(event.SubjectDNSACMESet, func(m *nats.Msg) {
		data, _ := json.Marshal(event.ACMEReply{OK: true})
		_ = m.Respond(data)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = responder.Unsubscribe() }()
	req, _ := json.Marshal(event.ACMERequest{Name: "_acme-challenge.dns-monitor.tmsoft.com.br.", Value: "v"})
	inbox := nats.NewInbox()
	replies, err := nc.SubscribeSync(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.PublishRequest(event.SubjectDNSACMESet, inbox, req); err != nil {
		t.Fatal(err)
	}
	m, err := replies.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var ack event.ACMEReply
	if err := json.Unmarshal(m.Data, &ack); err != nil || !ack.OK || ack.Error != nil || len(m.Header) != 0 {
		t.Fatalf("reply %q %v", m.Data, err)
	}
	if extra, err := replies.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("unexpected second reply (PubAck?): %q", extra.Data)
	}
	s, _ := js.Stream(ctx, StreamName)
	info, err := s.Info(ctx, jetstream.WithSubjectFilter(">"))
	if err != nil {
		t.Fatal(err)
	}
	for subj := range info.State.Subjects {
		if subj == event.SubjectDNSACMESet || subj == event.SubjectStoreConnID {
			t.Fatalf("stream stored request subject %s", subj)
		}
	}
}

// TestEnsureStreamUpdatesSubjects: um stream antigo com fs.v1.> passa para a lista explícita sem perder mensagens.
func TestEnsureStreamUpdatesSubjects(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	ctx := context.Background()
	js, _ := jetstream.New(nc)
	old := StreamConfig()
	old.Subjects = []string{"fs.v1.>"}
	if _, err := js.CreateStream(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, event.SubjectHeartbeat, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureStream(ctx, js); err != nil {
		t.Fatal(err)
	}
	s, _ := js.Stream(ctx, StreamName)
	info, _ := s.Info(ctx)
	if info.State.Msgs != 1 || len(info.Config.Subjects) != len(event.StreamSubjects) {
		t.Fatalf("msgs=%d subjects=%v", info.State.Msgs, info.Config.Subjects)
	}
	for i, subj := range event.StreamSubjects {
		if info.Config.Subjects[i] != subj {
			t.Fatalf("subjects=%v", info.Config.Subjects)
		}
	}
}
