package store

import (
	"context"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestEventBeforeSYNSameBatch: o evento vem antes do lote do SYN no mesmo lote; fica pendente e é associado.
func TestEventBeforeSYNSameBatch(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 30, "t1a2b3c4", hello),
		batch(client, mirror, protoTCP, fullTCP))
	id, r := onlyConn(t, db)
	if r.ProbeID == nil || *r.ProbeID != "t1a2b3c4" {
		t.Fatalf("probe %v", r.ProbeID)
	}
	if count(t, db, "SELECT count(*) FROM app_events WHERE conn_id = ?", id) != 1 ||
		count(t, db, "SELECT count(*) FROM connections WHERE probe_id = 't1a2b3c4'") != 1 ||
		count(t, db, "SELECT count(*) FROM probes WHERE probe_id = 't1a2b3c4'") != 1 {
		t.Fatal("event, probe column or probes row missing")
	}
	if len(in.pending) != 0 {
		t.Fatal("pending must be empty")
	}
}

// TestEventBeforeSYNEarlierBatch: o evento chega num lote anterior ao dos pacotes (até 2 s).
func TestEventBeforeSYNEarlierBatch(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 0, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 30, "t1a2b3c4", map[string]any{"index": 0}))
	if len(in.pending) != 1 || count(t, db, "SELECT count(*) FROM connections") != 0 {
		t.Fatal("event must wait")
	}
	processAt(t, in, 1500, batch(client, mirror, protoTCP, fullTCP[:5]))
	id, _ := onlyConn(t, db)
	if len(in.pending) != 0 || count(t, db, "SELECT count(*) FROM app_events WHERE conn_id = ?", id) != 1 {
		t.Fatal("pending event not associated")
	}
	// Conexão aberta: o registro ao vivo já traz o probe.
	if r := recordOf(t, in, id); r.ProbeID == nil || r.Ended != nil {
		t.Fatalf("live record %+v", r)
	}
	// Evento seguinte, com a conexão aberta, entra direto.
	processAt(t, in, 1600, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 36, "", map[string]any{"index": 1}))
	if count(t, db, "SELECT count(*) FROM app_events WHERE conn_id = ?", id) != 2 {
		t.Fatal("open connection event")
	}
}

// TestEventWithoutPackets: capture parado; depois de 2 s o evento cria a conexão sem pacotes, que o probe encontra.
func TestEventWithoutPackets(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	reservedID, _ := in.flows.connID(protoTCP, client, mirror, base, base)
	processAt(t, in, 0, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 0, "t1a2b3c4", hello))
	processAt(t, in, 1900)
	if count(t, db, "SELECT count(*) FROM connections") != 0 {
		t.Fatal("must still wait")
	}
	processAt(t, in, 2100)
	id, r := onlyConn(t, db)
	if id != reservedID {
		t.Fatalf("event-only connection must use the reserved conn_id: %s != %s", id, reservedID)
	}
	if r.Times == nil || r.Times.Syn != nil || r.IP != nil || r.TCP != nil || r.Ended == nil || r.ProbeID == nil || r.L4 != "tcp" {
		t.Fatalf("%+v", r)
	}
	if count(t, db, "SELECT count(*) FROM pcaps") != 0 {
		t.Fatal("no pcap expected")
	}
	// Outro evento da mesma 5-tupla vai para a mesma conexão e estende o fim.
	processAt(t, in, 3000, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 2900, "", map[string]any{"index": 0}))
	if count(t, db, "SELECT count(*) FROM connections") != 1 || count(t, db, "SELECT count(*) FROM app_events WHERE conn_id = ?", id) != 2 {
		t.Fatal("second event must join the event-only connection")
	}
	if _, r := onlyConn(t, db); *r.Ended != event.FormatTime(time.Unix(0, base+2900e6)) {
		t.Fatalf("ended %v", *r.Ended)
	}
	p, err := NewQueries(db, in.flows.live, 65535).Probe(context.Background(), "t1a2b3c4", 0)
	if err != nil || len(p.Connections) != 1 || !p.AllClosed {
		t.Fatalf("probe %+v %v", p, err)
	}
}

// TestEventOnlyAdoptedByLatePackets: os pacotes chegam depois que a conexão só de eventos foi criada; ficam com o
// mesmo conn_id e o registro mantém o probe.
func TestEventOnlyAdoptedByLatePackets(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 0, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 30, "t1a2b3c4", hello))
	processAt(t, in, 2100)
	id, _ := onlyConn(t, db)
	processAt(t, in, 2200, batch(client, mirror, protoTCP, fullTCP))
	if err := in.Finalize(context.Background(), in.flows.due(base+10_000e6)); err != nil {
		t.Fatal(err)
	}
	got, r := onlyConn(t, db)
	if got != id || r.TCP == nil || r.Times.Syn == nil || r.ProbeID == nil || *r.ProbeID != "t1a2b3c4" {
		t.Fatalf("id %s (want %s) %+v", got, id, r)
	}
	if count(t, db, "SELECT count(*) FROM pcaps WHERE conn_id = ?", id) != 1 {
		t.Fatal("pcap expected")
	}
}

// TestEventAfterClose: evento de conexão já finalizada atualiza o registro gravado.
func TestEventAfterClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP))
	id, r := onlyConn(t, db)
	if r.Ended == nil || r.ProbeID != nil {
		t.Fatal("closed without probe expected")
	}
	processAt(t, in, 6000, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 1060, "t1a2b3c4", map[string]any{"mode": "echo"}))
	_, r = onlyConn(t, db)
	if r.ProbeID == nil || *r.ProbeID != "t1a2b3c4" || r.TCP == nil {
		t.Fatalf("%+v", r)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE conn_id = ? AND probe_id = 't1a2b3c4'", id) != 1 {
		t.Fatal("probe column")
	}
	// Evento muito depois do fim (> 30 s) não é dessa conexão: cria outra só de eventos.
	processAt(t, in, 50_000, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 45_000, "", map[string]any{}))
	processAt(t, in, 53_000)
	if count(t, db, "SELECT count(*) FROM connections") != 2 {
		t.Fatal("unrelated late event must not join the old connection")
	}
}

// TestEventFirstProbeWins: o probe da conexão é o primeiro não nulo.
func TestEventFirstProbeWins(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:4]),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", hello),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 30, "aaaaaaaa", nil),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 31, "bbbbbbbb", nil))
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[4:]))
	_, r := onlyConn(t, db)
	if r.ProbeID == nil || *r.ProbeID != "aaaaaaaa" {
		t.Fatalf("%v", r.ProbeID)
	}
	if count(t, db, "SELECT count(*) FROM probes") != 2 {
		t.Fatal("both probes seen")
	}
}

// TestRecordCompleteWithin500ms: RNF-01 — com eventos de aplicação, o registro completo sai em ≤ 500 ms depois
// que a conexão vence.
func TestRecordCompleteWithin500ms(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	msgs := []fakeMsg{batch(client, mirror, protoTCP, fullTCP)}
	for i := range 50 {
		msgs = append(msgs, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 30+i, "t1a2b3c4", map[string]any{"index": i}))
	}
	processAt(t, in, 0, msgs...)
	start := time.Now()
	if err := in.Finalize(context.Background(), in.flows.due(base+5000e6)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("finalize took %v", d)
	}
	if _, r := onlyConn(t, db); r.Ended == nil || r.ProbeID == nil {
		t.Fatal("record not complete")
	}
}

// TestEventKeepsConnectionWithoutHandshake: capture começou no meio da conexão (sem SYN-ACK visto); com eventos
// de aplicação ela continua conexão em vez de virar pacotes avulsos.
func TestEventKeepsConnectionWithoutHandshake(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	mid := []pkt{{0, true, tcpACK | tcpPSH, 100}, {10, false, tcpACK | tcpPSH, 200}, {20, true, tcpFIN | tcpACK, 0}, {30, false, tcpFIN | tcpACK, 0}}
	run(t, in, 5000, batch(client, mirror, protoTCP, mid), appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 5, "t1a2b3c4", map[string]any{"index": 0}))
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") != 1 || count(t, db, "SELECT count(*) FROM stray_packets") != 0 {
		t.Fatal("connection with app events must not become stray")
	}
}

// TestLateEventOfExpungedConnection: evento tardio de conexão já expurgada não cria registro só de eventos
// (task 080).
func TestLateEventOfExpungedConnection(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.Retention = 10 * time.Minute })
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP))
	if n, err := NewRetention(db, 10*time.Minute, 1<<30).RunOnce(context.Background(), time.Unix(0, base).Add(11*time.Minute)); err != nil || n != 1 {
		t.Fatalf("expunge %d %v", n, err)
	}
	const at = 11 * 60 * 1000
	processAt(t, in, at, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 30, "t1a2b3c4", map[string]any{"mode": "echo"}))
	processAt(t, in, at+3000)
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 0 || len(in.pending) != 0 {
		t.Fatalf("late event must be dropped: %d connections, %d pending", n, len(in.pending))
	}
	// Evento recente sem conexão continua criando o registro só de eventos.
	processAt(t, in, at+4000, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, at+3900, "", map[string]any{"mode": "echo"}))
	processAt(t, in, at+7000)
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("recent event must create an event-only connection: %d", n)
	}
}
