package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// pubSink guarda o que o publicador mandou ao NATS.
type pubSink struct {
	mu   sync.Mutex
	msgs [][]byte
	fail bool
}

func (s *pubSink) publish(subject string, data []byte) error {
	if subject != event.SubjectStoreConnection {
		return errors.New("subject " + subject)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("nats refused")
	}
	s.msgs = append(s.msgs, append([]byte(nil), data...))
	return nil
}

// storeConnMsg é uma mensagem decodificada de fs.v1.store.connection.
type storeConnMsg struct {
	raw  []byte
	env  event.Envelope
	pay  event.StoreConnection
	conn connectionJSON
}

// decodeConnMsg confere o envelope e o payload do contrato (asyncapi StoreConnection).
func decodeConnMsg(t *testing.T, raw []byte) storeConnMsg {
	t.Helper()
	env, err := event.Decode(raw)
	if err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	m := storeConnMsg{raw: raw, env: env}
	if env.Service != event.ServiceStore || env.Flow == nil {
		t.Fatalf("envelope %+v", env)
	}
	if err := json.Unmarshal(env.Payload, &m.pay); err != nil {
		t.Fatal(err)
	}
	switch m.pay.Stage {
	case event.StageOpened, event.StageUpdated, event.StageClosed:
	default:
		t.Fatalf("stage %q", m.pay.Stage)
	}
	if err := json.Unmarshal(m.pay.Connection, &m.conn); err != nil || !ValidConnID(m.conn.ConnID) {
		t.Fatalf("connection %v: %s", err, m.pay.Connection)
	}
	if env.Flow.SrcIP != m.conn.Src.IP || env.Flow.DstPort != m.conn.Dst.Port || env.Flow.L4 != m.conn.L4 {
		t.Fatalf("flow %+v differs from the record", env.Flow)
	}
	return m
}

// drainPub envia, no próprio teste, o que estiver na fila (o Run faz isso em produção).
func drainPub(t *testing.T, p *connPublisher, sink *pubSink) []storeConnMsg {
	t.Helper()
	for _, s := range p.take() {
		p.send(s)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	out := make([]storeConnMsg, 0, len(sink.msgs))
	for _, raw := range sink.msgs {
		out = append(out, decodeConnMsg(t, raw))
	}
	sink.msgs = nil
	return out
}

func stagesOf(ms []storeConnMsg, id string) []string {
	var out []string
	for _, m := range ms {
		if m.conn.ConnID == id {
			out = append(out, m.pay.Stage)
		}
	}
	return out
}

func newPubIngestor(t *testing.T, mut func(*IngestConfig)) (*Ingestor, *connPublisher, *pubSink) {
	t.Helper()
	in, _ := newTestIngestor(t, mut)
	sink := &pubSink{}
	p := newConnPublisher(sink.publish, "test", in.flows.live)
	in.SetConnPublisher(p)
	return in, p, sink
}

// TestConnPublishStages: um assinante recebe opened, updated e closed de uma conexão TCP (com TLS e HTTP/1) e de
// uma QUIC/h3, depois do commit, com o Connection da API; os exemplos golden são regravados com -update.
func TestConnPublishStages(t *testing.T) {
	in, p, sink := newPubIngestor(t, func(c *IngestConfig) { c.CloseGrace = 100 * time.Millisecond })

	// TCP: SYN até os dados, com ClientHello e uma requisição HTTP/1.
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, probeID, tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	open := drainPub(t, p, sink)
	if len(open) != 2 || open[0].pay.Stage != event.StageOpened || open[1].pay.Stage != event.StageUpdated {
		t.Fatalf("open stages %v", stagesOf(open, open[0].conn.ConnID))
	}
	id := open[0].conn.ConnID
	if u := open[1].conn; u.TLS == nil || len(u.HTTP) != 1 || u.Requests != 1 || u.ProbeID == nil || *u.ProbeID != probeID || u.Ended != nil {
		t.Fatalf("updated must carry the app layers: %s", open[1].pay.Connection)
	}
	if open[0].conn.TCP == nil || open[0].conn.Times == nil || open[0].conn.Times.Syn == nil {
		t.Fatalf("opened must carry the SYN analysis: %s", open[0].pay.Connection)
	}
	run(t, in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	closed := drainPub(t, p, sink)
	if len(closed) != 1 || closed[0].pay.Stage != event.StageClosed || closed[0].conn.ConnID != id ||
		closed[0].conn.Ended == nil || closed[0].conn.Close.How != "fin" || len(closed[0].conn.HTTP) != 1 {
		t.Fatalf("closed %s", closed[0].raw)
	}

	// QUIC/h3.
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	run(t, in, 1000, msgs[6])
	quic := drainPub(t, p, sink)
	run(t, in, 1300)
	quic = append(quic, drainPub(t, p, sink)...)
	qid := quic[0].conn.ConnID
	st := stagesOf(quic, qid)
	if len(st) < 3 || st[0] != event.StageOpened || st[len(st)-1] != event.StageClosed || st[1] != event.StageUpdated {
		t.Fatalf("quic stages %v", st)
	}
	last := quic[len(quic)-1].conn
	if last.L4 != "udp" || last.Proto != "quic/h3" || last.HTTP3 == nil || last.Close.How != "quic_close" {
		t.Fatalf("quic closed %s", quic[len(quic)-1].pay.Connection)
	}
	if p.dropped.Load() != 0 {
		t.Fatalf("dropped %d", p.dropped.Load())
	}

	// Contrato: cada connection valida contra o Connection do openapi; os goldens referenciados pelo asyncapi.
	var conns [][]byte
	for _, m := range append(append(open, closed...), quic...) {
		if m.pay.ConnectionTruncated {
			t.Fatal("small record marked truncated")
		}
		conns = append(conns, m.pay.Connection)
	}
	checkEventGolden(t, filepath.Join("testdata", "events", "store.connection.opened.json"), open[0].raw)
	checkEventGolden(t, filepath.Join("testdata", "events", "store.connection.closed.json"), closed[0].raw)
	validateContract(t, "Connection", conns...)
}

// TestConnPublishDegraded: conexão em modo degradado publica só opened e closed.
func TestConnPublishDegraded(t *testing.T) {
	in, p, sink := newPubIngestor(t, func(c *IngestConfig) { c.MaxNewPerS = 1 })
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, in, 0, batch(client, mirror, protoTCP, fullTCP[:6]), batch(other, mirror, protoTCP, fullTCP[:6]))
	run(t, in, 100,
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, "", http1Payload(0, "HTTP/1.1")),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", other, mirror, 40, "", http1Payload(0, "HTTP/1.1")))
	// o updated de conexão aberta é montado no envio: drena antes do fechamento, como o Run faria
	ms := drainPub(t, p, sink)
	run(t, in, 200_000)
	ms = append(ms, drainPub(t, p, sink)...)
	var degraded, normal string
	for _, m := range ms {
		if m.conn.Degraded {
			degraded = m.conn.ConnID
		} else {
			normal = m.conn.ConnID
		}
	}
	if got := strings.Join(stagesOf(ms, degraded), ","); degraded == "" || got != "opened,closed" {
		t.Fatalf("degraded stages %q", got)
	}
	if got := strings.Join(stagesOf(ms, normal), ","); got != "opened,updated,closed" {
		t.Fatalf("normal stages %q", got)
	}
}

// TestConnPublishQueueFull: com a fila cheia o ingest não espera: o estágio é descartado e contado.
func TestConnPublishQueueFull(t *testing.T) {
	in, p, sink := newPubIngestor(t, nil)
	p.enqueue(make([]connStage, connPubQueue-1)...)
	p.enqueue(connStage{stage: event.StageOpened})
	start := time.Now()
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	run(t, in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("ingest waited %v with the queue full", d)
	}
	if n := p.dropped.Load(); n != 2 {
		t.Fatalf("dropped %d, want 2 (opened and closed)", n)
	}
	if len(sink.msgs) != 0 || len(p.q) != connPubQueue || len(p.wake) != 1 {
		t.Fatal("queue changed")
	}
	// NATS que recusa também descarta e conta.
	p2 := newConnPublisher((&pubSink{fail: true}).publish, "test", in.flows.live)
	p2.send(connStage{stage: event.StageClosed, rec: []byte(`{"conn_id":"x"}`), flow: &event.Flow{}})
	if p2.dropped.Load() != 1 {
		t.Fatal("refused publish not counted")
	}
}

// TestConnPublishRollback: lote desfeito não publica nada (os estágios voltam com a reentrega).
func TestConnPublishRollback(t *testing.T) {
	in, p, _ := newPubIngestor(t, nil)
	in.pubConn(event.StageOpened, base, []byte(`{}`), &connectionJSON{ConnID: "x"})
	in.pubConnOpen("y", base, false)
	in.discardBatchState()
	in.publishConns()
	if len(p.q) != 0 || len(in.connUpd) != 0 {
		t.Fatalf("rolled back stages enqueued: %d", len(p.q))
	}
}

// TestConnPublishTruncate: registro acima de 900 KiB é cortado (listas pela metade) e marcado connection_truncated.
func TestConnPublishTruncate(t *testing.T) {
	r := connectionJSON{ConnID: "01JCDEFGHJKMNPQRSTVWXYZ012", L4: "tcp", Proto: "tcp/tls/h2", Src: endpointJSON{IP: "192.0.2.1", Port: 1}, Dst: endpointJSON{IP: "192.0.2.2", Port: 443}}
	big := strings.Repeat("a", 1000)
	for i := range 800 {
		h, _ := json.Marshal(map[string]any{"index": i, "path": big})
		r.HTTP = append(r.HTTP, h)
	}
	streams := make([]map[string]any, 600)
	for i := range streams {
		streams[i] = map[string]any{"stream_id": 2*i + 1, "path": big}
	}
	r.HTTP2, _ = json.Marshal(map[string]any{"settings": []int{1, 2}, "streams": streams})
	r.Requests = 1400
	rec, _ := json.Marshal(r)
	if len(rec) <= event.MaxEventBytes {
		t.Fatalf("fixture too small: %d", len(rec))
	}
	p := newConnPublisher(nil, "test", nil)
	msg := p.encode(connStage{stage: event.StageClosed, ts: base, flow: flowOf(r)}, rec)
	if len(msg) > event.MaxEventBytes {
		t.Fatalf("message %d bytes", len(msg))
	}
	m := decodeConnMsg(t, msg)
	if !m.pay.ConnectionTruncated || len(m.conn.HTTP) == 0 || len(m.conn.HTTP) >= 800 || m.conn.Requests != 1400 {
		t.Fatalf("truncated=%v http=%d requests=%d", m.pay.ConnectionTruncated, len(m.conn.HTTP), m.conn.Requests)
	}
	var h2 struct {
		Streams []json.RawMessage `json:"streams"`
	}
	if err := json.Unmarshal(m.conn.HTTP2, &h2); err != nil || len(h2.Streams) >= 600 {
		t.Fatalf("http2 streams %d %v", len(h2.Streams), err)
	}
	// Sem lista a cortar, sai a maior camada inteira.
	r2 := connectionJSON{ConnID: r.ConnID, L4: "tcp", Src: r.Src, Dst: r.Dst}
	r2.TLS, _ = json.Marshal(map[string]string{"ja4_r": strings.Repeat("b", event.MaxEventBytes)})
	rec2, _ := json.Marshal(r2)
	m2 := decodeConnMsg(t, p.encode(connStage{stage: event.StageOpened, ts: base, flow: flowOf(r2)}, rec2))
	if !m2.pay.ConnectionTruncated || m2.conn.TLS != nil {
		t.Fatalf("tls must be dropped: %v", m2.pay.ConnectionTruncated)
	}
}

// openIDs devolve os IDs das conexões abertas.
func openIDs(in *Ingestor) []string {
	in.flows.mu.Lock()
	defer in.flows.mu.Unlock()
	var out []string
	for id := range in.flows.byID {
		out = append(out, id)
	}
	return out
}

// TestConnPublishThrottle: updated da mesma conexão no máximo a cada connPubUpdateEvery; o adiado sai no fim da
// janela com o estado daquele instante.
func TestConnPublishThrottle(t *testing.T) {
	in, p, sink := newPubIngestor(t, nil)
	processAt(t, in, 0, batch(client, mirror, protoTCP, fullTCP[:6]),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	if got := strings.Join(stagesOf(drainPub(t, p, sink), openIDs(in)[0]), ","); got != "opened,updated" {
		t.Fatalf("first batch %q", got)
	}
	processAt(t, in, 10, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 45, probeID, http1Payload(1, "HTTP/1.1")))
	processAt(t, in, 20, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 50, probeID, http1Payload(2, "HTTP/1.1")))
	in.afterBatch(context.Background()) // ainda na janela
	if ms := drainPub(t, p, sink); len(ms) != 0 {
		t.Fatalf("updated inside the window: %d", len(ms))
	}
	in.now = func() time.Time { return time.Unix(0, base).Add(connPubUpdateEvery) }
	in.afterBatch(context.Background())
	ms := drainPub(t, p, sink)
	if len(ms) != 1 || ms[0].pay.Stage != event.StageUpdated || ms[0].conn.Requests != 3 {
		t.Fatalf("trailing updated: %d msgs", len(ms))
	}
	if len(in.connTrail) != 0 {
		t.Fatal("trail kept")
	}
	// Janela vencida sem evento novo: a entrada some.
	in.now = func() time.Time { return time.Unix(0, base).Add(3 * connPubUpdateEvery) }
	in.afterBatch(context.Background())
	if len(in.connLast) != 0 {
		t.Fatalf("connLast leaks: %d", len(in.connLast))
	}
}

// TestMarshalRecordMatchesJSON: o registro emendado é o mesmo JSON de json.Marshal (TCP com TLS, HTTP/1, h2,
// WebSocket e raw; QUIC com h3).
func TestMarshalRecordMatchesJSON(t *testing.T) {
	in, _ := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, probeID, tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 26, probeID, handshakePayload()),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	var checked int
	for _, id := range openIDs(in) {
		r, ok := in.flows.live(id)
		if !ok {
			t.Fatal(id)
		}
		if r.L4 == "tcp" {
			// camadas sintéticas para cobrir todos os campos emendados
			r.HTTP2 = json.RawMessage(`{"mode":"alpn","streams":[{"stream_id":1,"path":"/<a>&"}]}`)
			r.WebSocket = &wsJSON{Over: "http1.1", Path: "/ws", Frames: []wsFrameJSON{{Dir: "in", Opcode: 1}}}
			r.Raw = json.RawMessage(`{"mode":"echo"}`)
		}
		var a, b any
		std, _ := json.Marshal(r)
		if err := json.Unmarshal(std, &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(marshalRecord(r), &b); err != nil {
			t.Fatalf("%v: %s", err, marshalRecord(r))
		}
		sa, _ := json.Marshal(a)
		sb, _ := json.Marshal(b)
		if string(sa) != string(sb) {
			t.Fatalf("differs:\n%s\n%s", sa, sb)
		}
		checked++
	}
	if checked != 2 {
		t.Fatalf("checked %d records", checked)
	}
}

// TestLayersCacheInvalidation: o tls e o http3 em cache acompanham os eventos novos.
func TestLayersCacheInvalidation(t *testing.T) {
	in, _ := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, probeID, tlsHelloPayload(clientHelloRaw(95))))
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:2]...)
	var tcpID, quicID string
	for _, id := range openIDs(in) {
		if r, _ := in.flows.live(id); r.L4 == "tcp" {
			tcpID = id
		} else {
			quicID = id
		}
	}
	if r, _ := in.flows.live(tcpID); strings.Contains(string(r.TLS), "negotiated") {
		t.Fatal("negotiated before the handshake")
	}
	run(t, in, 600, appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 26, probeID, handshakePayload()))
	if r, _ := in.flows.live(tcpID); !strings.Contains(string(r.TLS), "negotiated") {
		t.Fatalf("stale tls cache: %s", r.TLS)
	}
	before, _ := in.flows.live(quicID)
	run(t, in, 950, msgs[2:6]...)
	after, _ := in.flows.live(quicID)
	var h3 http3JSON
	if err := json.Unmarshal(after.HTTP3, &h3); err != nil || len(h3.Requests) != 2 || string(before.HTTP3) == string(after.HTTP3) {
		t.Fatalf("stale h3 cache: %s", after.HTTP3)
	}
	// novo http3.connection troca o nível de conexão em cache
	run(t, in, 1000, msgs[6])
	if r, _ := in.flows.live(quicID); r.Ended == nil && !strings.Contains(string(r.HTTP3), `"close":{`) {
		t.Fatalf("stale h3 level: %s", r.HTTP3)
	}
}
