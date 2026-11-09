package store

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// jsMsg é uma mensagem com o metadado do JetStream (instante em que entrou no FS_EVENTS).
type jsMsg struct {
	fakeMsg
	published time.Time
}

func (m jsMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{Timestamp: m.published}, nil
}

func publishedMs(m fakeMsg, ms int) jsMsg {
	return jsMsg{fakeMsg: m, published: time.Unix(0, base+int64(ms)*1e6)}
}

// liveIngestor liga um hub com um cliente sem filtro e devolve a leitura do que ele recebeu.
func liveIngestor(t *testing.T) (*Ingestor, func() []*liveMsg) {
	t.Helper()
	in, _ := newTestIngestor(t, nil)
	h := NewHub(4096, 4)
	in.SetLive(h)
	c, err := h.join(LiveFilter{DstPort: -1}, "ws")
	if err != nil {
		t.Fatal(err)
	}
	return in, func() []*liveMsg {
		var out []*liveMsg
		for len(c.ch) > 0 {
			out = append(out, <-c.ch)
		}
		return out
	}
}

func processSrc(t *testing.T, in *Ingestor, atMs int, msgs ...msgSource) {
	t.Helper()
	in.now = func() time.Time { return time.Unix(0, base+int64(atMs)*1e6) }
	if err := in.process(t.Context(), msgs); err != nil {
		t.Fatal(err)
	}
}

func byKind(msgs []*liveMsg) map[string][]*liveMsg {
	out := map[string][]*liveMsg{}
	for _, m := range msgs {
		out[m.kind] = append(out[m.kind], m)
	}
	return out
}

func liveData(t *testing.T, m *liveMsg) (ev struct {
	Ts   string          `json:"ts"`
	Data json.RawMessage `json:"data"`
}, s summaryJSON,
) {
	t.Helper()
	if err := json.Unmarshal(m.data, &ev); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ev.Data, &s); err != nil {
		t.Fatal(err)
	}
	return ev, s
}

func at(ms int) int64 { return base + int64(ms)*1e6 }

// TestLiveTsSessionSummary (ADR 0025): o resumo de uma sessão raw com ts de accept 4 s antes, publicado agora, sai
// no feed com ts ≈ publicação e data.started = accept; o http.request mantém o ts do envelope.
func TestLiveTsSessionSummary(t *testing.T) {
	in, read := liveIngestor(t)
	processSrc(t, in, 50, batch(client, mirror, protoTCP, fullTCP[:6]))
	processSrc(t, in, 4010,
		publishedMs(appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 0, "", map[string]any{"mode": "echo", "tls": false}), 4000),
		publishedMs(appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, "", http1Payload(0, "HTTP/1.1")), 4001))
	k := byKind(read())
	if len(k[LiveConnOpened]) != 1 || k[LiveConnOpened][0].origin != at(0) {
		t.Fatalf("connection.opened must keep the SYN ts: %+v", k[LiveConnOpened])
	}
	upd := k[LiveConnUpdated]
	if len(upd) != 1 || upd[0].origin != at(4000) {
		t.Fatalf("connection.updated ts must be the publish instant: %+v", upd)
	}
	ev, s := liveData(t, upd[0])
	if ev.Ts != event.FormatTime(time.Unix(0, at(4000))) || s.Started != event.FormatTime(time.Unix(0, at(0))) {
		t.Fatalf("ts %s started %s", ev.Ts, s.Started)
	}
	if r := k[LiveHTTPRequest]; len(r) != 1 || r[0].origin != at(40) {
		t.Fatalf("http.request must keep the envelope ts: %+v", r)
	}
}

// TestLiveTsWithoutMetadata: sem metadado do JetStream, o ts do connection.updated é o recebimento do lote.
func TestLiveTsWithoutMetadata(t *testing.T) {
	in, read := liveIngestor(t)
	processSrc(t, in, 50, batch(client, mirror, protoTCP, fullTCP[:6]))
	processSrc(t, in, 3500, appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 0, "", map[string]any{"mode": "echo", "tls": false}))
	if upd := byKind(read())[LiveConnUpdated]; len(upd) != 1 || upd[0].origin != at(3500) {
		t.Fatalf("fallback must be the batch reception: %+v", upd)
	}
	if got := publishedAt(fakeMsg{}, 7); got != 7 {
		t.Fatalf("publishedAt fallback %d", got)
	}
}

// TestLiveTsIdleClose: fechamento por ociosidade sai com ts = decisão do store e data.ended = último pacote; o
// fechamento por FIN mantém o ts do fim.
func TestLiveTsIdleClose(t *testing.T) {
	in, read := liveIngestor(t)
	idle := netip.MustParseAddrPort("192.0.2.77:4000")
	processSrc(t, in, 50, batch(idle, mirror, protoTCP, fullTCP[:6]), batch(client, mirror, protoTCP, fullTCP))
	decide := 200_000 // > TCPIdle (150 s) depois do último pacote (40 ms)
	in.now = func() time.Time { return time.Unix(0, at(decide)) }
	if err := in.Finalize(t.Context(), in.flows.due(at(decide))); err != nil {
		t.Fatal(err)
	}
	closed := byKind(read())[LiveConnClosed]
	if len(closed) != 2 {
		t.Fatalf("closed events %d", len(closed))
	}
	for _, m := range closed {
		_, s := liveData(t, m)
		if s.Ended == nil {
			t.Fatal("closed without ended")
		}
		if s.Src.Port == int(idle.Port()) {
			if m.origin != at(decide) || *s.Ended != event.FormatTime(time.Unix(0, at(40))) {
				t.Fatalf("idle close: origin %d ended %s", m.origin, *s.Ended)
			}
		} else if m.origin != at(1060) {
			t.Fatalf("FIN close must keep the end ts: %d", m.origin)
		}
	}
}

// TestLiveTsOtherKinds: dns.query e packet.stray mantêm o ts de antes (envelope e pacote), mesmo publicados tarde.
func TestLiveTsOtherKinds(t *testing.T) {
	in, read := liveIngestor(t)
	stray := batch(netip.MustParseAddrPort("192.0.2.99:5555"), mirror, protoTCP, []pkt{{30, true, tcpRST, 0}})
	processSrc(t, in, 5000, stray, publishedMs(appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, 10, "", dnsPayload("udp")), 4900))
	k := byKind(read())
	if d := k[LiveDNSQuery]; len(d) != 1 || d[0].origin != at(10) {
		t.Fatalf("dns.query ts: %+v", d)
	}
	if s := k[LivePacketStray]; len(s) != 1 || s[0].origin != at(30) {
		t.Fatalf("packet.stray ts: %+v", s)
	}
}
