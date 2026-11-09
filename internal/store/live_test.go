package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// liveRecv é um LiveEvent recebido por um cliente de teste, com o instante da chegada.
type liveRecv struct {
	Kind    string          `json:"kind"`
	Ts      string          `json:"ts"`
	ConnID  *string         `json:"conn_id"`
	ProbeID *string         `json:"probe_id"`
	Data    json.RawMessage `json:"data"`
	raw     []byte
	at      time.Time
}

// sseClient lê /stream em segundo plano; para quando ctx acaba.
func sseClient(t *testing.T, ctx context.Context, url string) (<-chan liveRecv, *http.Response) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan liveRecv, 100000)
	if resp.StatusCode != http.StatusOK {
		close(out)
		return out, resp
	}
	go func() {
		defer close(out)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		kind := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				var ev liveRecv
				raw := []byte(strings.TrimPrefix(line, "data: "))
				if json.Unmarshal(raw, &ev) != nil || ev.Kind != kind {
					ev.Kind = "bad:" + kind
				}
				ev.raw, ev.at = raw, time.Now()
				out <- ev
			}
		}
	}()
	return out, resp
}

// wsClient lê /ws em segundo plano.
func wsClient(t *testing.T, ctx context.Context, url string, origin string) <-chan liveRecv {
	t.Helper()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	c, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatalf("ws dial: %v %v", err, resp)
	}
	out := make(chan liveRecv, 100000)
	go func() {
		defer close(out)
		defer func() { _ = c.CloseNow() }()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var ev liveRecv
			if typ != websocket.MessageText || json.Unmarshal(data, &ev) != nil {
				ev.Kind = "bad"
			}
			ev.raw, ev.at = data, time.Now()
			out <- ev
		}
	}()
	return out
}

// collect lê do canal até cond ou o prazo.
func collect(ch <-chan liveRecv, d time.Duration, done func([]liveRecv) bool) []liveRecv {
	var got []liveRecv
	deadline := time.After(d)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, ev)
			if done(got) {
				return got
			}
		case <-deadline:
			return got
		}
	}
}

func kinds(evs []liveRecv) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Kind]++
	}
	return m
}

func TestParseLiveFilter(t *testing.T) {
	q := func(v map[string]string) func(string) string { return func(k string) string { return v[k] } }
	f, err := ParseLiveFilter(q(map[string]string{"probe": "t1a2b3c4", "src_ip": "::ffff:192.0.2.10", "dst_port": "443", "kind": "dns.query, http.request"}))
	if err != nil || f.Probe != "t1a2b3c4" || f.SrcIP != netip.MustParseAddr("192.0.2.10") || f.DstPort != 443 || len(f.Kinds) != 2 {
		t.Fatalf("%+v %v", f, err)
	}
	if f, err := ParseLiveFilter(q(nil)); err != nil || f.DstPort != -1 || f.Kinds != nil {
		t.Fatalf("%+v %v", f, err)
	}
	for _, bad := range []map[string]string{
		{"probe": "UPPER123"},
		{"probe": "short"},
		{"src_ip": "x"},
		{"dst_port": "70000"},
		{"dst_port": "a"},
		{"kind": "stream.dropped"},
		{"kind": "http.request,"},
	} {
		if _, err := ParseLiveFilter(q(bad)); err == nil {
			t.Errorf("%v: expected error", bad)
		}
	}
}

func liveTestMsg(kind, conn string, port int) *liveMsg {
	return newLiveMsg(kind, time.Now().UnixNano(), conn, "t1a2b3c4", client.Addr(), port, []byte(`{}`))
}

// TestHubFilterAndUpdates: filtros por cliente e connection.updated agregado a 1 por conexão a cada 250 ms (o
// último estado vale); closed descarta o updated pendente.
func TestHubFilterAndUpdates(t *testing.T) {
	h := NewHub(16, 4)
	now := time.Unix(0, base)
	h.now = func() time.Time { return now }
	all, _ := h.join(LiveFilter{DstPort: -1}, "sse")
	dns, _ := h.join(LiveFilter{DstPort: -1, Kinds: map[string]bool{LiveDNSQuery: true}}, "ws")
	port, _ := h.join(LiveFilter{DstPort: 443}, "ws")
	other, _ := h.join(LiveFilter{DstPort: -1, Probe: "zzzzzzzz"}, "ws")
	if _, err := h.join(LiveFilter{}, "sse"); err != ErrTooManyLiveClients {
		t.Fatalf("max clients: %v", err)
	}
	h.Publish(liveTestMsg(LiveConnOpened, "A", 443), liveTestMsg(LiveDNSQuery, "", 53))
	first := newLiveMsg(LiveConnUpdated, now.UnixNano(), "A", "", client.Addr(), 443, []byte(`{"v":1}`))
	h.Publish(first)
	for i := 2; i <= 5; i++ {
		h.Publish(newLiveMsg(LiveConnUpdated, now.UnixNano(), "A", "", client.Addr(), 443, []byte(fmt.Sprintf(`{"v":%d}`, i))))
	}
	if len(all.ch) != 3 {
		t.Fatalf("updates in the window must wait: %d", len(all.ch))
	}
	now = now.Add(260 * time.Millisecond)
	h.flushUpdates()
	if len(all.ch) != 4 || len(dns.ch) != 1 || len(port.ch) != 3 || len(other.ch) != 0 {
		t.Fatalf("all=%d dns=%d port=%d other=%d", len(all.ch), len(dns.ch), len(port.ch), len(other.ch))
	}
	var last *liveMsg
	for len(all.ch) > 0 {
		last = <-all.ch
	}
	if !strings.Contains(string(last.data), `"v":5`) {
		t.Fatalf("aggregated update must carry the last state: %s", last.data)
	}
	// Na janela, um updated pendente some quando a conexão fecha.
	h.Publish(newLiveMsg(LiveConnUpdated, now.UnixNano(), "A", "", client.Addr(), 443, []byte(`{"v":6}`)),
		newLiveMsg(LiveConnClosed, now.UnixNano(), "A", "", client.Addr(), 443, []byte(`{}`)))
	now = now.Add(time.Second)
	h.flushUpdates()
	if got := kinds(drain(all)); got[LiveConnUpdated] != 0 || got[LiveConnClosed] != 1 {
		t.Fatalf("%v", got)
	}
	h.flushUpdates()
	if len(h.lastUpd) != 0 || len(h.pendUpd) != 0 {
		t.Fatal("aggregation state must be released")
	}
	h.leave(other)
	if _, err := h.join(LiveFilter{}, "sse"); err != nil {
		t.Fatal("leaving must free the slot")
	}
	st := h.Stats()
	if st.Clients["ws"] != 2 || st.Clients["sse"] != 2 || st.Events[LiveConnUpdated] != 2 || st.Dropped != 0 {
		t.Fatalf("%+v", st)
	}
}

func drain(c *liveClient) []liveRecv {
	var out []liveRecv
	for len(c.ch) > 0 {
		m := <-c.ch
		out = append(out, liveRecv{Kind: m.kind, raw: m.data})
	}
	return out
}

// TestHubDropsForFullQueue: fila cheia descarta para aquele cliente, sem bloquear, e conta.
func TestHubDropsForFullQueue(t *testing.T) {
	h := NewHub(2, 2)
	slow, _ := h.join(LiveFilter{DstPort: -1}, "sse")
	for range 5 {
		h.Publish(liveTestMsg(LiveHTTPRequest, "A", 443))
	}
	if len(slow.ch) != 2 || slow.dropped.Load() != 3 || h.Stats().Dropped != 3 {
		t.Fatalf("queue=%d dropped=%d", len(slow.ch), slow.dropped.Load())
	}
	var d struct {
		Kind string `json:"kind"`
		Data struct {
			Dropped int `json:"dropped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(slow.nextDropped(time.Now()), &d); err != nil || d.Kind != LiveStreamDrop || d.Data.Dropped != 3 {
		t.Fatalf("%+v %v", d, err)
	}
	if slow.nextDropped(time.Now()) != nil {
		t.Fatal("dropped count must reset")
	}
	var nilHub *Hub
	nilHub.Publish(liveTestMsg(LiveHTTPRequest, "A", 443)) // sem hub: nada
}

// liveAPI sobe a API com o hub e o ingestor de teste.
func liveAPI(t *testing.T, buffer, maxClients int) (*Ingestor, *Hub, *httptest.Server) {
	t.Helper()
	in, db := newTestIngestor(t, nil)
	in.now = time.Now
	h := NewHub(buffer, maxClients)
	in.SetLive(h)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go h.Run(done)
	api := &API{
		OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now,
		Q: NewQueries(db, in.flows.live, 65535), W: db, Live: h,
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return in, h, srv
}

// TestLiveSlowClient: um cliente que não lê perde eventos (stream.dropped com a contagem) e o ingest não espera.
func TestLiveSlowClient(t *testing.T) {
	_, h, srv := liveAPI(t, 8, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/stream", nil)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	eventually(t, 2*time.Second, func() bool { return h.Stats().Clients["sse"] == 1 }, "client not joined")
	// 20 000 eventos de ~1 KiB (20 MiB) passam de qualquer buffer de socket: o cliente não lê nada até o fim.
	const n = 20000
	payload := []byte(`{"pad":"` + strings.Repeat("x", 1000) + `"}`)
	start := time.Now()
	var worst time.Duration
	for range n {
		t0 := time.Now()
		h.Publish(newLiveMsg(LiveHTTPRequest, time.Now().UnixNano(), "A", "", client.Addr(), 443, payload))
		worst = max(worst, time.Since(t0))
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Second || worst > time.Second { // bloquear seria nunca terminar; folga para o -race
		t.Fatalf("publish blocked by the slow client: total %v, worst %v", elapsed, worst)
	}
	if h.Stats().Dropped == 0 {
		t.Fatal("nothing dropped")
	}
	// Agora o cliente lê tudo: eventos entregues + soma dos stream.dropped = publicados.
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	got, dropped, kind := 0, 0, ""
	for got+dropped < n && sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			kind = strings.TrimPrefix(line, "event: ")
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		if kind == LiveStreamDrop {
			var d struct {
				Data struct {
					Dropped int `json:"dropped"`
				} `json:"data"`
			}
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d)
			dropped += d.Data.Dropped
		} else {
			got++
		}
	}
	if dropped == 0 || got+dropped != n {
		t.Fatalf("got=%d dropped=%d want sum %d", got, dropped, n)
	}
	t.Logf("publish %d events: %v (worst %v); delivered %d, dropped %d", n, elapsed, worst, got, dropped)
}

// TestLiveMaxClients: o 65º cliente recebe 503; desconectar libera a vaga; filtro inválido é 400 antes.
func TestLiveMaxClients(t *testing.T) {
	_, h, srv := liveAPI(t, 8, DefaultLiveMaxClients)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancels []context.CancelFunc
	for i := range DefaultLiveMaxClients {
		c, cc := context.WithCancel(ctx)
		cancels = append(cancels, cc)
		if i%2 == 0 {
			_, resp := sseClient(t, c, srv.URL+"/api/v1/stream")
			if resp.StatusCode != 200 {
				t.Fatalf("client %d: %d", i, resp.StatusCode)
			}
		} else {
			wsClient(t, c, strings.Replace(srv.URL, "http", "ws", 1)+"/api/v1/ws", "")
		}
	}
	eventually(t, 3*time.Second, func() bool { return h.Stats().Clients["sse"]+h.Stats().Clients["ws"] == 64 }, "64 clients not joined")
	for _, path := range []string{"/api/v1/stream", "/api/v1/ws"} {
		resp, err := http.Get(srv.URL + path) //nolint:noctx,gosec // teste
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: 65th client got %d", path, resp.StatusCode)
		}
	}
	resp, _ := http.Get(srv.URL + "/api/v1/ws?kind=nope") //nolint:noctx,gosec // teste
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid filter: %d", resp.StatusCode)
	}
	cancels[0]()
	eventually(t, 3*time.Second, func() bool { return h.Stats().Clients["sse"]+h.Stats().Clients["ws"] == 63 }, "slot not freed")
	ch, resp := sseClient(t, ctx, srv.URL+"/api/v1/stream")
	if resp.StatusCode != 200 {
		t.Fatalf("after disconnect: %d", resp.StatusCode)
	}
	_ = ch
}

// TestLiveFeedFromIngest: o ingest (sem NATS) alimenta o feed com todos os kind; cada LiveEvent valida contra o
// openapi; filtros por kind e porta.
func TestLiveFeedFromIngest(t *testing.T) {
	in, _, srv := liveAPI(t, 4096, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	feed, _ := sseClient(t, ctx, srv.URL+"/api/v1/stream")
	onlyDNS := wsClient(t, ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/api/v1/ws?kind=dns.query", "https://other.example")
	onlyQUIC, _ := sseClient(t, ctx, srv.URL+"/api/v1/stream?dst_port=443&probe="+probeID)
	time.Sleep(100 * time.Millisecond)

	shift := time.Now().UnixNano() - base
	at := func(ms int) int { return int(shift/1e6) + ms }
	tcp := batch(client, mirror, protoTCP, fullTCP)
	tcp = shiftBatch(tcp, shift)
	stray := shiftBatch(batch(netip.MustParseAddrPort("192.0.2.99:5555"), mirror, protoTCP, []pkt{{0, true, tcpRST, 0}}), shift)
	processAt(t, in, at(100), tcp, stray,
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, at(25), probeID, tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, at(40), probeID, http1Payload(0, "HTTP/1.1")),
		appMsg(t, event.SubjectWebHTTP2Stream, "tcp", client, mirror, at(45), "", map[string]any{"stream_id": 1, "status": 200}),
		appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, at(0), probeID, dnsPayload("udp")))
	h3 := h3Session(t, 1000)
	for i := range h3 {
		h3[i] = shiftMsg(t, h3[i], shift)
	}
	processAt(t, in, at(200), h3...)
	in.now = time.Now
	if err := in.Finalize(ctx, in.flows.due(time.Now().Add(5*time.Second).UnixNano())); err != nil {
		t.Fatal(err)
	}

	want := []string{LiveConnOpened, LiveConnUpdated, LiveConnClosed, LiveHTTPRequest, LiveDNSQuery, LivePacketStray}
	got := collect(feed, 3*time.Second, func(evs []liveRecv) bool {
		k := kinds(evs)
		for _, w := range want {
			if k[w] == 0 {
				return false
			}
		}
		return k[LiveConnClosed] >= 2 && k[LiveHTTPRequest] >= 5
	})
	k := kinds(got)
	if k[LiveHTTPRequest] != 5 || k[LiveConnClosed] != 2 || k[LivePacketStray] != 1 || k[LiveDNSQuery] != 1 || k[LiveConnOpened] != 2 {
		t.Fatalf("feed kinds %v", k)
	}
	for _, e := range got {
		if e.Kind == LiveHTTPRequest && (e.ConnID == nil || e.ProbeID == nil || *e.ProbeID != probeID) {
			t.Fatalf("http.request without conn_id/probe_id: %s", e.raw)
		}
	}
	dnsOnly := collect(onlyDNS, time.Second, func(evs []liveRecv) bool { return len(evs) >= 1 })
	if kd := kinds(dnsOnly); len(dnsOnly) != 1 || kd[LiveDNSQuery] != 1 {
		t.Fatalf("kind=dns.query got %v", kd)
	}
	quic := collect(onlyQUIC, time.Second, func([]liveRecv) bool { return false })
	for _, e := range quic {
		var d struct {
			Dst endpointJSON `json:"dst"`
			L4  string       `json:"l4"`
		}
		_ = json.Unmarshal(e.Data, &d)
		if e.ProbeID == nil || *e.ProbeID != probeID || (strings.HasPrefix(e.Kind, "connection.") && d.Dst.Port != 443) {
			t.Fatalf("filter dst_port=443&probe leaked: %s", e.raw)
		}
	}
	if kq := kinds(quic); kq[LiveHTTPRequest] != 3 || kq[LiveConnClosed] != 1 || kq[LiveDNSQuery] != 0 {
		t.Fatalf("dst_port=443 got %v", kq)
	}
	// Contrato: um exemplo de cada kind (mais o stream.dropped) valida contra LiveEvent.
	seen := map[string]bool{}
	var samples [][]byte
	for _, e := range got {
		key := e.Kind + string(e.Data[:min(len(e.Data), 12)])
		if !seen[key] {
			seen[key] = true
			samples = append(samples, e.raw)
		}
	}
	slow := &liveClient{}
	slow.dropped.Store(7)
	samples = append(samples, slow.nextDropped(time.Now()))
	validateContract(t, "LiveEvent", samples...)
}

func shiftBatch(m fakeMsg, shift int64) fakeMsg {
	var buf []byte
	_, _ = event.DecodePackets(m.data, func(p event.Packet) error {
		p.TsNs += shift
		buf = event.AppendPacket(buf, p)
		return nil
	})
	return fakeMsg{subject: m.subject, data: buf}
}

func shiftMsg(t *testing.T, m fakeMsg, shift int64) fakeMsg {
	t.Helper()
	if m.subject == event.SubjectCapturePacket {
		return shiftBatch(m, shift)
	}
	env, err := event.Decode(m.data)
	if err != nil {
		t.Fatal(err)
	}
	when, _ := env.Time()
	env.Ts = event.FormatTime(when.Add(time.Duration(shift)))
	data, _ := json.Marshal(env)
	return fakeMsg{subject: m.subject, data: data}
}

// TestIntegrationLive: NATS embutido e store real; 200 requisições h1 publicadas chegam como http.request no /ws
// (com Origin de outra página) e no /stream com p99 < 1 s; o desligamento fecha o WS com 1001.
func TestIntegrationLive(t *testing.T) {
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
	stopped := make(chan struct{})
	go func() { _ = st.Run(ctx); close(stopped) }()
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
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d/api/v1/ws?kind=http.request,connection.opened,connection.closed", port)
	var ws <-chan liveRecv
	eventually(t, 5*time.Second, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", port)) //nolint:noctx,gosec // teste
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil
	}, "api not up")
	ws = wsClient(t, cctx, wsURL, "https://vps602.tmsoft.com.br")
	sse, resp := sseClient(t, cctx, fmt.Sprintf("http://127.0.0.1:%d/api/v1/stream?kind=http.request", port))
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("headers %v", resp.Header)
	}
	eventually(t, 2*time.Second, func() bool { s := st.live.Stats(); return s.Clients["ws"] == 1 && s.Clients["sse"] == 1 }, "clients")

	shift := time.Now().UnixNano() - base
	if _, err := js.Publish(ctx, event.SubjectCapturePacket, shiftBatch(batch(client, mirror, protoTCP, fullTCP[:6]), shift).data); err != nil {
		t.Fatal(err)
	}
	const n = 200
	sentAt := make([]time.Time, n)
	var mu sync.Mutex
	for i := range n {
		m := shiftMsg(t, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(i, "HTTP/1.1")), shift)
		mu.Lock()
		sentAt[i] = time.Now()
		mu.Unlock()
		if _, err := js.Publish(ctx, m.subject, m.data); err != nil {
			t.Fatal(err)
		}
		if i%20 == 19 {
			time.Sleep(20 * time.Millisecond) // ritmo de tráfego real, não uma rajada só
		}
	}
	latencies := func(name string, ch <-chan liveRecv) []time.Duration {
		evs := collect(ch, 10*time.Second, func(evs []liveRecv) bool { return kinds(evs)[LiveHTTPRequest] >= n })
		var out []time.Duration
		for _, e := range evs {
			if e.Kind != LiveHTTPRequest {
				continue
			}
			var d struct {
				Index int `json:"index"`
			}
			_ = json.Unmarshal(e.Data, &d)
			mu.Lock()
			out = append(out, e.at.Sub(sentAt[d.Index]))
			mu.Unlock()
		}
		if len(out) != n {
			t.Fatalf("%s: %d http.request of %d", name, len(out), n)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	wsLat, sseLat := latencies("ws", ws), latencies("sse", sse)
	for name, l := range map[string][]time.Duration{"ws": wsLat, "sse": sseLat} {
		p99 := l[len(l)*99/100-1]
		t.Logf("%s: p50 %v p99 %v", name, l[len(l)/2], p99)
		if p99 >= time.Second {
			t.Fatalf("%s p99 %v", name, p99)
		}
	}
	// Desligamento: o WS recebe 1001.
	c, _, err := websocket.Dial(cctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, _, err = c.Read(cctx)
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Fatalf("close status %v (%v)", websocket.CloseStatus(err), err)
	}
	<-stopped
}
