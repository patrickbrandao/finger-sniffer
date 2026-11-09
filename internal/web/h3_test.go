package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// startH3 abre um listener UDP efêmero no servidor do harness (o Alt-Svc passa a valer para ele) e um
// store falso que responde o conn_id também para l4=udp.
func startH3(t *testing.T, h *harness) *net.UDPConn {
	t.Helper()
	if _, err := h.nc.Subscribe(event.SubjectStoreConnID, func(m *nats.Msg) {
		var req event.ConnIDRequest
		if json.Unmarshal(m.Data, &req) != nil || req.Flow.L4 != "udp" || req.Flow.QUICDCIDHex == "" {
			return
		}
		data, _ := json.Marshal(event.ConnIDReply{ConnID: h.connID, Reserved: true})
		_ = m.Respond(data)
	}); err != nil {
		t.Fatal(err)
	}
	_ = h.nc.Flush()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.h3AnyPort = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = h.srv.ServeQUIC(ctx, pc); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for !h.srv.h3Active() {
		if time.Now().After(deadline) {
			t.Fatal("listener h3 não subiu")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return pc
}

func h3Client(t *testing.T) *http3.Transport {
	t.Helper()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: testSNI, InsecureSkipVerify: true}, //nolint:gosec // autoassinado de teste
		QUICConfig:      &quic.Config{MaxIdleTimeout: 5 * time.Second},
	}
	return tr
}

func h3Get(t *testing.T, cl *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

// TestH3Integration: cliente quic-go/http3 contra o servidor → espelho com conn_id, controles aplicados
// (status, size, h=, trailers), controle que não existe em h3 recusado com 400, e os eventos http3.connection
// (Initial com transport params na ordem e JA4 q, SETTINGS do cliente, close) e http3.request (pseudo_order,
// repr QPACK, controls) conferidos com o contrato e os goldens.
func TestH3Integration(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	port := pc.LocalAddr().(*net.UDPAddr).Port
	base := "https://127.0.0.1:" + itoa(port)
	tr := h3Client(t)
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	resp, body := h3Get(t, cl, base+"/p/"+testProbe+"/")
	if resp.StatusCode != 200 || resp.Proto != "HTTP/3.0" || !strings.Contains(body, "conn_id: "+h.connID) ||
		!strings.Contains(body, "probe_id: "+testProbe) {
		t.Fatalf("espelho %d %s %q", resp.StatusCode, resp.Proto, body)
	}
	if resp.Header.Get("Alt-Svc") != "" {
		t.Fatal("Alt-Svc numa resposta h3")
	}
	resp, body = h3Get(t, cl, base+"/p/"+testProbe+"/r?status=201&size=10&h=X-A:b&trailers=1&delay_head=5")
	if resp.StatusCode != 201 || body != "0123456789" || resp.Header.Get("X-A") != "b" ||
		resp.Trailer.Get(TrailerName) != "1" {
		t.Fatalf("controles %d %q %v trailer %v", resp.StatusCode, body, resp.Header, resp.Trailer)
	}
	h3Get(t, cl, base+"/r?delay_head=200&size=5")
	resp, body = h3Get(t, cl, base+"/r?close=after&ver=1.0")
	if resp.StatusCode != 400 || !strings.Contains(body, "close=after: not applicable to HTTP/3") ||
		!strings.Contains(body, "ver=1.0: not applicable to HTTP/3") {
		t.Fatalf("não aplicável %d %q", resp.StatusCode, body)
	}
	resp, _ = h3Get(t, cl, base+"/.well-known/acme-challenge/x")
	if resp.StatusCode != 404 {
		t.Fatalf("acme %d", resp.StatusCode)
	}
	_ = tr.Close()

	reqs := h.events.wait(t, event.SubjectWebHTTP3Request, 0, 5)
	// Instantes (spec 011 RF-03): em ordem em todas; delay_head=200 entre o FIN do cliente e o HEADERS.
	for _, r := range reqs {
		in := instantsOf(t, r.Payload)
		checkOrder(t, "h3", in)
		if ctl, _ := r.Payload["controls"].(map[string]any); ctl != nil &&
			ctl["params"].(map[string]any)["delay_head"] == "200" && in.respStart.Sub(in.reqEnd) < 200*time.Millisecond {
			t.Fatalf("h3 delay_head: %+v", in)
		}
	}
	conns := h.events.wait(t, event.SubjectWebHTTP3Connection, 0, 3)
	last := conns[len(conns)-1].Payload
	deadline := time.Now().Add(5 * time.Second)
	for last["close"] == nil {
		if time.Now().After(deadline) {
			t.Fatal("sem http3.connection com close")
		}
		time.Sleep(10 * time.Millisecond)
		conns = h.events.find(t, event.SubjectWebHTTP3Connection, 0)
		last = conns[len(conns)-1].Payload
	}
	env := conns[0].Env
	if env.Flow == nil || env.Flow.L4 != "udp" || env.Flow.QUICDCIDHex == "" || env.ProbeID == nil ||
		*env.ProbeID != testProbe {
		t.Fatalf("envelope %+v", env)
	}
	first := conns[0].Payload
	ch := first["client_hello"].(map[string]any)
	if !strings.HasPrefix(ch["ja4"].(string), "q13d") || ch["negotiated"] == nil ||
		len(first["transport_params"].([]any)) < 5 || first["version"] != "00000001" {
		t.Fatalf("Initial: ja4 %v negotiated %v tps %v", ch["ja4"], ch["negotiated"], first["transport_params"])
	}
	tp0 := first["transport_params"].([]any)[0].([]any)
	if len(tp0) != 3 {
		t.Fatalf("transport param %v", tp0)
	}
	if len(last["h3_settings"].([]any)) == 0 {
		t.Fatalf("sem h3_settings: %v", last)
	}
	cls := last["close"].(map[string]any)
	if cls["by"] != "client" || cls["how"] != quicparse.CloseApplication {
		t.Fatalf("close %v", cls)
	}

	var mirror, ctl map[string]any
	for _, r := range reqs {
		switch num(t, r.Payload["status"]) {
		case 200:
			mirror = r.Payload
		case 201:
			ctl = r.Payload
		}
	}
	if mirror == nil || ctl == nil {
		t.Fatal("requisições sem 200/201")
	}
	po := mirror["pseudo_order"].([]any)
	// o quic-go manda :authority primeiro: a ordem é a do fio
	if len(po) != 4 || po[0] != ":authority" || po[1] != ":method" {
		t.Fatalf("pseudo_order %v", po)
	}
	f0 := mirror["fields"].([]any)[0].(map[string]any)
	if f0["repr"] == nil || f0["name"] != ":authority" || f0["value"] == "" || mirror["ja4h"] == nil {
		t.Fatalf("campo %v", f0)
	}
	params := ctl["controls"].(map[string]any)["params"].(map[string]any)
	if params["status"] != "201" || params["size"] != "10" {
		t.Fatalf("controls %v", ctl["controls"])
	}

	blocks := contractBlocks(t)
	for _, e := range append(reqs, conns...) {
		checkContract(t, blocks, e)
	}
	checkGolden(t, event.SubjectWebHTTP3Connection, conns[len(conns)-1])
	for _, r := range reqs {
		if num(t, r.Payload["status"]) == 201 {
			checkGolden(t, event.SubjectWebHTTP3Request, r)
		}
	}
	if v := h.srv.metrics.Snapshot()[MetricH3Listening]; v != 1 {
		t.Fatalf("h3_listening %v", v)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestAltSvc: Alt-Svc em h1 e h2 sobre TLS com o h3 de pé; ausente com alt_svc=0, na porta em claro e
// sem listener (heartbeat degraded com h3_listener_down).
func TestAltSvc(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.UDPPorts = []int{443} }})
	if st, reasons := h.srv.Status(); st != event.StatusDegraded || !strings.Contains(strings.Join(reasons, ","), ReasonH3Down) {
		t.Fatalf("sem listener: %s %v", st, reasons)
	}
	get := func(proto, addr, path string) string {
		t.Helper()
		trp := &http.Transport{
			TLSClientConfig:   &tls.Config{ServerName: testSNI, InsecureSkipVerify: true}, //nolint:gosec // teste
			ForceAttemptHTTP2: proto == "h2",
		}
		if proto == "h1" {
			trp.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		defer trp.CloseIdleConnections()
		scheme := "https"
		if proto == "plain" {
			scheme = "http"
		}
		resp, err := (&http.Client{Transport: trp, Timeout: 5 * time.Second}).Get(scheme + "://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if proto == "h2" && resp.ProtoMajor != 2 {
			t.Fatalf("h2 virou %s", resp.Proto)
		}
		return resp.Header.Get("Alt-Svc")
	}
	writeFile(t, h.htdocs, "index.html", "<p>x</p>")
	if v := get("h1", h.addr443, "/"); v != "" {
		t.Fatalf("Alt-Svc sem listener: %q", v)
	}
	startH3(t, h)
	if st, reasons := h.srv.Status(); strings.Contains(strings.Join(reasons, ","), ReasonH3Down) {
		t.Fatalf("listener de pé: %s %v", st, reasons)
	}
	for _, proto := range []string{"h1", "h2"} {
		for _, path := range []string{"/", "/p/" + testProbe + "/", "/r?size=1"} {
			if v := get(proto, h.addr443, path); v != altSvcH3 {
				t.Errorf("%s %s: Alt-Svc %q", proto, path, v)
			}
		}
		if v := get(proto, h.addr443, "/r?size=1&alt_svc=0"); v != "" {
			t.Errorf("%s alt_svc=0: %q", proto, v)
		}
		if v := get(proto, h.addr443, "/?alt_svc=0"); v != "" {
			t.Errorf("%s htdocs alt_svc=0: %q", proto, v)
		}
	}
	if v := get("plain", h.addr80, "/"); v != "" {
		t.Errorf("porta em claro: %q", v)
	}
}

// TestH3Curl: um curl com HTTP3 (ngtcp2/nghttp3), se houver um no PATH ou em FS_TEST_CURL, consegue o
// espelho por h3 e a requisição vira evento com os campos do curl na ordem.
func TestH3Curl(t *testing.T) {
	curl := os.Getenv("FS_TEST_CURL")
	if curl == "" {
		curl = "curl"
	}
	out, err := exec.Command(curl, "-V").Output()
	if err != nil || !strings.Contains(string(out), "HTTP3") {
		t.Skip("curl sem HTTP3")
	}
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	url := "https://localhost:" + itoa(pc.LocalAddr().(*net.UDPAddr).Port) + "/p/" + testProbe + "/r?size=5&h=X-T:1"
	got, err := exec.Command(curl, "-sk", "--http3-only", "-m", "5", "-i", url).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(got), "HTTP/3 200") || !strings.Contains(string(got), "x-t: 1") ||
		!strings.HasSuffix(string(got), "01234") {
		t.Fatalf("curl: %v %q", err, got)
	}
	reqs := h.events.wait(t, event.SubjectWebHTTP3Request, 0, 1)
	po := reqs[0].Payload["pseudo_order"].([]any)
	if len(po) != 4 || po[0] != ":method" || po[1] != ":scheme" {
		t.Fatalf("pseudo_order do curl %v", po)
	}
}

// TestH3ResetInstants: stream que o servidor encerra por erro (RESET_STREAM sem HEADERS, aqui um stream
// sem HEADERS com FIN) sai com response_started_at nulo e response_ended_at preenchido: cada instante é
// independente (nulo = não observado), e o reset conta como fim da resposta.
func TestH3ResetInstants(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h3"}}, //nolint:gosec // autoassinado de teste
		&quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = qc.CloseWithError(0, "") }()
	str, err := qc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	reqs := h.events.wait(t, event.SubjectWebHTTP3Request, 0, 1)
	in := instantsOf(t, reqs[0].Payload)
	if !in.respStart.IsZero() || in.respEnd.IsZero() {
		t.Fatalf("reset sem HEADERS: %+v", in)
	}
}
