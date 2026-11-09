package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// h2TLSClient é um cliente Go h2 por ALPN contra o listener addr.
func h2TLSClient(addr, sni string) *http.Client {
	var p http.Protocols
	p.SetHTTP2(true)
	tr := &http.Transport{
		Protocols:       &p,
		TLSClientConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true}, //nolint:gosec // autoassinado de teste
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// h2cClient é um cliente Go h2c (prior knowledge) contra addr; port recebe a porta local da conexão.
func h2cClient(addr string, port *int) *http.Client {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: &p,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			if err == nil && port != nil {
				*port = c.LocalAddr().(*net.TCPAddr).Port
			}
			return c, err
		},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func do(t *testing.T, cl *http.Client, method, url string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// lastConn espera o nível de conexão h2 da porta que satisfaz ok e o devolve.
func (c *collector) lastConn(t *testing.T, port int, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := c.find(t, event.SubjectWebHTTP2Connection, port)
		if len(evs) > 0 && ok(evs[len(evs)-1].Payload) {
			return evs[len(evs)-1].Payload
		}
		if time.Now().After(deadline) {
			t.Fatalf("http2.connection for port %d: %d events, last %v", port, len(evs), evs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func anyConn(map[string]any) bool { return true }

// framesOut devolve os tipos dos frames de um sentido.
func framesOf(p map[string]any, dir string) []string {
	var out []string
	list, _ := p["frames"].([]any)
	for _, f := range list {
		m := f.(map[string]any)
		if m["dir"] == dir {
			out = append(out, m["type"].(string))
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestH2ALPN: cliente Go h2 por TLS em /p/<id>/: corpo com conn_id e stream, eventos de conexão (mode
// alpn, Akamai, frames dos dois sentidos) e de stream (ja4h, status), fluxo in a partir do prefácio.
func TestH2ALPN(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	writeFile(t, h.htdocs, "index.html", "<p>x</p>")
	cl := h2TLSClient(h.addr80, testSNI)
	resp, body := do(t, cl, http.MethodGet, "https://"+testSNI+"/p/"+testProbe+"/")
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
		t.Fatalf("proto %s status %d", resp.Proto, resp.StatusCode)
	}
	if !strings.Contains(body, "conn_id: "+h.connID) || !strings.Contains(body, "stream_id: 1") ||
		!strings.Contains(body, "probe_id: "+testProbe) {
		t.Fatalf("body %q", body)
	}
	resp, body = do(t, cl, http.MethodGet, "https://"+testSNI+"/index.html")
	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || body != "<p>x</p>" {
		t.Fatalf("static %v %q", resp.Header, body)
	}
	cl.CloseIdleConnections()

	streams := h.events.wait(t, event.SubjectWebHTTP2Stream, 0, 2)
	port := streams[0].Env.Flow.SrcPort
	st := streams[0].Payload
	if num(t, st["stream_id"]) != 1 || num(t, st["status"]) != 200 || st["ja4h"] == nil ||
		!strings.HasPrefix(st["ja4h"].(string), "ge20") {
		t.Fatalf("stream %v", st)
	}
	if *streams[0].Env.ProbeID != testProbe {
		t.Fatalf("probe %v", streams[0].Env.ProbeID)
	}
	if order := st["pseudo_order"].([]any); len(order) != 4 {
		t.Fatalf("pseudo_order %v", order)
	}
	if num(t, streams[1].Payload["stream_id"]) != 3 {
		t.Fatalf("second stream %v", streams[1].Payload)
	}
	p := h.events.lastConn(t, port, func(p map[string]any) bool {
		return contains(framesOf(p, "in"), "GOAWAY") || len(framesOf(p, "out")) >= 4
	})
	if p["mode"] != h2passive.ModeALPN || p["preface_ok"] != true || len(p["streams"].([]any)) != 0 {
		t.Fatalf("conn %v", p)
	}
	ak, _ := p["akamai"].(string)
	if parts := strings.Split(ak, "|"); len(parts) != 4 || len(parts[3]) != 7 || parts[0] == "" {
		t.Fatalf("akamai %q", ak)
	}
	if out := framesOf(p, "out"); !contains(out, "SETTINGS") || !contains(out, "HEADERS") || !contains(out, "DATA") {
		t.Fatalf("out frames %v", out)
	}
	in := h.events.stream(t, port, event.DirectionIn)
	if !bytes.HasPrefix(in, []byte(h2passive.Preface)) {
		t.Fatalf("stream in %q", in[:min(len(in), 30)])
	}
}

// TestH2CPriorKnowledge: cliente Go h2c sem TLS; controles status, h= e 103 em h2.
func TestH2CPriorKnowledge(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	cl := h2cClient(h.addr443, &port)
	resp, _ := do(t, cl, http.MethodGet, "http://"+testSNI+"/p/"+testProbe+"/r?status=201&h=X-Fs-A:b%20c&size=10")
	if resp.StatusCode != 201 || resp.Header.Get("X-Fs-A") != "b c" || resp.ContentLength != 10 {
		t.Fatalf("resp %d %v", resp.StatusCode, resp.Header)
	}
	streams := h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)
	st := streams[0].Payload
	ctl, _ := st["controls"].(map[string]any)
	if num(t, st["status"]) != 201 || ctl == nil || ctl["params"].(map[string]any)["status"] != "201" {
		t.Fatalf("stream %v", st)
	}
	p := h.events.lastConn(t, port, anyConn)
	if p["mode"] != h2passive.ModePriorKnowledge || p["akamai"] == "" {
		t.Fatalf("conn %v", p)
	}
	// Corpo de padrão: offset i = bodyPattern[i%64].
	_, body := do(t, cl, http.MethodGet, "http://x/r?size=70&chunk=7")
	if body != bodyPattern+bodyPattern[:6] {
		t.Fatalf("body %q", body)
	}
}

// h2raw é um cliente h2 de frames crus.
type h2raw struct {
	t   *testing.T
	c   net.Conn
	fr  *http2.Framer
	enc *hpack.Encoder
	hb  bytes.Buffer
}

func newH2Raw(t *testing.T, c net.Conn, preface bool) *h2raw {
	r := &h2raw{t: t, c: c}
	r.fr = http2.NewFramer(c, c)
	r.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	r.enc = hpack.NewEncoder(&r.hb)
	if preface {
		if _, err := io.WriteString(c, h2passive.Preface); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *h2raw) headers(id uint32, method, path string, prio http2.PriorityParam) {
	r.t.Helper()
	r.hb.Reset()
	for _, f := range [][2]string{{":method", method}, {":authority", testSNI}, {":scheme", "http"}, {":path", path}, {"user-agent", "fs-raw"}} {
		_ = r.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: r.hb.Bytes(), EndStream: true, EndHeaders: true, Priority: prio,
	}); err != nil {
		r.t.Fatal(err)
	}
}

// until lê frames (respondendo SETTINGS com ACK) até ok devolver true.
func (r *h2raw) until(ok func(http2.Frame) bool) http2.Frame {
	r.t.Helper()
	_ = r.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := r.fr.ReadFrame()
		if err != nil {
			r.t.Fatalf("read frame: %v", err)
		}
		if sf, isSettings := f.(*http2.SettingsFrame); isSettings && !sf.IsAck() {
			_ = r.fr.WriteSettingsAck()
		}
		if ok(f) {
			return f
		}
	}
}

// TestH2RawFrames: SETTINGS na ordem, WINDOW_UPDATE, PRIORITY antes do HEADERS (Akamai exato); rst=1 gera
// RST_STREAM e close=after gera GOAWAY, os dois registrados nos frames out.
func TestH2RawFrames(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	if err := r.fr.WriteSettings(http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 3, Val: 1000},
		http2.Setting{ID: 4, Val: 6291456}); err != nil {
		t.Fatal(err)
	}
	_ = r.fr.WriteWindowUpdate(0, 15663105)
	_ = r.fr.WritePriority(3, http2.PriorityParam{Weight: 200})
	_ = r.fr.WritePriority(5, http2.PriorityParam{StreamDep: 3, Exclusive: true, Weight: 100})
	r.headers(1, "GET", "/r?rst=1", http2.PriorityParam{StreamDep: 5, Weight: 41})
	rst := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.RSTStreamFrame); return ok }).(*http2.RSTStreamFrame)
	if rst.StreamID != 1 || rst.ErrCode != http2.ErrCodeInternal {
		t.Fatalf("rst %v", rst)
	}
	r.headers(7, "GET", "/r?close=after", http2.PriorityParam{})
	// O stream 7 termina normalmente e o servidor manda GOAWAY (NO_ERROR), em qualquer ordem.
	var ga *http2.GoAwayFrame
	ended := false
	r.until(func(f http2.Frame) bool {
		if g, ok := f.(*http2.GoAwayFrame); ok {
			ga = g
		}
		if f.Header().StreamID == 7 && f.Header().Flags.Has(http2.FlagDataEndStream) {
			ended = true
		}
		return ga != nil && ended
	})
	if ga.ErrCode != http2.ErrCodeNo || ga.LastStreamID != 7 {
		t.Fatalf("goaway %v", ga)
	}
	port := srcPort(c)
	p := h.events.lastConn(t, port, func(p map[string]any) bool { return contains(framesOf(p, "out"), "GOAWAY") })
	want := "1:65536;3:1000;4:6291456|15663105|3:0:0:201,5:1:3:101|m,a,s,p"
	if p["akamai"] != want {
		t.Fatalf("akamai %q want %q", p["akamai"], want)
	}
	if out := framesOf(p, "out"); !contains(out, "RST_STREAM") {
		t.Fatalf("out %v", out)
	}
	streams := h.events.wait(t, event.SubjectWebHTTP2Stream, port, 2)
	pr := streams[0].Payload["priority"].(map[string]any)
	if num(t, pr["depends_on"]) != 5 || num(t, pr["weight"]) != 42 {
		t.Fatalf("priority %v", pr)
	}
}

// TestH2RepeatedSettings: SETTINGS com ids repetidos ficam na ordem recebida, com as repetições, no
// registro e no Akamai. O x/net recusa a repetição com GOAWAY PROTOCOL_ERROR (RFC 9113 não a proíbe, mas o
// servidor sem fork é assim); o registro sai mesmo assim.
func TestH2RepeatedSettings(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings(http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 3, Val: 1000}, http2.Setting{ID: 1, Val: 4096})
	ga := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.GoAwayFrame); return ok }).(*http2.GoAwayFrame)
	if ga.ErrCode != http2.ErrCodeProtocol {
		t.Fatalf("goaway %v", ga)
	}
	p := h.events.lastConn(t, srcPort(c), func(p map[string]any) bool { return contains(framesOf(p, "out"), "GOAWAY") })
	got, _ := json.Marshal(p["settings"])
	if string(got) != "[[1,65536],[3,1000],[1,4096]]" || !strings.HasPrefix(p["akamai"].(string), "1:65536;3:1000;1:4096|") {
		t.Fatalf("settings %s akamai %v", got, p["akamai"])
	}
}

// TestH2PriorityLimit: frames PRIORITY além de FS_MAX_H2_PRIORITY_FRAMES não entram no registro.
func TestH2PriorityLimit(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) {
		c.H2Limits = h2passive.DefaultLimits()
		c.H2Limits.MaxPriorityFrames = 5
	}})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	for i := uint32(0); i < 50; i++ {
		_ = r.fr.WritePriority(3+2*i, http2.PriorityParam{Weight: 15})
	}
	r.headers(1, "GET", "/p/"+testProbe+"/", http2.PriorityParam{})
	r.until(func(f http2.Frame) bool {
		return f.Header().StreamID == 1 && f.Header().Flags.Has(http2.FlagDataEndStream)
	})
	p := h.events.lastConn(t, srcPort(c), anyConn)
	if len(p["priorities"].([]any)) != 5 || p["priority_frames_capped"] != true {
		t.Fatalf("priorities %d capped %v", len(p["priorities"].([]any)), p["priority_frames_capped"])
	}
}

// TestH2CUpgrade: Upgrade: h2c pelo HTTP/1: 101 registrado em http1.request (com ja4h), resposta no
// stream 1 do h2 e conexão com mode upgrade.
func TestH2CUpgrade(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr443)
	settings := base64.RawURLEncoding.EncodeToString([]byte{0, 3, 0, 0, 0, 100})
	_, _ = io.WriteString(c, "GET /p/"+testProbe+"/ HTTP/1.1\r\nHost: "+testSNI+"\r\nConnection: Upgrade, HTTP2-Settings\r\n"+
		"Upgrade: h2c\r\nHTTP2-Settings: "+settings+"\r\nUser-Agent: fs-test\r\n\r\n")
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("Upgrade") != "h2c" {
		t.Fatalf("101: %v %v", resp, err)
	}
	if _, err := io.WriteString(c, h2passive.Preface); err != nil {
		t.Fatal(err)
	}
	r := &h2raw{t: t, c: c}
	r.fr = http2.NewFramer(c, br)
	r.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	_ = r.fr.WriteSettings(http2.Setting{ID: 4, Val: 1 << 20})
	hf := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.MetaHeadersFrame); return ok }).(*http2.MetaHeadersFrame)
	if hf.StreamID != 1 || hf.PseudoValue("status") != "200" {
		t.Fatalf("headers %v", hf)
	}
	df := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.DataFrame); return ok }).(*http2.DataFrame)
	if !strings.Contains(string(df.Data()), "conn_id: "+h.connID) {
		t.Fatalf("data %q", df.Data())
	}
	port := srcPort(c)
	reqs := h.events.wait(t, event.SubjectWebHTTP1Request, port, 1)
	if num(t, reqs[0].Payload["status"]) != 101 || reqs[0].Payload["ja4h"] == nil {
		t.Fatalf("http1 %v", reqs[0].Payload)
	}
	streams := h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)
	if num(t, streams[0].Payload["stream_id"]) != 1 || streams[0].Payload["ja4h"] != reqs[0].Payload["ja4h"] {
		t.Fatalf("stream %v", streams[0].Payload)
	}
	// O stream 1 pode terminar antes do SETTINGS do cliente: espera o fim da conexão, que traz tudo.
	_ = c.Close()
	p := h.events.lastConn(t, port, func(p map[string]any) bool { return len(p["settings"].([]any)) > 0 })
	if p["mode"] != h2passive.ModeUpgrade || p["preface_ok"] != true {
		t.Fatalf("conn %v", p)
	}
	set := p["settings"].([]any)
	if len(set) != 1 || num(t, set[0].([]any)[0]) != 4 {
		t.Fatalf("settings %v", set)
	}
}

// TestH2DelayHoldsIdle: com stream em atendimento a ociosidade não corre (delay_head maior que idle).
func TestH2DelayHoldsIdle(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault = 300 * time.Millisecond }})
	cl := h2cClient(h.addr80, nil)
	start := time.Now()
	resp, _ := do(t, cl, http.MethodGet, "http://x/r?delay_head=800")
	if resp.StatusCode != 200 || time.Since(start) < 800*time.Millisecond {
		t.Fatalf("status %d after %v", resp.StatusCode, time.Since(start))
	}
}

// TestH2BadPreface: h2 por ALPN com prefácio errado: registro com preface_ok false e a conexão fica aberta
// até o cliente fechar (o servidor não fecha antes da ociosidade).
func TestH2BadPreface(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	raw := dial(t, h.addr80)
	c := tls.Client(raw, &tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // autoassinado de teste
	if err := c.Handshake(); err != nil || c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("handshake %v %q", err, c.ConnectionState().NegotiatedProtocol)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
		t.Fatalf("want open, got %v", err)
	}
	_ = c.Close()
	p := h.events.lastConn(t, srcPort(c), anyConn)
	if p["preface_ok"] != false {
		t.Fatalf("conn %v", p)
	}
}

// TestH2GoldenClients: os bytes h2 decifrados de curl, Go, Chrome e Firefox (task 036) enviados em h2c dão
// o mesmo Akamai e o mesmo JA4H do primeiro stream que o tshark e a ferramenta da FoxIO.
func TestH2GoldenClients(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	dir := filepath.Join("..", "..", "pkg", "h2passive", "testdata", "clients")
	files, _ := filepath.Glob(filepath.Join(dir, "*.client.h2"))
	if len(files) == 0 {
		t.Fatal("no golden clients")
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".client.h2")
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var want struct {
				Akamai string `json:"akamai"`
				JA4H   string `json:"ja4h"`
			}
			exp, err := os.ReadFile(filepath.Join(dir, name+".expected.json"))
			if err != nil || json.Unmarshal(exp, &want) != nil {
				t.Fatalf("expected: %v", err)
			}
			c := dial(t, h.addr80)
			if _, err := c.Write(data); err != nil {
				t.Fatal(err)
			}
			port := srcPort(c)
			h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)
			_ = c.(*net.TCPConn).CloseWrite()
			p := h.events.lastConn(t, port, func(p map[string]any) bool { return contains(framesOf(p, "out"), "HEADERS") })
			// O primeiro stream (menor id): os handlers de streams diferentes terminam em qualquer ordem.
			var st map[string]any
			for _, e := range h.events.find(t, event.SubjectWebHTTP2Stream, port) {
				if st == nil || num(t, e.Payload["stream_id"]) < num(t, st["stream_id"]) {
					st = e.Payload
				}
			}
			if p["akamai"] != want.Akamai {
				t.Errorf("akamai %q want %q", p["akamai"], want.Akamai)
			}
			if want.JA4H != "" && st["ja4h"] != want.JA4H {
				t.Errorf("ja4h %v want %q", st["ja4h"], want.JA4H)
			}
		})
	}
}

// TestH2EventsContractAndGolden confere os eventos h2 com o contrato e com testdata/events/.
func TestH2EventsContractAndGolden(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	cl := h2cClient(h.addr80, &port)
	do(t, cl, http.MethodGet, "http://"+testSNI+"/p/"+testProbe+"/r?status=200")
	cl.CloseIdleConnections()
	h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)
	h.events.lastConn(t, port, anyConn)
	blocks := contractBlocks(t)
	for _, subj := range []string{event.SubjectWebHTTP2Connection, event.SubjectWebHTTP2Stream} {
		evs := h.events.find(t, subj, port)
		for _, e := range evs {
			checkContract(t, blocks, e)
		}
		checkGolden(t, subj, evs[0])
	}
}

// TestH2StopWhileDelayed: a parada do serviço interrompe um delay_head em h2 sem travar o Close.
func TestH2StopWhileDelayed(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	cl := h2cClient(h.addr80, nil)
	errc := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "http://x/r?delay_head=30000", nil)
		resp, err := cl.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	done := make(chan struct{})
	go func() { h.srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked")
	}
	if err := <-errc; err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("want connection error, got %v", err)
	}
}
