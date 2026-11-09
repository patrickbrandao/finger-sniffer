package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

const (
	testProbe = "abcdefgh"
	testSNI   = testProbe + ".dns-monitor.tmsoft.com.br"
)

// startNATS sobe um nats-server embutido em porta efêmera.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// collector junta os eventos fs.v1.web.> publicados.
type collector struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func (c *collector) add(m *nats.Msg) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
}

// decoded é um evento decodificado.
type decoded struct {
	Subject string
	Size    int
	Env     event.Envelope
	Payload map[string]any
}

// find devolve os eventos do subject cuja 5-tupla tem src_port igual a port (0 = qualquer).
func (c *collector) find(t *testing.T, subject string, port int) []decoded {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []decoded
	for _, m := range c.msgs {
		if m.Subject != subject {
			continue
		}
		env, err := event.Decode(m.Data)
		if err != nil {
			t.Fatalf("decode %s: %v", subject, err)
		}
		if port != 0 && (env.Flow == nil || env.Flow.SrcPort != port) {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			t.Fatal(err)
		}
		out = append(out, decoded{Subject: m.Subject, Size: len(m.Data), Env: env, Payload: p})
	}
	return out
}

// wait espera até n eventos do subject para a porta.
func (c *collector) wait(t *testing.T, subject string, port, n int) []decoded {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := c.find(t, subject, port)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting %d %s for port %d: got %d", n, subject, port, len(got))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stream remonta os bytes de um sentido a partir dos eventos stream.bytes.
func (c *collector) stream(t *testing.T, port int, dir string) []byte {
	t.Helper()
	var out []byte
	for _, e := range c.find(t, event.SubjectWebStreamBytes, port) {
		if e.Payload["dir"] != dir {
			continue
		}
		var sb event.StreamBytes
		if err := json.Unmarshal(e.Env.Payload, &sb); err != nil {
			t.Fatal(err)
		}
		if int(sb.Offset) != len(out) {
			t.Fatalf("stream %s offset %d, have %d", dir, sb.Offset, len(out))
		}
		out = append(out, sb.Data...)
	}
	return out
}

type harness struct {
	nc     *nats.Conn
	srv    *Server
	events *collector
	connID string
	// addr80 e addr443 são dois listeners efêmeros que fazem o papel das portas 80 e 443.
	addr80, addr443 string
	htdocs          string
}

type harnessOpts struct {
	noStore bool
	cfg     func(*Config)
	deps    func(*Deps)
}

func testConfig(htdocs string) Config {
	return Config{
		MaxConns:       64,
		Htdocs:         htdocs,
		IdleDefault:    3 * time.Second,
		IdleMax:        10 * time.Second,
		DetectBytes:    24,
		DetectTimeout:  300 * time.Millisecond,
		EventInlineMax: event.DefaultEventInlineMax,
		RawBodyMax:     h1.DefaultRawBodyMax,
		RawStreamMax:   event.DefaultRawStreamMaxBytes,
		MaxHeadBytes:   h1.DefaultMaxHeadBytes,
		Zones:          []string{"dns-monitor.tmsoft.com.br", "vps602.tmsoft.com.br"},
	}
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	nc := startNATS(t)
	h := &harness{nc: nc, events: &collector{}, connID: ulid.Make().String(), htdocs: t.TempDir()}
	if _, err := nc.Subscribe("fs.v1.web.>", h.events.add); err != nil {
		t.Fatal(err)
	}
	if !o.noStore {
		// store falso: responde sempre o mesmo ULID reservado (ADR 0017).
		if _, err := nc.Subscribe(event.SubjectStoreConnID, func(m *nats.Msg) {
			var req event.ConnIDRequest
			if json.Unmarshal(m.Data, &req) != nil || req.Flow.L4 != "tcp" || req.Flow.SrcPort == 0 {
				return
			}
			data, _ := json.Marshal(event.ConnIDReply{ConnID: h.connID, Reserved: true})
			_ = m.Respond(data)
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = nc.Flush()

	st, err := certs.Open(certs.Config{
		Dir:         t.TempDir(),
		NamesDNS01:  certs.SplitNames(certs.DefaultNamesDNS01),
		NamesHTTP01: certs.SplitNames(certs.DefaultNamesHTTP01),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := testConfig(h.htdocs)
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	metrics := service.NewMetrics()
	prod := service.NewProducer(nc, 30*time.Second, 64<<20, metrics)
	d := Deps{
		Metrics: metrics,
		Publish: prod.Publish,
		ConnID: func(ctx context.Context, flow event.Flow, ts time.Time) (string, error) {
			rep, err := service.RequestConnID(ctx, nc, flow, ts)
			return rep.ConnID, err
		},
		TLS:         st.TLSConfig(),
		CertReasons: st.Reasons,
	}
	if o.deps != nil {
		o.deps(&d)
	}
	h.srv = NewServer(cfg, d)
	ctx, cancel := context.WithCancel(context.Background())
	for _, a := range []*string{&h.addr80, &h.addr443} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		*a = ln.Addr().String()
		go func() { _ = h.srv.Serve(ctx, ln) }()
	}
	t.Cleanup(func() { cancel(); h.srv.Close() })
	return h
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func dialTLS(t *testing.T, addr, sni string) *tls.Conn {
	t.Helper()
	raw := dial(t, addr)
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // autoassinado de teste
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	return c
}

// srcPort devolve a porta local do cliente (src_port da 5-tupla).
func srcPort(c net.Conn) int {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c.LocalAddr().(*net.TCPAddr).Port
}

// recorder guarda tudo o que o cliente leu, para comparar com o fluxo out.
type recorder struct {
	r   io.Reader
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

// client é um cliente HTTP/1 de teste sobre uma conexão.
type client struct {
	t    *testing.T
	c    net.Conn
	rec  *recorder
	br   *bufio.Reader
	sent bytes.Buffer
}

func newClient(t *testing.T, c net.Conn) *client {
	rec := &recorder{r: c}
	return &client{t: t, c: c, rec: rec, br: bufio.NewReader(rec)}
}

func (cl *client) send(s string) {
	cl.t.Helper()
	cl.sent.WriteString(s)
	_ = cl.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(cl.c, s); err != nil {
		cl.t.Fatal(err)
	}
}

func (cl *client) response(method string) (*http.Response, string) {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(cl.br, &http.Request{Method: method})
	if err != nil {
		cl.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cl.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp, string(body)
}

func get(path, host string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: fs-test\r\n\r\n"
}

func num(t *testing.T, v any) int {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("not a number: %#v", v)
	}
	return int(f)
}

// TestDetectionAnyPort: TLS no listener "80" e HTTP em claro no "443" (e o contrário) são detectados e
// respondidos; o corpo de /p/<id>/ traz o conn_id reservado pelo store; eventos e fluxos batem com os bytes.
func TestDetectionAnyPort(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, addr := range []string{h.addr80, h.addr443} {
		for _, useTLS := range []bool{true, false} {
			t.Run(addr+"/tls="+strconv.FormatBool(useTLS), func(t *testing.T) {
				var c net.Conn
				if useTLS {
					c = dialTLS(t, addr, testSNI)
				} else {
					c = dial(t, addr)
				}
				cl := newClient(t, c)
				cl.send(get("/p/"+testProbe+"/", testSNI))
				resp, body := cl.response("GET")
				want := "conn_id: " + h.connID + "\nrequest: 0\nprobe_id: " + testProbe + "\n"
				if resp.StatusCode != 200 || body != want {
					t.Fatalf("got %d %q", resp.StatusCode, body)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
					t.Fatalf("content-type %q", ct)
				}
				if resp.Header.Get("Alt-Svc") != "" {
					t.Fatal("Alt-Svc without h3")
				}
				port := srcPort(c)
				reqs := h.events.wait(t, event.SubjectWebHTTP1Request, port, 1)
				ev := reqs[0]
				if ev.Env.ProbeID == nil || *ev.Env.ProbeID != testProbe || ev.Env.Service != event.ServiceWeb {
					t.Fatalf("envelope %+v", ev.Env)
				}
				if ev.Env.Flow.DstPort == 0 || ev.Env.Flow.SrcIP != "127.0.0.1" {
					t.Fatalf("flow %+v", ev.Env.Flow)
				}
				p := ev.Payload
				if num(t, p["status"]) != 200 || num(t, p["index"]) != 0 || num(t, p["in_offset"]) != 0 ||
					num(t, p["out_offset"]) != 0 || p["ja4h"] != nil || p["t_first_byte_ms"] == nil {
					t.Fatalf("payload %v", p)
				}
				if got := num(t, p["response_sent_size"]); got != cl.rec.buf.Len() {
					t.Fatalf("response_sent_size %d, client read %d", got, cl.rec.buf.Len())
				}
				in := h.events.stream(t, port, event.DirectionIn)
				out := h.events.stream(t, port, event.DirectionOut)
				if !bytes.Equal(in, cl.sent.Bytes()) || !bytes.Equal(out, cl.rec.buf.Bytes()) {
					t.Fatalf("stream in %q / out %q", in, out)
				}
				if !useTLS {
					return
				}
				ch := h.events.wait(t, event.SubjectWebTLSClientHello, port, 1)[0]
				if ch.Payload["sni"] != testSNI || !strings.HasPrefix(ch.Payload["ja4"].(string), "t13d") ||
					ch.Payload["ja3_md5"] == "" || ch.Env.ProbeID == nil || *ch.Env.ProbeID != testProbe {
					t.Fatalf("client hello %v", ch.Payload)
				}
				hs := h.events.wait(t, event.SubjectWebTLSHandshake, port, 1)[0]
				neg, _ := hs.Payload["negotiated"].(map[string]any)
				if neg == nil || neg["version"] != "TLS 1.3" || neg["alpn"] != "http/1.1" || neg["group"] == "" ||
					hs.Payload["handshake_ms"] == nil {
					t.Fatalf("handshake %v", hs.Payload)
				}
			})
		}
	}
}

// TestConnIDUnknown: sem store respondendo, o corpo traz conn_id: unknown sem esperar mais de ~250 ms.
func TestConnIDUnknown(t *testing.T) {
	h := newHarness(t, harnessOpts{noStore: true, deps: func(d *Deps) {
		// Store lento: só responderia depois do prazo de 250 ms.
		d.ConnID = func(ctx context.Context, _ event.Flow, _ time.Time) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		}
	}})
	c := dial(t, h.addr80)
	start := time.Now()
	cl := newClient(t, c)
	cl.send(get("/p/"+testProbe+"/", "vps602.tmsoft.com.br"))
	_, body := cl.response("GET")
	if !strings.HasPrefix(body, "conn_id: unknown\n") {
		t.Fatalf("body %q", body)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("waited %v", el)
	}
}

// TestIdleDefault: sem idle=, a conexão ociosa só é fechada pelo servidor depois de FS_IDLE_DEFAULT (aqui
// reduzido), tanto depois de uma resposta quanto sem nenhum byte do cliente.
func TestIdleDefault(t *testing.T) {
	const idle = 600 * time.Millisecond
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault = idle }})

	t.Run("after-response", func(t *testing.T) {
		c := dial(t, h.addr80)
		cl := newClient(t, c)
		cl.send(get("/index.html", "x"))
		cl.response("GET")
		start := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := cl.br.ReadByte(); !errors.Is(err, io.EOF) {
			t.Fatalf("want EOF, got %v", err)
		}
		if el := time.Since(start); el < idle-50*time.Millisecond || el > idle+time.Second {
			t.Fatalf("closed after %v, idle %v", el, idle)
		}
	})
	t.Run("silent", func(t *testing.T) {
		c := dial(t, h.addr443)
		start := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("want EOF, got %v", err)
		}
		if el := time.Since(start); el < idle-50*time.Millisecond || el > idle+time.Second {
			t.Fatalf("closed after %v, idle %v", el, idle)
		}
		rs := h.events.wait(t, event.SubjectWebRawSession, srcPort(c), 1)[0]
		if rs.Payload["mode"] != "sink" || len(rs.Payload["reads_in"].([]any)) != 0 {
			t.Fatalf("raw session %v", rs.Payload)
		}
	})
}

// TestRawUnknown: bytes que não são TLS nem HTTP viram raw/unknown em modo sink, com o fluxo in e
// fs.v1.web.raw.session no fim.
func TestRawUnknown(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	msg := "EHLO mail.example\r\nsome more bytes\r\n"
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(c, "tail"); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 16)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("server wrote in sink mode: %d %v", n, err)
	}
	port := srcPort(c)
	rs := h.events.wait(t, event.SubjectWebRawSession, port, 1)[0]
	total := 0
	for _, r := range rs.Payload["reads_in"].([]any) {
		total += num(t, r.([]any)[1])
	}
	if rs.Payload["mode"] != "sink" || rs.Payload["tls"] != false || total != len(msg)+4 {
		t.Fatalf("raw session %v", rs.Payload)
	}
	if in := h.events.stream(t, port, event.DirectionIn); string(in) != msg+"tail" {
		t.Fatalf("stream in %q", in)
	}
}

// TestRawProbeLine: "PROBE <id>" numa porta web vira raw com probe_line e probe_id.
func TestRawProbeLine(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	_, _ = io.WriteString(c, "PROBE "+testProbe+"\r\nxyz")
	_ = c.(*net.TCPConn).CloseWrite()
	rs := h.events.wait(t, event.SubjectWebRawSession, srcPort(c), 1)[0]
	if rs.Payload["probe_line"] != "PROBE "+testProbe || rs.Env.ProbeID == nil || *rs.Env.ProbeID != testProbe {
		t.Fatalf("raw session %v %v", rs.Payload, rs.Env.ProbeID)
	}
}

// TestH2CStub: o prefácio h2c é registrado no fluxo in e a conexão é fechada (h2c na task 025).
func TestH2CStub(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr443)
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	_, _ = io.WriteString(c, preface)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("want close, got %v", err)
	}
	port := srcPort(c)
	deadline := time.Now().Add(2 * time.Second)
	for string(h.events.stream(t, port, event.DirectionIn)) != preface {
		if time.Now().After(deadline) {
			t.Fatalf("stream in %q", h.events.stream(t, port, event.DirectionIn))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTLSHandshakeFailure: cliente que recusa o certificado gera client_hello e handshake com o alerta.
func TestTLSHandshakeFailure(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	raw := dial(t, h.addr443)
	c := tls.Client(raw, &tls.Config{ServerName: testSNI, MaxVersion: tls.VersionTLS12})
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake with self-signed should fail")
	}
	_ = raw.Close()
	port := srcPort(raw)
	h.events.wait(t, event.SubjectWebTLSClientHello, port, 1)
	hs := h.events.wait(t, event.SubjectWebTLSHandshake, port, 1)[0]
	alerts, _ := hs.Payload["alerts"].([]any)
	if hs.Payload["negotiated"] != nil || len(alerts) != 1 {
		t.Fatalf("handshake %v", hs.Payload)
	}
	a := alerts[0].(map[string]any)
	if a["dir"] != "in" || num(t, a["description"]) != 42 && num(t, a["description"]) != 48 {
		t.Fatalf("alert %v", a)
	}
}

// TestStatusDegradedSelfSigned: com o autoassinado em uso, o heartbeat sai degraded com o motivo de pkg/certs.
func TestStatusDegradedSelfSigned(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	st, reasons := h.srv.Status()
	if st != event.StatusDegraded || len(reasons) == 0 || reasons[0] != certs.ReasonSelfSigned {
		t.Fatalf("status %s %v", st, reasons)
	}
}

// TestMaxConns: acima de FS_MAX_CONNS a conexão espera no backlog (não é fechada) e é atendida quando abre vaga.
func TestMaxConns(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.MaxConns = 1 }})
	first := dial(t, h.addr80)
	cl1 := newClient(t, first)
	cl1.send(get("/p/"+testProbe+"/", "x"))
	cl1.response("GET")

	second := dial(t, h.addr80)
	cl2 := newClient(t, second)
	cl2.send(get("/p/"+testProbe+"/", "x"))
	_ = second.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := cl2.br.Peek(1); err == nil {
		t.Fatal("second connection served above FS_MAX_CONNS")
	}
	_ = first.Close()
	resp, _ := cl2.response("GET")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// TestLoadConfig: leitura das variáveis e o corte de FS_RAW_BODY_MAX_BYTES no teto inline.
func TestLoadConfig(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "127.0.0.1")
	t.Setenv("FS_LISTEN_IPV6", "")
	t.Setenv("FS_WEB_TCP_PORTS", "80, 8080")
	t.Setenv("FS_RAW_BODY_MAX_BYTES", "1048576")
	t.Setenv("FS_IDLE_DEFAULT", "30s")
	base, err := service.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if c.RawBodyMax != base.EventInlineMax || len(c.Warnings) != 1 || c.IdleDefault != 30*time.Second {
		t.Fatalf("config %+v", c)
	}
	if got := c.listenAddrs(); len(got) != 2 || got[0] != "127.0.0.1:80" || got[1] != "127.0.0.1:8080" {
		t.Fatalf("addrs %v", got)
	}
	t.Setenv("FS_WEB_TCP_PORTS", "80,x")
	if _, err := LoadConfig(base); err == nil {
		t.Fatal("bad port accepted")
	}
	t.Setenv("FS_WEB_TCP_PORTS", "80")
	t.Setenv("FS_LISTEN_IPV4", "::1")
	if _, err := LoadConfig(base); err == nil {
		t.Fatal("v6 in FS_LISTEN_IPV4 accepted")
	}
}

// TestRunListenRetry: Run abre os listeners da configuração e marca degraded o que não abriu.
func TestRunListenRetry(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	port := busy.Addr().(*net.TCPAddr).Port
	cfg := testConfig(t.TempDir())
	cfg.ListenIPv4 = netip.MustParseAddr("127.0.0.1")
	cfg.TCPPorts = []int{port}
	cfg.RetryListen = 50 * time.Millisecond
	srv := NewServer(cfg, Deps{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if st, r := srv.Status(); st == event.StatusDegraded && strings.HasPrefix(r[0], "listen_failed:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listen failure not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = busy.Close()
	for {
		if st, _ := srv.Status(); st == event.StatusOK {
			break
		}
		if time.Now().After(deadline.Add(2 * time.Second)) {
			t.Fatal("listener not retried")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
