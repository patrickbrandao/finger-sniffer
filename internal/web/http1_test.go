package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// TestKeepAlive5: cinco requisições na mesma conexão, com índice, offsets e tempos de cada uma.
func TestKeepAlive5(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	var inOff, outOff []int
	for i := range 5 {
		inOff = append(inOff, cl.sent.Len())
		outOff = append(outOff, cl.rec.buf.Len())
		cl.send(get("/p/"+testProbe+"/", "vps602.tmsoft.com.br"))
		_, body := cl.response("GET")
		if !strings.Contains(body, "request: "+string(rune('0'+i))+"\n") {
			t.Fatalf("request %d body %q", i, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	evs := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 5)
	for i, e := range evs {
		p := e.Payload
		if num(t, p["index"]) != i || num(t, p["in_offset"]) != inOff[i] || num(t, p["out_offset"]) != outOff[i] {
			t.Fatalf("req %d: index %v in %v out %v (want %d %d)", i, p["index"], p["in_offset"], p["out_offset"], inOff[i], outOff[i])
		}
		if p["pipelined"] != false {
			t.Fatalf("req %d pipelined", i)
		}
		if i == 0 && (p["t_first_byte_ms"] == nil || p["t_since_prev_response_ms"] != nil) {
			t.Fatalf("req 0 times %v %v", p["t_first_byte_ms"], p["t_since_prev_response_ms"])
		}
		if i > 0 && (p["t_since_prev_response_ms"] == nil || p["t_since_prev_response_ms"].(float64) < 15) {
			t.Fatalf("req %d t_since_prev %v", i, p["t_since_prev_response_ms"])
		}
	}
}

// TestPipelining3: três requisições numa escrita só; as duas últimas saem pipelined=true.
func TestPipelining3(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr443)
	cl := newClient(t, c)
	r := get("/p/"+testProbe+"/", "x")
	cl.send(r + r + r)
	for range 3 {
		cl.response("GET")
	}
	evs := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 3)
	for i, want := range []bool{false, true, true} {
		if evs[i].Payload["pipelined"] != want || num(t, evs[i].Payload["in_offset"]) != i*len(r) {
			t.Fatalf("req %d: %v", i, evs[i].Payload)
		}
	}
}

// TestExpectContinue: o servidor manda o 100 antes de ler o corpo; o cliente esperou e o tempo fica registrado.
func TestExpectContinue(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send("POST /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := cl.br.ReadString('\n')
	if err != nil || line != "HTTP/1.1 100 Continue\r\n" {
		t.Fatalf("interim %q %v", line, err)
	}
	if blank, _ := cl.br.ReadString('\n'); blank != "\r\n" {
		t.Fatalf("interim end %q", blank)
	}
	time.Sleep(60 * time.Millisecond)
	cl.send("hello")
	resp, _ := cl.response("POST")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload
	ec, _ := p["expect_continue"].(map[string]any)
	if ec == nil || ec["waited"] != true || ec["wait_ms"] == nil || ec["wait_ms"].(float64) < 50 {
		t.Fatalf("expect_continue %v", p["expect_continue"])
	}
	sent, _ := base64.StdEncoding.DecodeString(p["response_sent_b64"].(string))
	if !strings.HasPrefix(string(sent), "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n") ||
		num(t, p["response_sent_size"]) != len(sent) || num(t, p["status"]) != 200 {
		t.Fatalf("response_sent %q", sent)
	}
	body := p["body"].(map[string]any)
	if body["framing"] != "content-length" || num(t, body["size"]) != 5 {
		t.Fatalf("body %v", body)
	}
}

// bigHead monta uma requisição com cabeçalho de exatamente size bytes (linha de requisição até a linha vazia).
func bigHead(size int) string {
	prefix := "GET /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nX-Big: "
	return prefix + strings.Repeat("a", size-len(prefix)-4) + "\r\n\r\n"
}

// TestHeadLimit: cabeçalho de 1 MiB - 1 byte é atendido e o evento fica abaixo de 900 KiB com o inline
// cortado; acima de 1 MiB, 431 com head_too_large, e a conexão não é fechada pelo servidor.
func TestHeadLimit(t *testing.T) {
	h := newHarness(t, harnessOpts{})

	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send(bigHead(1<<20 - 1))
	if resp, _ := cl.response("GET"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0]
	p := e.Payload
	if e.Size > event.MaxEventBytes || p["raw_head_truncated"] != true || p["fields_truncated"] != true ||
		num(t, p["head_size"]) != 1<<20-1 || num(t, p["field_count"]) != 2 || p["head_too_large"] != false {
		t.Fatalf("size %d payload head_size=%v trunc=%v fields_trunc=%v", e.Size, p["head_size"], p["raw_head_truncated"], p["fields_truncated"])
	}
	raw, _ := base64.StdEncoding.DecodeString(p["raw_head_b64"].(string))
	if len(raw) != event.DefaultEventInlineMax {
		t.Fatalf("inline %d", len(raw))
	}

	c2 := dial(t, h.addr443)
	cl2 := newClient(t, c2)
	cl2.send(bigHead(1<<20 + 100))
	if resp, _ := cl2.response("GET"); resp.StatusCode != 431 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e = h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c2), 1)[0]
	if e.Size > event.MaxEventBytes || e.Payload["head_too_large"] != true || num(t, e.Payload["status"]) != 431 {
		t.Fatalf("431 event size %d %v", e.Size, e.Payload["head_too_large"])
	}
	// Depois do 431 o servidor continua lendo (descarta) e não fecha.
	_ = c2.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := cl2.br.ReadByte(); !isTimeout(err) {
		t.Fatalf("server closed after 431: %v", err)
	}
}

// TestBadRequest: linha de campo inválida → 400 com os bytes crus no evento.
func TestBadRequest(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	req := "GET /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nno colon here\r\n\r\n"
	cl.send(req)
	if resp, _ := cl.response("GET"); resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	e := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0]
	raw, _ := base64.StdEncoding.DecodeString(e.Payload["raw_head_b64"].(string))
	if !strings.HasPrefix(req, string(raw)) || len(raw) == 0 || num(t, e.Payload["status"]) != 400 ||
		e.Env.ProbeID == nil || *e.Env.ProbeID != testProbe {
		t.Fatalf("raw %q payload %v", raw, e.Payload)
	}
}

// TestFieldsAsReceived: caixa, ordem, duplicatas, separador e LF puro chegam iguais (spec 009 caso 1).
func TestFieldsAsReceived(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send("GET /r HTTP/1.1\r\nhOsT:x\nX-Dup:  a  \r\nx-dup: b\r\n\r\n")
	cl.response("GET")
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload
	got, _ := json.Marshal(p["fields"])
	want := `[["hOsT",":","x","lf"],["X-Dup",":  ","a  ","crlf"],["x-dup",": ","b","crlf"]]`
	if string(got) != want {
		t.Fatalf("fields %s", got)
	}
	if d, _ := json.Marshal(p["duplicates"]); string(d) != `["x-dup"]` {
		t.Fatalf("duplicates %s", d)
	}
}

// TestChunkedBody: corpo chunked com extensões e trailers, pedaço a pedaço.
func TestChunkedBody(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send("POST /r HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"3;a=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n")
	cl.response("POST")
	body := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload["body"].(map[string]any)
	chunks, _ := json.Marshal(body["chunks"])
	trailers, _ := json.Marshal(body["trailers"])
	if body["framing"] != "chunked" || num(t, body["size"]) != 5 ||
		string(chunks) != `[{"ext":";a=1","size":3,"size_literal":"3"},{"ext":null,"size":2,"size_literal":"2"},{"ext":null,"size":0,"size_literal":"0"}]` ||
		string(trailers) != `[["X-Trailer",": ","t","crlf"]]` {
		t.Fatalf("body %v chunks %s trailers %s", body, chunks, trailers)
	}
	if body["chunks_truncated"] != false || body["raw_truncated"] != false {
		t.Fatalf("truncation flags %v", body)
	}
}

// TestChunksTruncated: corpo com mais de 4096 pedaços registra só os primeiros e marca chunks_truncated;
// tamanho e SHA-256 continuam do corpo inteiro.
func TestChunksTruncated(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	const n = h1.DefaultMaxChunks + 10
	cl.send("POST /r HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		strings.Repeat("1\r\nx\r\n", n) + "0\r\n\r\n")
	cl.response("POST")
	body := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload["body"].(map[string]any)
	sum := sha256.Sum256([]byte(strings.Repeat("x", n)))
	if body["chunks_truncated"] != true || len(body["chunks"].([]any)) != h1.DefaultMaxChunks ||
		num(t, body["size"]) != n || body["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("chunks_truncated %v chunks %d size %v", body["chunks_truncated"], len(body["chunks"].([]any)), body["size"])
	}
}

// TestProxySignals: Via, absolute-form numa conexão direta e Host diferente do SNI.
func TestProxySignals(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dialTLS(t, h.addr443, testSNI)
	cl := newClient(t, c)
	cl.send("GET http://other.example/p/" + testProbe + "/ HTTP/1.1\r\nHost: other.example\r\nVia: 1.1 squid\r\n\r\n")
	if _, body := cl.response("GET"); !strings.HasPrefix(body, "conn_id: ") {
		t.Fatalf("body %q", body)
	}
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload
	kinds := map[string]bool{}
	for _, s := range p["proxy_signals"].([]any) {
		kinds[s.(map[string]any)["kind"].(string)] = true
	}
	for _, k := range []string{"via", "absolute-form-direct", "host-sni-mismatch"} {
		if !kinds[k] {
			t.Fatalf("missing %s in %v", k, p["proxy_signals"])
		}
	}
}

// TestInline: ?inline=1 devolve o JSON da própria requisição.
func TestInline(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send(get("/p/"+testProbe+"/?inline=1", "x"))
	resp, body := cl.response("GET")
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("inline %v %q", err, body)
	}
	rl := got["request_line"].(map[string]any)
	if rl["target"] != "/p/"+testProbe+"/?inline=1" || rl["form"] != "origin" {
		t.Fatalf("request_line %v", rl)
	}
}

// TestHead: HEAD recebe o Content-Length do GET sem corpo.
func TestHead(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	writeFile(t, h.htdocs, "index.html", "<p>hi</p>")
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send("HEAD /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, body := cl.response("HEAD")
	if resp.StatusCode != 200 || resp.ContentLength != 9 || body != "" {
		t.Fatalf("head %d %d %q", resp.StatusCode, resp.ContentLength, body)
	}
	// A conexão continua utilizável: nenhum corpo foi mandado depois do HEAD.
	cl.send(get("/index.html", "x"))
	if _, body := cl.response("GET"); body != "<p>hi</p>" {
		t.Fatalf("get after head %q", body)
	}
}

// memConn é uma net.Conn em memória: lê de in, descarta o que é escrito.
type memConn struct {
	in *strings.Reader
}

func (m *memConn) Read(p []byte) (int, error)  { return m.in.Read(p) }
func (m *memConn) Write(p []byte) (int, error) { return len(p), nil }
func (m *memConn) Close() error                { return nil }
func (m *memConn) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80} }

func (m *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000} }
func (m *memConn) SetDeadline(time.Time) error      { return nil }
func (m *memConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memConn) SetWriteDeadline(time.Time) error { return nil }

// FuzzHTTP1Session: bytes arbitrários no laço HTTP/1 (rotas, htdocs, eventos) nunca causam pânico e todo
// evento fica abaixo do teto.
func FuzzHTTP1Session(f *testing.F) {
	for _, s := range []string{
		get("/p/"+testProbe+"/?inline=1", testSNI),
		"POST /r HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n3;x\r\nabc\r\n0\r\nT: 1\r\n\r\n",
		"GET http://h/p/" + testProbe + "/ HTTP/1.0\nHost: h\n\n",
		"GET /../%2e%2e/x HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
		"CONNECT h:443 HTTP/1.1\r\n\r\n", "OPTIONS * HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\n folded\r\n\r\n", "GET / HTTP/1.1\r\nContent-Length: 1, 2\r\n\r\n",
		"GET /r?status=103&status=404&size=99&frame=chunked&chunk=7&trailers=1&h=X-A:1&hsize=400 HTTP/1.1\r\n\r\n",
		"POST /p/" + testProbe + "/r?continue=late&close=mid-body&rst=1&delay_head=5&ka=1,2 HTTP/1.1\r\n" +
			"Content-Length: 2\r\nExpect: 100-continue\r\n\r\nab",
		"GET /r?status=abc&ver=2&size=-1&h=bad&upgrade=ws&idle=0 HTTP/1.1\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	dir := f.TempDir()
	if err := os.WriteFile(dir+"/index.html", []byte("x"), 0o644); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var maxSize int
		cfg := testConfig(dir)
		// Atrasos curtos para o fuzz não ficar parado em delay_head/delay_body.
		cfg.Limits.DelayMax = time.Millisecond
		srv := NewServer(cfg, Deps{Publish: func(m *nats.Msg) { maxSize = max(maxSize, len(m.Data)) }})
		mc := &memConn{in: strings.NewReader(string(data))}
		c := &conn{srv: srv, raw: mc, flow: flowOf(mc), acceptAt: time.Now()}
		ic := newIdleConn(mc, time.Second, time.Now(), time.Now)
		tp := newTap(ic, srv.cfg.RawStreamMax, time.Now, c.emitStream)
		c.serveHTTP1(tp, ic, time.Now())
		tp.flush()
		if maxSize > event.MaxEventBytes {
			t.Fatalf("event %d bytes", maxSize)
		}
	})
}

// reqInstants são os quatro instantes de uma requisição (spec 009 RF-06, ADR 0029); zero quando nulos.
type reqInstants struct {
	reqStart, reqEnd, respStart, respEnd time.Time
}

// instantsOf lê os quatro instantes do payload (string RFC 3339 com ns ou null).
func instantsOf(t *testing.T, p map[string]any) reqInstants {
	t.Helper()
	parse := func(k string) time.Time {
		v, ok := p[k]
		if !ok {
			t.Fatalf("campo %s ausente: %v", k, p)
		}
		if v == nil {
			return time.Time{}
		}
		at, err := time.Parse(time.RFC3339Nano, v.(string))
		if err != nil || !strings.HasSuffix(v.(string), "Z") {
			t.Fatalf("%s = %v (%v)", k, v, err)
		}
		return at
	}
	return reqInstants{
		parse("request_started_at"), parse("request_ended_at"),
		parse("response_started_at"), parse("response_ended_at"),
	}
}

// checkOrder confere request_started_at ≤ request_ended_at ≤ response_ended_at e
// request_started_at ≤ response_started_at ≤ response_ended_at, todos presentes.
func checkOrder(t *testing.T, what string, in reqInstants) {
	t.Helper()
	if in.reqStart.IsZero() || in.reqEnd.IsZero() || in.respStart.IsZero() || in.respEnd.IsZero() {
		t.Fatalf("%s: instante nulo %+v", what, in)
	}
	if in.reqEnd.Before(in.reqStart) || in.respEnd.Before(in.reqEnd) || in.respStart.Before(in.reqStart) ||
		in.respEnd.Before(in.respStart) {
		t.Fatalf("%s: ordem %+v", what, in)
	}
}

// TestH1Instants: keep-alive, pipeline e 100-continue saem com os quatro instantes em ordem; em pipeline
// a 2ª requisição começa antes de a 1ª resposta terminar.
func TestH1Instants(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	r := get("/p/"+testProbe+"/", "x")
	cl.send(r)
	cl.response("GET")
	time.Sleep(20 * time.Millisecond)
	cl.send(r + r)
	cl.response("GET")
	cl.response("GET")
	cl.send("POST /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = cl.br.ReadString('\n')
	_, _ = cl.br.ReadString('\n')
	time.Sleep(50 * time.Millisecond)
	cl.send("hello")
	cl.response("POST")
	evs := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 4)
	var all []reqInstants
	for i, e := range evs {
		in := instantsOf(t, e.Payload)
		checkOrder(t, "req "+string(rune('0'+i)), in)
		all = append(all, in)
	}
	if !all[1].reqStart.After(all[0].respEnd) {
		t.Fatalf("keep-alive: req 1 começa antes do fim da 0: %+v %+v", all[0], all[1])
	}
	if all[2].reqStart.After(all[1].respEnd) {
		t.Fatalf("pipeline: %+v %+v", all[1], all[2])
	}
	// 100-continue: a resposta começa (o 100) antes do fim do corpo, que veio ≥ 50 ms depois.
	if ec := all[3]; !ec.respStart.Before(ec.reqEnd) || ec.reqEnd.Sub(ec.respStart) < 40*time.Millisecond {
		t.Fatalf("100-continue: %+v", ec)
	}
}

// TestH1InstantsDelay: delay_head=200 aparece como ≥ 200 ms entre request_ended_at e response_started_at, e
// delay_body=100 como ≥ 100 ms dentro da resposta.
func TestH1InstantsDelay(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send(get("/p/"+testProbe+"/r?delay_head=200&delay_body=100&size=10", "x"))
	cl.response("GET")
	in := instantsOf(t, h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload)
	checkOrder(t, "delay", in)
	if d := in.respStart.Sub(in.reqEnd); d < 200*time.Millisecond {
		t.Fatalf("delay_head: %v", d)
	}
	if d := in.respEnd.Sub(in.respStart); d < 100*time.Millisecond {
		t.Fatalf("delay_body: %v", d)
	}
}

// TestH1InstantsIncomplete: requisição cortada no meio do corpo sai com request_ended_at e os da resposta
// nulos.
func TestH1InstantsIncomplete(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	cl := newClient(t, c)
	cl.send("POST /p/" + testProbe + "/ HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nabc")
	time.Sleep(30 * time.Millisecond)
	_ = c.(*net.TCPConn).CloseWrite()
	in := instantsOf(t, h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload)
	if in.reqStart.IsZero() || !in.reqEnd.IsZero() || !in.respStart.IsZero() || !in.respEnd.IsZero() {
		t.Fatalf("incompleta: %+v", in)
	}
}
