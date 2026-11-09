package web

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Testes de integração dos controles (spec 005 RF-07): cada um confere os bytes exatos que chegaram ao
// cliente pela conexão TCP.

// ctlHarness sobe o servidor com tetos pequenos para os testes de clamped.
func ctlHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, harnessOpts{cfg: func(c *Config) {
		c.Limits = ControlLimits{SizeMax: 4096, DelayMax: 2 * time.Second, HSizeMax: 2048}
	}})
}

// head200 é o cabeçalho padrão de uma resposta controlada com size=n.
func head200(n string, extra ...string) string {
	return "HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
		strings.Join(extra, "") + "Content-Length: " + n + "\r\n\r\n"
}

// dateLine marca, no esperado, o Date automático (ADR 0021): IMF-fixdate tem sempre 29 bytes, então o
// tamanho lido não muda; expect troca o Date real pela marca antes de comparar.
const dateLine = "Date: Www, DD Mmm YYYY HH:MM:SS GMT\r\n"

// dateRE casa um campo Date em IMF-fixdate UTC.
var dateRE = regexp.MustCompile(`Date: (Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT\r\n`)

// maskDate troca os Date em IMF-fixdate pela marca dateLine.
func maskDate(b []byte) string { return dateRE.ReplaceAllString(string(b), dateLine) }

// expect lê exatamente len(want) bytes e compara (com os Date mascarados por dateLine).
func (cl *client) expect(want string) {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	n, err := io.ReadFull(cl.br, got)
	if err != nil || maskDate(got) != want {
		cl.t.Fatalf("got %q (%v)\nwant %q", got[:n], err, want)
	}
}

// expectEOF confere que o servidor fechou com FIN logo depois.
func (cl *client) expectEOF() {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := cl.br.ReadByte(); !errors.Is(err, io.EOF) {
		cl.t.Fatalf("want EOF, got %q %v", b, err)
	}
}

// expectOpen confere que a conexão segue aberta (nada chega em d).
func (cl *client) expectOpen(d time.Duration) {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(d))
	_, err := cl.br.ReadByte()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		cl.t.Fatalf("want open connection, got %v", err)
	}
}

// do manda um GET para path e devolve o cliente.
func ctlDo(t *testing.T, h *harness, path string) *client {
	t.Helper()
	cl := newClient(t, dial(t, h.addr80))
	cl.send(get(path, "x"))
	return cl
}

func TestControlStatus(t *testing.T) {
	h := ctlHarness(t)
	t.Run("final", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?status=503&size=2")
		cl.expect(strings.Replace(head200("2"), "200 OK", "503 Service Unavailable", 1) + "01")
		cl.expectOpen(100 * time.Millisecond)
	})
	t.Run("early-hints", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?status=103&size=1")
		cl.expect("HTTP/1.1 103 Early Hints\r\n\r\n" + head200("1") + "0")
		p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0].Payload
		sent, _ := base64.StdEncoding.DecodeString(p["response_sent_b64"].(string))
		if num(t, p["status"]) != 200 || !bytes.Equal(sent, cl.rec.buf.Bytes()) {
			t.Fatalf("status %v sent %q", p["status"], sent)
		}
		ctl := p["controls"].(map[string]any)
		if ctl["params"].(map[string]any)["status"] != "103" {
			t.Fatalf("controls %v", ctl)
		}
	})
	t.Run("unknown-code", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?status=799&size=0")
		cl.expect(strings.Replace(head200("0"), "200 OK", "799 ", 1))
	})
	t.Run("no-content", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?status=204&size=10")
		cl.expect("HTTP/1.1 204 No Content\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n\r\n")
		cl.expectOpen(100 * time.Millisecond)
	})
}

func TestControlVersion(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?ver=1.0&size=3")
	cl.expect(strings.Replace(head200("3"), "HTTP/1.1", "HTTP/1.0", 1) + "012")
	// O servidor não fecha por conta própria (RF-08) mesmo em 1.0.
	cl.expectOpen(100 * time.Millisecond)
}

func TestControlSize(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?size=70")
	cl.expect(head200("70") + bodyPattern + "012345")
	// Acima de FS_SIZE_MAX (4096 no teste): reduzido e registrado em clamped.
	cl = ctlDo(t, h, "/r?size=999999")
	resp, body := cl.response("GET")
	if resp.ContentLength != 4096 || len(body) != 4096 {
		t.Fatalf("clamped size %d %d", resp.ContentLength, len(body))
	}
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0].Payload
	ctl := p["controls"].(map[string]any)
	if cl := ctl["clamped"].([]any); len(cl) != 1 || cl[0] != "size" {
		t.Fatalf("controls %v", ctl)
	}
	if num(t, p["response_sent_size"]) != cl.rec.buf.Len() {
		t.Fatalf("response_sent_size %v, read %d", p["response_sent_size"], cl.rec.buf.Len())
	}
}

func TestControlFrame(t *testing.T) {
	h := ctlHarness(t)
	t.Run("chunked-trailers", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=10&frame=chunked&chunk=4&trailers=1")
		cl.expect("HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
			"Trailer: X-Fs-Trailer\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"4\r\n0123\r\n4\r\n4567\r\n2\r\n89\r\n0\r\nX-Fs-Trailer: 1\r\n\r\n")
		cl.expectOpen(100 * time.Millisecond)
	})
	t.Run("chunk-implies-chunked", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=3&chunk=2")
		cl.expect("HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n2\r\n01\r\n1\r\n2\r\n0\r\n\r\n")
	})
	t.Run("close", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=5&frame=close")
		cl.expect("HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n\r\n01234")
		cl.expectEOF()
	})
	t.Run("cl", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=1&frame=cl")
		cl.expect(head200("1") + "0")
	})
}

func TestControlConn(t *testing.T) {
	h := ctlHarness(t)
	for q, field := range map[string]string{
		"keep": "Connection: keep-alive\r\n", "close": "Connection: close\r\n", "none": "",
	} {
		t.Run(q, func(t *testing.T) {
			cl := ctlDo(t, h, "/r?size=1&conn="+q)
			cl.expect(head200("1", field) + "0")
			// conn= só escreve o campo: o servidor continua atendendo e não fecha (RF-08).
			cl.send(get("/r?size=0", "x"))
			cl.expect(head200("0"))
			cl.expectOpen(100 * time.Millisecond)
		})
	}
}

func TestControlKeepAlive(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?size=0&conn=keep&ka=5,100")
	cl.expect(head200("0", "Connection: keep-alive\r\n", "Keep-Alive: timeout=5, max=100\r\n"))
	cl = ctlDo(t, h, "/r?size=0&ka=7")
	cl.expect(head200("0", "Keep-Alive: timeout=7\r\n"))
}

func TestControlClose(t *testing.T) {
	h := ctlHarness(t)
	t.Run("after", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=4&close=after")
		cl.expect(head200("4") + "0123")
		cl.expectEOF()
	})
	t.Run("before-body", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=4&close=before-body")
		cl.expect(head200("4"))
		cl.expectEOF()
		p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0].Payload
		if num(t, p["response_sent_size"]) != len(head200("4")) {
			t.Fatalf("response_sent_size %v", p["response_sent_size"])
		}
	})
	t.Run("mid-body", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=10&close=mid-body")
		cl.expect(head200("10") + "01234")
		cl.expectEOF()
	})
	t.Run("mid-body-chunked", func(t *testing.T) {
		cl := ctlDo(t, h, "/r?size=10&chunk=4&close=mid-body")
		cl.expect("HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n4\r\n01")
		cl.expectEOF()
	})
	// No TLS (1.2, para o alerta ficar visível no tipo do registro) o fechamento abrupto não manda
	// close_notify; close=after manda.
	for q, wantAlert := range map[string]bool{"/r?size=10&close=mid-body": false, "/r?size=1&close=after": true} {
		t.Run("tls"+q, func(t *testing.T) {
			raw := dial(t, h.addr443)
			rec := &recorder{r: raw}
			c := tls.Client(&recConn{Conn: raw, rec: rec}, &tls.Config{ //nolint:gosec // autoassinado de teste
				ServerName: testSNI, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12,
			})
			cl := newClient(t, c)
			cl.send(get(q, "x"))
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.ReadAll(cl.br)
			if got := hasTLSAlert(t, rec.buf.Bytes()); got != wantAlert {
				t.Fatalf("close_notify %v, want %v", got, wantAlert)
			}
		})
	}
}

// recConn grava os bytes TCP crus lidos pelo cliente TLS.
type recConn struct {
	net.Conn
	rec *recorder
}

func (c *recConn) Read(p []byte) (int, error) { return c.rec.Read(p) }

// hasTLSAlert percorre os registros TLS do servidor e informa se algum é alerta (tipo 21).
func hasTLSAlert(t *testing.T, b []byte) bool {
	t.Helper()
	for len(b) >= 5 {
		n := int(b[3])<<8 | int(b[4])
		if b[0] == 21 {
			return true
		}
		if len(b) < 5+n {
			break
		}
		b = b[5+n:]
	}
	return false
}

func TestControlRST(t *testing.T) {
	h := ctlHarness(t)
	for _, q := range []string{"/r?size=3&rst=1", "/r?size=3&close=after&rst=1"} {
		cl := ctlDo(t, h, q)
		cl.expect(head200("3") + "012")
		_ = cl.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := cl.br.ReadByte()
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%s: want ECONNRESET, got %v", q, err)
		}
	}
}

func TestControlDelay(t *testing.T) {
	h := ctlHarness(t)
	t.Run("head", func(t *testing.T) {
		start := time.Now()
		cl := ctlDo(t, h, "/r?status=103&size=1&delay_head=300")
		cl.expect("HTTP/1.1 103 Early Hints\r\n\r\n")
		if el := time.Since(start); el > 250*time.Millisecond {
			t.Fatalf("103 after %v", el)
		}
		cl.expect(head200("1") + "0")
		if el := time.Since(start); el < 300*time.Millisecond {
			t.Fatalf("head after %v", el)
		}
	})
	t.Run("body", func(t *testing.T) {
		start := time.Now()
		cl := ctlDo(t, h, "/r?size=1&delay_body=300")
		cl.expect(head200("1"))
		if el := time.Since(start); el > 250*time.Millisecond {
			t.Fatalf("head after %v", el)
		}
		cl.expect("0")
		if el := time.Since(start); el < 300*time.Millisecond {
			t.Fatalf("body after %v", el)
		}
	})
	t.Run("clamped", func(t *testing.T) {
		start := time.Now()
		cl := ctlDo(t, h, "/r?size=0&delay_head=600000")
		cl.expect(head200("0"))
		if el := time.Since(start); el < 2*time.Second || el > 4*time.Second {
			t.Fatalf("clamped delay %v", el)
		}
		ctl := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0].Payload["controls"].(map[string]any)
		if c := ctl["clamped"].([]any); len(c) != 1 || c[0] != "delay_head" {
			t.Fatalf("controls %v", ctl)
		}
	})
}

// TestControlIdle: idle=2 fecha só depois de 2 s de ociosidade (e não depois do padrão).
func TestControlIdle(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?size=0&idle=2")
	cl.expect(head200("0"))
	start := time.Now()
	cl.expectOpen(1500 * time.Millisecond)
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := cl.br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	if el := time.Since(start); el < 2*time.Second-50*time.Millisecond || el > 3*time.Second {
		t.Fatalf("closed after %v", el)
	}
}

func TestControlFields(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?size=0&h=x-LOWER:a&h=X-Dup:1&h=X-Dup:2&h=X-Sp:%20%20two%20&h=Content-Length:0")
	// Campos na ordem e na caixa exatas, depois dos padrões; Content-Length explícito não é repetido.
	cl.expect("HTTP/1.1 200 OK\r\n" + dateLine + "Content-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
		"x-LOWER: a\r\nX-Dup: 1\r\nX-Dup: 2\r\nX-Sp:   two \r\nContent-Length: 0\r\n\r\n")
}

func TestControlHSize(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?size=0&hsize=300")
	base := head200("0")
	pad := "X-Fs-Pad: " + strings.Repeat("a", 300-len(base)-len("X-Fs-Pad: \r\n")) + "\r\n"
	want := strings.TrimSuffix(base, "\r\n") + pad + "\r\n"
	if len(want) != 300 {
		t.Fatalf("want len %d", len(want))
	}
	cl.expect(want)
	// Acima de FS_HSIZE_MAX (2048 no teste).
	cl = ctlDo(t, h, "/r?size=0&hsize=100000")
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := cl.br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	if cl.rec.buf.Len() != 2048 {
		t.Fatalf("head %d bytes", cl.rec.buf.Len())
	}
}

func TestControlContinue(t *testing.T) {
	h := ctlHarness(t)
	post := func(q string) *client {
		cl := newClient(t, dial(t, h.addr80))
		cl.send("POST /r?size=1" + q + " HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n")
		return cl
	}
	t.Run("send", func(t *testing.T) {
		cl := post("&continue=send")
		cl.expect("HTTP/1.1 100 Continue\r\n\r\n")
		cl.send("ab")
		cl.expect(head200("1") + "0")
	})
	t.Run("skip", func(t *testing.T) {
		cl := post("&continue=skip")
		cl.expectOpen(150 * time.Millisecond)
		cl.send("ab")
		cl.expect(head200("1") + "0")
		p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0].Payload
		ec := p["expect_continue"].(map[string]any)
		if ec["waited"] != true || ec["wait_ms"].(float64) < 100 {
			t.Fatalf("expect_continue %v", ec)
		}
	})
	t.Run("late", func(t *testing.T) {
		cl := post("&continue=late&status=103")
		cl.expectOpen(150 * time.Millisecond)
		cl.send("ab")
		cl.expect("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n" + head200("1") + "0")
	})
}

// TestControlUpgradeWS: upgrade=ws sem o handshake do WebSocket recebe 426 com Upgrade/Connection (o eco
// com handshake está em ws_test.go).
func TestControlUpgradeWS(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/r?upgrade=ws")
	resp, body := cl.response("GET")
	if resp.StatusCode != 426 || resp.Header.Get("Upgrade") != "websocket" ||
		resp.Header.Get("Connection") != "Upgrade" || !strings.Contains(body, "Connection header") {
		t.Fatalf("resp %d %v %q", resp.StatusCode, resp.Header, body)
	}
}

func TestControlAltSvc(t *testing.T) {
	h := ctlHarness(t)
	c := dialTLS(t, h.addr443, testSNI)
	cl := newClient(t, c)
	cl.send(get("/r?size=1&alt_svc=0", "x"))
	cl.expect(head200("1") + "0")
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c), 1)[0].Payload
	if p["controls"].(map[string]any)["params"].(map[string]any)["alt_svc"] != "0" {
		t.Fatalf("controls %v", p["controls"])
	}
}

// TestControlInvalid: valor inválido → 400 com a explicação em texto e invalid no evento; a conexão segue.
func TestControlInvalid(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/p/"+testProbe+"/r?status=abc&size=1&frame=gzip")
	body := "invalid response controls:\nstatus=abc: must be a 3-digit code 100..999\n" +
		"frame=gzip: must be one of cl, chunked, close\n"
	cl.expect("HTTP/1.1 400 Bad Request\r\n" + dateLine + "Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(cl.c), 1)[0]
	ctl := p.Payload["controls"].(map[string]any)
	inv := ctl["invalid"].([]any)
	if num(t, p.Payload["status"]) != 400 || len(inv) != 2 || inv[0] != "status" || inv[1] != "frame" ||
		p.Env.ProbeID == nil || *p.Env.ProbeID != testProbe {
		t.Fatalf("event %v", p.Payload)
	}
	cl.send(get("/r?size=0", "x"))
	cl.expect(head200("0"))
}

// TestControlProbeRouteAndHead: /p/<id>/r aceita os controles; HEAD manda só o cabeçalho.
func TestControlProbeRouteAndHead(t *testing.T) {
	h := ctlHarness(t)
	cl := ctlDo(t, h, "/p/"+testProbe+"/r?size=2&h=X-A:1")
	cl.expect(head200("2", "X-A: 1\r\n") + "01")
	cl.send("HEAD /r?size=9 HTTP/1.1\r\nHost: x\r\n\r\n")
	cl.expect(head200("9"))
	cl.send(get("/r", "x"))
	resp, body := cl.response("GET")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "conn_id: "+h.connID+"\nrequest: 2\n") {
		t.Fatalf("default body %d %q", resp.StatusCode, body)
	}
}
