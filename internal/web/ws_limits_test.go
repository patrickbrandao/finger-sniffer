package web

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// wsUpgradeRaw é um Upgrade HTTP/1.1 válido para /p/<id>/ws.
func wsUpgradeRaw() string {
	return "GET /p/" + testProbe + "/ws HTTP/1.1\r\nHost: " + testSNI + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
}

// h2WSConnect abre o CONNECT estendido do WebSocket no stream id e devolve o :status.
func h2WSConnect(t *testing.T, r *h2raw, id uint32) string {
	t.Helper()
	r.hb.Reset()
	for _, f := range [][2]string{
		{":method", "CONNECT"},
		{":protocol", "websocket"},
		{":scheme", "http"},
		{":path", "/p/" + testProbe + "/ws"},
		{":authority", testSNI},
		{"sec-websocket-version", "13"},
	} {
		_ = r.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: r.hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	hf := r.until(func(f http2.Frame) bool {
		m, ok := f.(*http2.MetaHeadersFrame)
		return ok && m.StreamID == id
	}).(*http2.MetaHeadersFrame)
	return hf.PseudoValue("status")
}

// TestWSSessionLimit (task 136): com wsMaxSessions WebSockets abertos, o seguinte recebe 503 em HTTP/1 e em
// h2, registrado como resposta normal; a vaga volta quando um deles fecha. O SETTINGS anuncia
// MAX_CONCURRENT_STREAMS = 100.
func TestWSSessionLimit(t *testing.T) {
	// Orçamento acima do padrão para caberem as 32 sessões de 2 MiB (e os pendentes do tap).
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = wsMaxSessions*wsSessionBudget + 8<<20 }})
	conns := make([]*websocket.Conn, 0, wsMaxSessions)
	for range wsMaxSessions {
		c, _ := wsDial(t, h.addr80, "ws://"+testSNI+"/p/"+testProbe+"/ws", nil, nil)
		conns = append(conns, c)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.wsSessions.Load() == wsMaxSessions },
		func() string { return fmt.Sprint("sessions ", h.srv.wsSessions.Load()) })
	// pathInUse lê dois contadores (total e tap) sem atomicidade entre eles: um pendente do tap reservando ou
	// devolvendo no meio da leitura aparece por um instante como bytes de caminho (task 241). Espera com prazo
	// o valor exato; uma reserva retida de verdade persiste e falha aqui.
	waitFor(t, 2*time.Second, func() bool { return pathInUse(h.srv.budget) == wsMaxSessions*wsSessionBudget },
		func() string { return fmt.Sprint("budget in use ", pathInUse(h.srv.budget)) })

	// HTTP/1: 503 e o laço segue na mesma conexão.
	c1 := dial(t, h.addr80)
	cl := newClient(t, c1)
	cl.send(wsUpgradeRaw())
	if resp, _ := cl.response("GET"); resp.StatusCode != 503 {
		t.Fatalf("h1 status %d", resp.StatusCode)
	}
	p := h.events.wait(t, event.SubjectWebHTTP1Request, srcPort(c1), 1)[0].Payload
	if num(t, p["status"]) != 503 {
		t.Fatalf("h1 event status %v", p["status"])
	}
	cl.send(get("/p/"+testProbe+"/", testSNI))
	if resp, _ := cl.response("GET"); resp.StatusCode != 200 {
		t.Fatalf("after 503: %d", resp.StatusCode)
	}

	// h2: 503 no stream, e o SETTINGS do servidor com MAX_CONCURRENT_STREAMS.
	c2 := dial(t, h.addr80)
	r := newH2Raw(t, c2, true)
	_ = r.fr.WriteSettings()
	sf := r.until(func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && !s.IsAck() }).(*http2.SettingsFrame)
	if v, ok := sf.Value(http2.SettingMaxConcurrentStreams); !ok || v != h2MaxConcurrentStreams {
		t.Fatalf("MAX_CONCURRENT_STREAMS %d %v", v, ok)
	}
	if st := h2WSConnect(t, r, 1); st != "503" {
		t.Fatalf("h2 status %s", st)
	}

	// Fecha um: a vaga volta.
	_ = conns[0].Close(websocket.StatusNormalClosure, "")
	waitFor(t, 2*time.Second, func() bool { return h.srv.wsSessions.Load() == wsMaxSessions-1 },
		func() string { return fmt.Sprint("sessions ", h.srv.wsSessions.Load()) })
	if st := h2WSConnect(t, r, 3); st != "200" {
		t.Fatalf("h2 after release %s", st)
	}
	for _, c := range conns[1:] {
		_ = c.CloseNow()
	}
	_ = c2.Close()
	waitFor(t, 3*time.Second, func() bool { return h.srv.wsSessions.Load() == 0 && h.srv.budget.inUse() == 0 },
		func() string {
			return fmt.Sprint("sessions ", h.srv.wsSessions.Load(), " budget ", h.srv.budget.inUse())
		})
}

// TestWSBudgetLimit (task 136): sem orçamento de entrada para mais 1 MiB, o Upgrade recebe 503.
func TestWSBudgetLimit(t *testing.T) {
	// 64 KiB de folga para o cabeçalho do Upgrade, que também reserva (sem ela, o terceiro seria 431).
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = 2*wsSessionBudget + 64<<10 }})
	for range 2 {
		wsDial(t, h.addr80, "ws://"+testSNI+"/p/"+testProbe+"/ws", nil, nil)
	}
	cl := newClient(t, dial(t, h.addr80))
	cl.send(wsUpgradeRaw())
	if resp, _ := cl.response("GET"); resp.StatusCode != 503 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if h.srv.wsSessions.Load() != 2 || h.srv.metrics.Get(MetricInputBudgetDenied) < 1 {
		t.Fatalf("sessions %d denied %v", h.srv.wsSessions.Load(), h.srv.metrics.Get(MetricInputBudgetDenied))
	}
}

// TestWSWriteTimeoutH2 (task 136): eco para cliente h2 com janela do stream zerada encerra a sessão e o TCP
// depois de wsWriteTimeout, e devolve vaga e orçamento.
func TestWSWriteTimeoutH2(t *testing.T) {
	old := wsWriteTimeout
	wsWriteTimeout = 300 * time.Millisecond
	t.Cleanup(func() { wsWriteTimeout = old })
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	if st := h2WSConnect(t, r, 1); st != "200" {
		t.Fatalf("status %s", st)
	}
	_ = r.fr.WriteData(1, false, wsEncode(true, 0, wsOpText, []byte{1, 2, 3, 4}, []byte("stuck echo")))
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var err error
	for err == nil {
		_, err = r.fr.ReadFrame()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("TCP not closed after %v", time.Since(start))
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("read ended with %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.wsSessions.Load() == 0 && h.srv.budget.inUse() == 0 },
		func() string {
			return fmt.Sprint("sessions ", h.srv.wsSessions.Load(), " budget ", h.srv.budget.inUse())
		})
}
