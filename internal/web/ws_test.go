package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// wsDial abre um WebSocket HTTP/1.1 (ws ou wss) contra addr; port recebe a porta local.
func wsDial(t *testing.T, addr, url string, opts *websocket.DialOptions, port *int) (*websocket.Conn, *http.Response) {
	t.Helper()
	var p http.Protocols
	p.SetHTTP1(true)
	tr := &http.Transport{
		Protocols:       &p,
		TLSClientConfig: &tls.Config{ServerName: testSNI, InsecureSkipVerify: true}, //nolint:gosec // autoassinado de teste
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, addr)
			if err == nil && port != nil {
				*port = c.LocalAddr().(*net.TCPAddr).Port
			}
			return c, err
		},
	}
	if opts == nil {
		opts = &websocket.DialOptions{}
	}
	opts.HTTPClient = &http.Client{Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	c.SetReadLimit(wsReadLimit)
	t.Cleanup(func() { _ = c.CloseNow() })
	return c, resp
}

func wsRoundTrip(t *testing.T, c *websocket.Conn, typ websocket.MessageType, msg []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, typ, msg); err != nil {
		t.Fatal(err)
	}
	gt, got, err := c.Read(ctx)
	if err != nil || gt != typ || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v %v %q", err, gt, got[:min(len(got), 40)])
	}
}

// wsFrames espera os frames da porta até ok.
func (c *collector) wsFrames(t *testing.T, port int, ok func([]decoded) bool) []decoded {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := c.find(t, event.SubjectWebWebSocketFrame, port)
		if ok(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("websocket frames for port %d: %d", port, len(evs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasClose(evs []decoded) bool {
	for _, e := range evs {
		if e.Payload["close"] != nil {
			return true
		}
	}
	return false
}

func closeOf(evs []decoded) map[string]any {
	for _, e := range evs {
		if c, ok := e.Payload["close"].(map[string]any); ok {
			return c
		}
	}
	return nil
}

// TestWSEchoHTTP1: ws:// em /p/<id>/ws ecoa; 101 registrado byte a byte; frames com máscara, upgrade no
// primeiro e close do cliente com código e razão.
func TestWSEchoHTTP1(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	c, resp := wsDial(t, h.addr80, "ws://"+testSNI+"/p/"+testProbe+"/ws", nil, &port)
	if resp.StatusCode != 101 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	wsRoundTrip(t, c, websocket.MessageText, []byte("hello"))
	wsRoundTrip(t, c, websocket.MessageBinary, bytes.Repeat([]byte{7}, 70000))
	if err := c.Close(websocket.StatusNormalClosure, "bye"); err != nil {
		t.Fatal(err)
	}
	reqs := h.events.wait(t, event.SubjectWebHTTP1Request, port, 1)
	rq := reqs[0].Payload
	if num(t, rq["status"]) != 101 || rq["upgrade"] != "websocket" {
		t.Fatalf("http1 %v", rq)
	}
	evs := h.events.wsFrames(t, port, func(e []decoded) bool { return len(e) >= 6 })
	first := evs[0].Payload
	up, _ := first["upgrade"].(map[string]any)
	if up == nil || up["over"] != wsOverHTTP1 || up["path"] != "/p/"+testProbe+"/ws" || up["extensions"] != nil {
		t.Fatalf("upgrade %v", first)
	}
	if first["dir"] != "in" || first["masked"] != true || len(first["mask_key_hex"].(string)) != 8 ||
		num(t, first["opcode"]) != 1 || num(t, first["length"]) != 5 || *evs[0].Env.ProbeID != testProbe {
		t.Fatalf("first frame %v", first)
	}
	if evs[1].Payload["dir"] != "out" || evs[1].Payload["masked"] != false {
		t.Fatalf("echo frame %v", evs[1].Payload)
	}
	cl := closeOf(evs)
	if cl == nil || cl["by"] != "client" || num(t, cl["code"]) != 1000 || cl["reason"] != "bye" {
		t.Fatalf("close %v", cl)
	}
}

// TestWSEchoTLSDeflate: wss:// com permessage-deflate negociado (parâmetros no upgrade, RSV1 nos frames
// comprimidos) e subprotocolo.
func TestWSEchoTLSDeflate(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	c, resp := wsDial(t, h.addr443, "wss://"+testSNI+"/r?upgrade=ws", &websocket.DialOptions{
		CompressionMode: websocket.CompressionNoContextTakeover, Subprotocols: []string{"echo.v1", "other"},
	}, &port)
	ext := resp.Header.Get("Sec-WebSocket-Extensions")
	if !strings.Contains(ext, "permessage-deflate") || c.Subprotocol() != "echo.v1" {
		t.Fatalf("ext %q sub %q", ext, c.Subprotocol())
	}
	wsRoundTrip(t, c, websocket.MessageText, bytes.Repeat([]byte("abc"), 1000))
	_ = c.Close(websocket.StatusGoingAway, "")
	evs := h.events.wsFrames(t, port, hasClose)
	up := evs[0].Payload["upgrade"].(map[string]any)
	if !strings.Contains(up["extensions"].(string), "permessage-deflate") || up["subprotocol"] != "echo.v1" {
		t.Fatalf("upgrade %v", up)
	}
	if num(t, evs[0].Payload["rsv"]) != 4 || num(t, evs[0].Payload["length"]) >= 3000 {
		t.Fatalf("compressed frame %v", evs[0].Payload)
	}
}

// TestWSServerCloseIdle: com idle=1 o servidor fecha com 1001 depois de 1 s sem frames (close by server).
func TestWSServerCloseIdle(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	c, _ := wsDial(t, h.addr80, "ws://x/r?upgrade=ws&idle=1", nil, &port)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusGoingAway || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("read %v after %v", err, time.Since(start))
	}
	cl := closeOf(h.events.wsFrames(t, port, hasClose))
	if cl["by"] != "server" || num(t, cl["code"]) != 1001 {
		t.Fatalf("close %v", cl)
	}
}

// TestWSRefused: /p/<id>/ws sem Upgrade recebe 426 e a conexão HTTP/1 segue.
func TestWSRefused(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	cl := newClient(t, dial(t, h.addr80))
	cl.send(get("/p/"+testProbe+"/ws", testSNI))
	resp, _ := cl.response("GET")
	if resp.StatusCode != http.StatusUpgradeRequired || resp.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("resp %d %v", resp.StatusCode, resp.Header)
	}
	cl.send(get("/p/"+testProbe+"/", testSNI))
	if resp, _ := cl.response("GET"); resp.StatusCode != 200 {
		t.Fatalf("second %d", resp.StatusCode)
	}
}

// TestWSOverH2: CONNECT estendido (RFC 8441) em h2c: o servidor anuncia ENABLE_CONNECT_PROTOCOL, responde
// 200 e ecoa os frames nos DATA do stream; frames com upgrade over h2.
func TestWSOverH2(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	sf := r.until(func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && !s.IsAck() }).(*http2.SettingsFrame)
	if v, ok := sf.Value(http2.SettingEnableConnectProtocol); !ok || v != 1 {
		t.Fatalf("SETTINGS_ENABLE_CONNECT_PROTOCOL not announced: %v", sf)
	}
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
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: r.hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	hf := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.MetaHeadersFrame); return ok }).(*http2.MetaHeadersFrame)
	if hf.PseudoValue("status") != "200" {
		t.Fatalf("status %q", hf.PseudoValue("status"))
	}
	key := []byte{0xa, 0xb, 0xc, 0xd}
	_ = r.fr.WriteData(1, false, wsEncode(true, 0, wsOpText, key, []byte("hi h2")))
	want := wsEncode(true, 0, wsOpText, nil, []byte("hi h2"))
	var got []byte
	r.until(func(f http2.Frame) bool {
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 1 {
			got = append(got, d.Data()...)
		}
		return len(got) >= len(want)
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("echo %x want %x", got, want)
	}
	_ = r.fr.WriteData(1, false, wsEncode(true, 0, wsOpClose, key, []byte{0x03, 0xe8}))
	port := srcPort(c)
	evs := h.events.wsFrames(t, port, func(e []decoded) bool { return len(e) >= 4 })
	up := evs[0].Payload["upgrade"].(map[string]any)
	if up["over"] != wsOverH2 || up["path"] != "/p/"+testProbe+"/ws" {
		t.Fatalf("upgrade %v", up)
	}
	cl := closeOf(evs)
	if cl == nil || cl["by"] != "client" || num(t, cl["code"]) != 1000 {
		t.Fatalf("close %v", cl)
	}
	st := h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)[0].Payload
	if num(t, st["status"]) != 200 {
		t.Fatalf("stream %v", st)
	}
}

// TestWSFramesCap: só os primeiros wsMaxFrameEvents frames de dados viram evento; o close sempre sai.
func TestWSFramesCap(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	_, _ = io.WriteString(c, "GET /p/"+testProbe+"/ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+wsDummyKey+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("101: %v %v", resp, err)
	}
	go func() { _, _ = io.Copy(io.Discard, br) }()
	var buf []byte
	key := []byte{1, 1, 1, 1}
	for range 700 {
		buf = append(buf, wsEncode(true, 0, wsOpPing, key, nil)...)
	}
	buf = append(buf, wsEncode(true, 0, wsOpClose, key, []byte{0x03, 0xe8})...)
	if _, err := c.Write(buf); err != nil {
		t.Fatal(err)
	}
	h.events.wsFrames(t, srcPort(c), hasClose)
	time.Sleep(200 * time.Millisecond)
	evs := h.events.find(t, event.SubjectWebWebSocketFrame, srcPort(c))
	closes := 0
	for _, e := range evs {
		if num(t, e.Payload["opcode"]) == wsOpClose {
			closes++
		}
	}
	if len(evs)-closes != wsMaxFrameEvents || closes < 1 {
		t.Fatalf("events %d closes %d", len(evs), closes)
	}
}

// TestWSEventsContractAndGolden confere o evento de frame com o contrato e com testdata/events/.
func TestWSEventsContractAndGolden(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var port int
	c, _ := wsDial(t, h.addr80, "ws://x/p/"+testProbe+"/ws", nil, &port)
	wsRoundTrip(t, c, websocket.MessageText, []byte("x"))
	_ = c.Close(websocket.StatusNormalClosure, "done")
	evs := h.events.wsFrames(t, port, hasClose)
	blocks := contractBlocks(t)
	for _, e := range evs {
		checkContract(t, blocks, e)
	}
	checkGolden(t, event.SubjectWebWebSocketFrame, evs[0])
}
