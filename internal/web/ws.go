package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Teto e métricas do WebSocket.
const (
	// wsMaxFrameEvents é quantos frames de dados e de ping/pong viram evento por conexão: um a mais que o
	// teto do registro no store (1000), para que ele marque frames_truncated (ADR 0018). Frames de close
	// sempre saem.
	wsMaxFrameEvents = 1001
	// wsReadLimit é a maior mensagem ecoada; acima disso o coder/websocket fecha com 1009.
	wsReadLimit = 1 << 20
	// wsDummyKey é a Sec-WebSocket-Key usada para o coder/websocket aceitar o CONNECT estendido do h2, que não
	// tem chave (RFC 8441 §5); a Sec-WebSocket-Accept calculada com ela não vai para o cliente.
	wsDummyKey = "dGhlIHNhbXBsZSBub25jZQ=="

	MetricWSConnsTotal  = "web_websocket_connections_total"
	MetricWSFramesTotal = "web_websocket_frames_total"

	wsOverHTTP1 = "http1.1"
	wsOverH2    = "h2"
)

// wsSession é o registro de um WebSocket: o coder/websocket fala o protocolo e o parser próprio lê a cópia
// dos bytes dos dois sentidos (spec 012 RF-03/RF-04).
type wsSession struct {
	c       *conn
	probeID string
	upgrade event.WebSocketUpgrade

	mu         sync.Mutex
	in, out    wsParser
	events     int
	sentUp     bool
	closeSent  bool
	frameTotal int
}

func newWSSession(c *conn, probeID, over, path string) *wsSession {
	ws := &wsSession{c: c, probeID: probeID, upgrade: event.WebSocketUpgrade{Over: over, Path: path}}
	ws.in.onFrame = func(f wsFrame) { ws.onFrame(event.DirectionIn, f) }
	ws.out.onFrame = func(f wsFrame) { ws.onFrame(event.DirectionOut, f) }
	return ws
}

// feed alimenta o parser do sentido (chamado com os bytes que passam pelo wsConn).
func (ws *wsSession) feed(dir string, p []byte) {
	at := ws.c.srv.now()
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if dir == event.DirectionIn {
		ws.in.Feed(at, p)
	} else {
		ws.out.Feed(at, p)
	}
}

// onFrame publica fs.v1.web.websocket.frame (chamado com ws.mu).
func (ws *wsSession) onFrame(dir string, f wsFrame) {
	ws.frameTotal++
	ws.c.srv.metrics.Add(MetricWSFramesTotal, 1)
	isClose := f.Opcode == wsOpClose
	if !isClose && ws.events >= wsMaxFrameEvents {
		return
	}
	ws.events++
	p := event.WebSocketFrame{
		Dir: dir, Opcode: f.Opcode, Fin: f.Fin, RSV: f.RSV, Masked: f.Masked, Length: f.Length,
	}
	if f.Masked {
		p.MaskKeyHex = ptr(hex.EncodeToString(f.MaskKey[:]))
	}
	if !ws.sentUp {
		ws.sentUp = true
		up := ws.upgrade
		p.Upgrade = &up
	}
	if isClose && !ws.closeSent {
		// Só o primeiro close (de quem fechou) entra no registro: o outro é a resposta.
		ws.closeSent = true
		by := "client"
		if dir == event.DirectionOut {
			by = "server"
		}
		code, reason := f.closeInfo()
		p.Close = &event.WebSocketClose{By: by, Code: code, Reason: reason}
	}
	ws.c.publish(event.SubjectWebWebSocketFrame, f.At, ws.probeID, p)
}

// wsConn é a conexão entregue ao coder/websocket depois do "hijack": lê de r, escreve em w e copia os
// bytes para o parser. Os prazos são da conexão de baixo (HTTP/1) ou do contexto (h2).
type wsConn struct {
	net.Conn // endereços e prazos (no h2, uma conexão sem efeito nos prazos)
	r        io.Reader
	w        func([]byte) (int, error)
	close    func() error
	ws       *wsSession
	once     sync.Once
}

func (c *wsConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.ws.feed(event.DirectionIn, p[:n])
	}
	return n, err
}

func (c *wsConn) Write(p []byte) (int, error) {
	n, err := c.w(p)
	if n > 0 {
		c.ws.feed(event.DirectionOut, p[:n])
	}
	return n, err
}

func (c *wsConn) Close() error {
	var err error
	c.once.Do(func() { err = c.close() })
	return err
}

// wsResponse é o http.ResponseWriter + http.Hijacker entregue ao Accept do coder/websocket: guarda o
// cabeçalho, o status e o corpo de erro, e chama onSwitch no 101 (que escreve a resposta de verdade).
type wsResponse struct {
	hdr      http.Header
	status   int
	body     bytes.Buffer
	onSwitch func(http.Header) error
	switchE  error
	conn     *wsConn
}

func (w *wsResponse) Header() http.Header { return w.hdr }

func (w *wsResponse) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	if code == http.StatusSwitchingProtocols {
		w.switchE = w.onSwitch(w.hdr)
	}
}

func (w *wsResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

func (w *wsResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.switchE != nil {
		return nil, nil, w.switchE
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

// acceptOptions são as opções do Accept: qualquer Origin (o espelho não tem sessão a proteger), o primeiro
// subprotocolo oferecido e permessage-deflate sem context takeover quando o cliente oferece (RF-05).
func acceptOptions(r *http.Request) *websocket.AcceptOptions {
	var subs []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				subs = append(subs, s)
			}
		}
	}
	return &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       subs,
		CompressionMode:    websocket.CompressionNoContextTakeover,
	}
}

// echo ecoa as mensagens até o cliente fechar ou a ociosidade vencer (idle = 0: só os prazos da conexão).
func (ws *wsSession) echo(ctx context.Context, wc *websocket.Conn, idle func() time.Duration) {
	wc.SetReadLimit(wsReadLimit)
	for {
		rctx, cancel := ctx, context.CancelFunc(func() {})
		if d := idle(); d > 0 {
			rctx, cancel = context.WithTimeout(ctx, d)
		}
		typ, data, err := wc.Read(rctx)
		cancel()
		if err != nil {
			if websocket.CloseStatus(err) == -1 && isTimeout(err) {
				// Ociosidade vencida: o servidor fecha com 1001.
				_ = wc.Close(websocket.StatusGoingAway, "idle timeout")
			}
			_ = wc.CloseNow()
			return
		}
		if err := wc.Write(ctx, typ, data); err != nil {
			_ = wc.CloseNow()
			return
		}
	}
}

// wsRoute informa se a requisição é de WebSocket: /p/<id>/ws, ou /r e /p/<id>/r com upgrade=ws válido.
func wsRoute(path, rawQuery string, lim ControlLimits) (bool, *Controls) {
	if rest, ok := strings.CutPrefix(path, "/p/"); ok {
		if id, sub, _ := strings.Cut(rest, "/"); probe.Valid(id) && sub == "ws" {
			return true, nil
		}
	}
	if classify(path) != routeControl {
		return false, nil
	}
	ctl := ParseControls(rawQuery, lim)
	return ctl.Valid() && ctl.Upgrade == "ws", ctl
}

// ------------------------------------------------------------------ HTTP/1.1 (RFC 6455)

// wsRequestOf converte a requisição HTTP/1 na *http.Request que o Accept confere (com os campos de
// conexão, ao contrário do Upgrade do h2c).
func wsRequestOf(req *h1.Request, c *conn) *http.Request {
	rl := req.RequestLine
	hr := &http.Request{
		Method: rl.Method, RequestURI: rl.Target, Header: http.Header{}, Body: http.NoBody,
		RemoteAddr: c.raw.RemoteAddr().String(),
	}
	hr.Proto = rl.Version
	hr.ProtoMajor, hr.ProtoMinor, _ = http.ParseHTTPVersion(rl.Version)
	for _, f := range req.Fields {
		if strings.EqualFold(f.Name(), "Host") {
			if hr.Host == "" {
				hr.Host = strings.TrimSpace(f.Value())
			}
			continue
		}
		hr.Header.Add(f.Name(), strings.TrimSpace(f.Value()))
	}
	return hr
}

// serveWS atende o Upgrade para WebSocket no laço HTTP/1 (spec 012 RF-01): 101 registrado byte a byte no
// http1.request e eco até o fim. Handshake recusado (426/400/405) vira uma resposta normal e o laço segue.
func (s *h1Session) serveWS(req *h1.Request, probeID string, outOffset int64, path string) bool {
	c := s.c
	hr := wsRequestOf(req, c)
	ws := newWSSession(c, probeID, wsOverHTTP1, path)
	wc := &wsConn{
		Conn: s.t, r: s.br, w: s.t.Write, ws: ws,
		close: func() error { return s.t.Close() },
	}
	w := &wsResponse{hdr: http.Header{}, conn: wc}
	w.onSwitch = func(hdr http.Header) error {
		ws.upgrade.Extensions = headerPtr(hdr, "Sec-WebSocket-Extensions")
		ws.upgrade.Subprotocol = headerPtr(hdr, "Sec-WebSocket-Protocol")
		fields := []h1.HeaderField{{Name: "Upgrade", Value: "websocket"}, {Name: "Connection", Value: "Upgrade"}}
		for _, k := range []string{"Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
			if v := hdr.Get(k); v != "" {
				fields = append(fields, h1.HeaderField{Name: k, Value: v})
			}
		}
		err := s.w.WriteHead(&h1.Response{Status: http.StatusSwitchingProtocols, Fields: fields, Framing: h1.FramingNone})
		s.finish(req, probeID, outOffset, http.StatusSwitchingProtocols)
		return err
	}
	conn, err := websocket.Accept(w, hr, acceptOptions(hr))
	if err != nil {
		if w.status == http.StatusSwitchingProtocols {
			return false
		}
		werr := s.write(refusal(w))
		s.finish(req, probeID, outOffset, w.status)
		return werr == nil
	}
	c.srv.metrics.Add(MetricWSConnsTotal, 1)
	// A ociosidade é a do idleConn (prazos da conexão); o laço HTTP/1 termina com o WebSocket.
	ws.echo(c.ctx, conn, func() time.Duration { return 0 })
	return false
}

// refusal converte a resposta de erro do Accept numa resposta HTTP/1.
func refusal(w *wsResponse) response {
	status := w.status
	if status == 0 {
		status = http.StatusBadRequest
	}
	r := textResponse(status, w.body.String())
	keys := make([]string, 0, len(w.hdr))
	for k := range w.hdr {
		switch k {
		case "Content-Type", "X-Content-Type-Options", "Content-Length":
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range w.hdr[k] {
			r.head.Fields = append(r.head.Fields, h1.HeaderField{Name: k, Value: v})
		}
	}
	return r
}

func headerPtr(h http.Header, k string) *string {
	if v := h.Get(k); v != "" {
		return &v
	}
	return nil
}

// ------------------------------------------------------------------ HTTP/2 (RFC 8441)

// h2WSConn é a base de endereços do wsConn no h2: os prazos não se aplicam a um stream (a ociosidade do
// WebSocket sobre h2 é pelo contexto de cada leitura).
type h2WSConn struct{ net.Conn }

func (h2WSConn) SetDeadline(time.Time) error      { return nil }
func (h2WSConn) SetReadDeadline(time.Time) error  { return nil }
func (h2WSConn) SetWriteDeadline(time.Time) error { return nil }

// errWSClosed indica escrita num stream WebSocket já fechado.
var errWSClosed = errors.New("websocket: stream closed")

// websocket atende o CONNECT estendido com :protocol websocket (RFC 8441): 200 no lugar do 101, os frames
// nos DATA do stream e o eco pelo coder/websocket com um ResponseWriter adaptado (sem fork).
func (st *h2Stream) websocket() {
	r, h := st.r, st.h
	path, rawQuery, ok := splitTarget(r.RequestURI)
	if !ok && r.URL != nil {
		path, rawQuery, ok = splitTarget(r.URL.RequestURI())
	}
	isWS, ctl := wsRoute(path, rawQuery, h.c.srv.controlLimits())
	if ctl != nil {
		st.rec.Controls = &ctl.Record
	}
	if !ok || !isWS {
		st.writeResponse(textResponse(http.StatusNotFound, "websocket is served on /p/<id>/ws and /r?upgrade=ws\n"))
		return
	}
	if ctl != nil && ctl.Idle > 0 {
		h.ic.SetIdle(ctl.Idle)
	}
	ws := newWSSession(h.c, st.probeID, wsOverH2, path)
	flusher, _ := st.w.(http.Flusher)
	var mu sync.Mutex
	closed := false
	wc := &wsConn{
		Conn: h2WSConn{Conn: h.c.raw}, r: r.Body, ws: ws,
		w: func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			if closed {
				return 0, errWSClosed
			}
			n, err := st.w.Write(p)
			if err == nil && flusher != nil {
				flusher.Flush()
			}
			return n, err
		},
		close: func() error {
			mu.Lock()
			closed = true
			mu.Unlock()
			return r.Body.Close()
		},
	}
	w := &wsResponse{hdr: http.Header{}, conn: wc}
	w.onSwitch = func(hdr http.Header) error {
		ws.upgrade.Extensions = headerPtr(hdr, "Sec-WebSocket-Extensions")
		ws.upgrade.Subprotocol = headerPtr(hdr, "Sec-WebSocket-Protocol")
		out := st.w.Header()
		for _, k := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"} {
			if v := hdr.Get(k); v != "" {
				out.Set(k, v)
			}
		}
		st.status = http.StatusOK
		st.w.WriteHeader(http.StatusOK)
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	// O Accept confere a forma do HTTP/1.1; no h2 os campos de conexão e a chave não existem.
	hr := r.Clone(r.Context())
	hr.Method = http.MethodGet
	hr.Header.Set("Connection", "Upgrade")
	hr.Header.Set("Upgrade", "websocket")
	if hr.Header.Get("Sec-WebSocket-Key") == "" {
		hr.Header.Set("Sec-WebSocket-Key", wsDummyKey)
	}
	conn, err := websocket.Accept(w, hr, acceptOptions(hr))
	if err != nil {
		if w.status != http.StatusSwitchingProtocols {
			st.writeResponse(refusal(w))
		}
		return
	}
	h.c.srv.metrics.Add(MetricWSConnsTotal, 1)
	ws.echo(r.Context(), conn, func() time.Duration { return time.Duration(h.ic.idle.Load()) })
}
