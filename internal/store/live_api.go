package store

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// Intervalos de keepalive do tempo real (spec 004).
var (
	ssePingEvery = 15 * time.Second
	wsPingEvery  = 30 * time.Second
)

// liveJoin valida os filtros e reserva a vaga; responde 400/503 e devolve nil se não deu.
func (a *API) liveJoin(w http.ResponseWriter, r *http.Request, transport string) *liveClient {
	f, err := ParseLiveFilter(r.URL.Query().Get)
	if err != nil {
		writeErr(w, err)
		return nil
	}
	c, err := a.Live.join(f, transport)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return nil
	}
	return c
}

// stream serve GET /api/v1/stream (SSE): event/data por evento, flush a cada um, ": ping" a cada 15 s.
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	c := a.liveJoin(w, r, "sse")
	if c == nil {
		return
	}
	defer a.Live.leave(c)
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if rc.Flush() != nil {
		return
	}
	write := func(kind string, data []byte) error {
		buf := make([]byte, 0, len(kind)+len(data)+16)
		buf = append(buf, "event: "...)
		buf = append(buf, kind...)
		buf = append(buf, "\ndata: "...)
		buf = append(buf, data...)
		buf = append(buf, "\n\n"...)
		if _, err := w.Write(buf); err != nil {
			return err
		}
		return rc.Flush()
	}
	ping := time.NewTicker(ssePingEvery)
	defer ping.Stop()
	ctx := r.Context()
	for {
		if d := c.nextDropped(a.Live.now()); d != nil {
			if write(LiveStreamDrop, d) != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case m := <-c.ch:
			if write(m.kind, m.data) != nil {
				return
			}
			a.Live.sent(m)
		case <-c.notify:
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

// ws serve GET /api/v1/ws: uma mensagem de texto por evento, ping a cada 30 s, mensagens do cliente ignoradas,
// 1001 no desligamento. Qualquer Origin é aceito (API aberta, ADR 0007: a página vem de outra origem).
func (a *API) ws(w http.ResponseWriter, r *http.Request) {
	c := a.liveJoin(w, r, "ws")
	if c == nil {
		return
	}
	defer a.Live.leave(c)
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	// Contextos próprios para ler e escrever: cancelar o contexto de uma operação em curso derruba a conexão no
	// coder/websocket, e no desligamento (contexto da requisição, via BaseContext) queremos fechar com 1001.
	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		for {
			_, rd, err := conn.Reader(readCtx)
			if err != nil {
				return
			}
			if _, err := io.Copy(io.Discard, rd); err != nil {
				return
			}
		}
	}()
	timeout := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), wsPingEvery)
	}
	write := func(data []byte) error {
		wctx, wcancel := timeout()
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, data)
	}
	ping := time.NewTicker(wsPingEvery)
	defer ping.Stop()
	for {
		if d := c.nextDropped(a.Live.now()); d != nil {
			if write(d) != nil {
				return
			}
		}
		select {
		case <-r.Context().Done():
			_ = conn.Close(websocket.StatusGoingAway, "server shutting down")
			return
		case <-gone:
			return
		case m := <-c.ch:
			if write(m.data) != nil {
				return
			}
			a.Live.sent(m)
		case <-c.notify:
		case <-ping.C:
			pctx, pcancel := timeout()
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}
