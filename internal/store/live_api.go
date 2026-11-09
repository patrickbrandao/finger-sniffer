package store

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
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
	// Handshake inválido sai como 400 com corpo Error (contrato); a biblioteca responderia 426/400 em text/plain.
	// Fica depois do filtro e do limite de clientes, na ordem dos erros do SSE (400 de filtro, 503 cheio).
	if err := checkWSUpgrade(r); err != nil {
		w.Header().Set("Sec-WebSocket-Version", "13")
		writeErr(w, err)
		return
	}
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

// checkWSUpgrade confere o pedido de upgrade WebSocket da RFC 6455 §4.2.1 (Connection, Upgrade, versão e chave).
func checkWSUpgrade(r *http.Request) error {
	if !headerHasToken(r.Header, "Connection", "upgrade") {
		return bad("websocket upgrade required: Connection header must contain Upgrade")
	}
	if !headerHasToken(r.Header, "Upgrade", "websocket") {
		return bad("websocket upgrade required: Upgrade header must be websocket")
	}
	if v := r.Header.Get("Sec-WebSocket-Version"); v != "13" {
		return bad("unsupported Sec-WebSocket-Version %q (want 13)", v)
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		return bad("invalid or missing Sec-WebSocket-Key")
	}
	return nil
}

// headerHasToken informa se algum valor do cabeçalho (lista separada por vírgulas) tem o token, sem caixa.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}
