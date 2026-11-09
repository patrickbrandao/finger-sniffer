package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// h2Stream é o atendimento de um stream.
type h2Stream struct {
	h       *h2Conn
	w       http.ResponseWriter
	r       *http.Request
	rec     h2passive.HTTP2Stream
	index   int
	probeID string
	status  int
}

// ServeHTTP atende um stream h2 com as mesmas rotas do HTTP/1 (spec 005 RF-05) e os controles que fazem
// sentido em h2 (spec 010 RF-06).
func (h *h2Conn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.wg.Add(1)
	st := &h2Stream{h: h, w: w, r: r, index: h.requests}
	h.requests++
	if r.Context().Value(h2UpgradeKey{}) != nil && !h.upClaimed {
		// Stream 1 do Upgrade: o HEADERS foi a requisição HTTP/1 (já registrada em http1.request).
		h.upClaimed = true
		st.rec = h2passive.HTTP2Stream{StreamID: 1, PseudoOrder: []string{}, Fields: []h2passive.HPACKField{}, EndStream: true}
		if h.up != nil {
			st.rec.JA4H = h.up.ja4h
		}
	} else if rec, ok := h.streamRecordLocked(r.Method, r.RequestURI, r.Host); ok {
		st.rec = rec
		st.rec.JA4H = ja4hOfStream(&st.rec)
	} else {
		st.rec = h2passive.HTTP2Stream{PseudoOrder: []string{}, Fields: []h2passive.HPACKField{}}
	}
	h.mu.Unlock()
	h.ic.hold()
	h.c.srv.metrics.Add(MetricH2StreamsTotal, 1)
	defer func() {
		h.ic.release()
		st.finish()
		h.wg.Done()
	}()
	st.serve()
}

// finish publica o stream e, no primeiro, o nível de conexão (já com o Akamai).
func (st *h2Stream) finish() {
	h := st.h
	h.mu.Lock()
	h.refreshLocked(&st.rec)
	first := !h.connEmitted
	h.mu.Unlock()
	st.rec.Status = st.status
	h.publishStream(&st.rec, st.probeID)
	if first {
		h.publishConn()
	}
}

// serve escolhe a rota e responde.
func (st *h2Stream) serve() {
	r := st.r
	st.probeID = st.probeOf()
	if r.Method == http.MethodConnect && strings.EqualFold(r.Header.Get(":protocol"), "websocket") {
		st.websocket()
		return
	}
	if r.Method == http.MethodConnect {
		// O espelho não é proxy.
		st.writeResponse(func() response {
			resp := textResponse(http.StatusMethodNotAllowed, "this server is not a proxy\n")
			resp.head.Fields = append(resp.head.Fields, h1.HeaderField{Name: "Allow", Value: "GET, HEAD"})
			return resp
		}())
		return
	}
	// O corpo é lido inteiro antes da resposta, como no HTTP/1 (o fim do stream e os trailers entram no
	// registro); o x/net manda o 100-continue sozinho.
	_, _ = io.Copy(io.Discard, r.Body)

	path, rawQuery, ok := splitTarget(r.RequestURI)
	kind := routeBadTarget
	if ok {
		kind = classify(path)
	}
	switch kind {
	case routeMirror:
		st.mirror(rawQuery)
	case routeControl:
		st.control(rawQuery)
	case routeACME:
		st.writeResponse(st.acme(strings.TrimPrefix(path, acmePrefix)))
	case routeStatic:
		st.writeResponse(st.h.c.srv.static.serve(r.Method, path))
	default:
		st.writeResponse(textResponse(http.StatusBadRequest, "unsupported request target\n"))
	}
}

// splitTarget separa caminho e query do :path (só origin-form; "*" e vazio ficam de fora).
func splitTarget(t string) (path, rawQuery string, ok bool) {
	if !strings.HasPrefix(t, "/") {
		return "", "", false
	}
	if i := strings.IndexByte(t, '#'); i >= 0 {
		t = t[:i]
	}
	path, rawQuery, _ = strings.Cut(t, "?")
	return path, rawQuery, true
}

// probeOf acha o probe: caminho /p/<id>/, depois :authority, depois SNI; guarda o primeiro na conexão.
func (st *h2Stream) probeOf() string {
	c := st.h.c
	id, _ := probe.FromTarget(st.r.RequestURI)
	if id == "" {
		if h, ok := c.srv.probes.Host(st.r.Host); ok {
			id = h.ID
		}
	}
	c.setProbe(id)
	if id == "" {
		id = c.probe()
	}
	return id
}

// mirrorBody é o corpo padrão do espelho em h2: conn_id, índice da requisição e stream, ou o JSON do
// próprio stream com inline=1.
func (st *h2Stream) mirrorBody(inline bool) (body, contentType string) {
	if inline {
		st.h.mu.Lock()
		rec := st.rec
		st.h.refreshLocked(&rec)
		st.h.mu.Unlock()
		if data, err := json.Marshal(rec); err == nil {
			return string(data) + "\n", "application/json"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conn_id: %s\nrequest: %d\nstream_id: %d\n", st.h.c.connID.get(), st.index, st.rec.StreamID)
	if st.probeID != "" {
		fmt.Fprintf(&b, "probe_id: %s\n", st.probeID)
	}
	return b.String(), "text/plain; charset=utf-8"
}

func (st *h2Stream) mirror(rawQuery string) {
	q := ParseControls(rawQuery, ControlLimits{})
	body, contentType := st.mirrorBody(q.Inline)
	resp := textResponse(http.StatusOK, body)
	resp.head.Fields[0].Value = contentType
	st.writeResponse(resp)
}

// acme responde o desafio HTTP-01 pelo gancho; sem gancho ou token desconhecido, 404.
func (st *h2Stream) acme(token string) response {
	if f := st.h.c.srv.deps.ACME; f != nil && token != "" && !strings.Contains(token, "/") {
		if body, ok := f(token); ok {
			resp := textResponse(http.StatusOK, string(body))
			resp.head.Fields = resp.head.Fields[:1]
			resp.head.Fields[0].Value = "application/octet-stream"
			return resp
		}
	}
	return textResponse(http.StatusNotFound, "404 not found\n")
}

// setFields copia os campos para o cabeçalho h2 na ordem e sem canonizar o nome (o h2 manda em
// minúsculas); campos de conexão não existem em h2 e ficam de fora.
func setFields(hdr http.Header, fields []h1.HeaderField) {
	for _, f := range fields {
		if hopByHop[strings.ToLower(f.Name)] {
			continue
		}
		hdr[f.Name] = append(hdr[f.Name], f.Value)
	}
}

// writeResponse escreve uma resposta simples (rotas sem controles) em h2.
func (st *h2Stream) writeResponse(resp response) {
	if resp.closer != nil {
		defer func() { _ = resp.closer.Close() }()
	}
	hdr := st.w.Header()
	setFields(hdr, resp.head.Fields)
	if resp.head.Framing == h1.FramingContentLength {
		hdr.Set("Content-Length", strconv.FormatInt(resp.head.BodyLen, 10))
	}
	st.status = resp.head.Status
	st.w.WriteHeader(resp.head.Status)
	if resp.body != nil && st.r.Method != http.MethodHead {
		_, _ = io.Copy(st.w, resp.body)
	}
}

// control monta a resposta controlada de /r e /p/<id>/r em h2. Valem status (inclusive 1xx), size,
// chunk= (tamanho de cada DATA), trailers, h=, delay_head, delay_body, idle, inline e close=/rst=:
// close= manda GOAWAY (o x/net faz isso com Connection: close), rst=1 encerra o stream com RST_STREAM e
// close=before-body|mid-body cortam o corpo com RST_STREAM depois do GOAWAY. ver, frame, conn, ka, hsize e
// continue não existem em h2: ficam só no registro (controls.params).
func (st *h2Stream) control(rawQuery string) {
	h := st.h
	ctl := ParseControls(rawQuery, h.c.srv.controlLimits())
	st.rec.Controls = &ctl.Record
	if !ctl.Valid() {
		st.writeResponse(textResponse(http.StatusBadRequest, ctl.InvalidText()))
		return
	}
	if ctl.Upgrade == "ws" {
		// Em h2 o WebSocket é pelo CONNECT estendido (RFC 8441), não por GET.
		st.writeResponse(textResponse(http.StatusBadRequest, "websocket over h2 needs an extended CONNECT (RFC 8441)\n"))
		return
	}
	if ctl.Idle > 0 {
		h.ic.SetIdle(ctl.Idle)
	}
	text, contentType := st.mirrorBody(ctl.Inline)
	var body io.Reader = strings.NewReader(text)
	size := int64(len(text))
	if ctl.HasSize {
		body, size = &patternReader{left: ctl.Size}, ctl.Size
		contentType = "application/octet-stream"
	}
	status := ctl.Status
	if status == 0 {
		status = http.StatusOK
	}
	ctx := st.r.Context()
	hdr := st.w.Header()
	// As 1xx saem antes de qualquer campo (o x/net manda o cabeçalho atual junto com elas).
	for _, code := range ctl.Interim {
		if code == http.StatusContinue || code == http.StatusSwitchingProtocols {
			// 100 é do x/net (Expect) e 101 não existe em h2.
			continue
		}
		st.w.WriteHeader(code)
	}
	if !sleepCtx(ctx, ctl.DelayHead) {
		return
	}
	hdr["Content-Type"] = []string{contentType}
	hdr["Cache-Control"] = []string{"no-store"}
	setFields(hdr, ctl.Fields)
	_, closeAsked := ctl.Record.Params["close"]
	goAway := closeAsked || ctl.Frame == FrameClose
	if goAway {
		hdr.Set("Connection", "close")
	}
	noBody := st.r.Method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified
	if ctl.Trailers && !noBody {
		hdr.Set("Trailer", TrailerName)
	}
	if ctl.Frame != FrameChunked && ctl.Frame != FrameClose && ctl.Chunk == 0 && status != http.StatusNoContent &&
		status != http.StatusNotModified {
		hdr.Set("Content-Length", strconv.FormatInt(size, 10))
	}
	st.status = status
	st.w.WriteHeader(status)
	if noBody {
		st.end(ctl)
		return
	}
	flusher, _ := st.w.(http.Flusher)
	if ctl.Close == CloseBeforeBody {
		st.abort(flusher)
	}
	if !sleepCtx(ctx, ctl.DelayBody) {
		return
	}
	limit := size
	if ctl.Close == CloseMidBody {
		limit = size / 2
	}
	piece := ctl.Chunk
	if piece <= 0 {
		piece = 32 << 10
	}
	buf := make([]byte, min(int64(piece), max(limit, 1)))
	for left := limit; left > 0; {
		n, err := body.Read(buf[:min(int64(len(buf)), left)])
		if n > 0 {
			if _, werr := st.w.Write(buf[:n]); werr != nil {
				return
			}
			left -= int64(n)
			if ctl.Chunk > 0 && flusher != nil {
				// Um DATA por pedaço (até o SETTINGS_MAX_FRAME_SIZE do cliente).
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	if ctl.Close == CloseMidBody {
		st.abort(flusher)
	}
	if ctl.Trailers {
		hdr.Set(TrailerName, "1")
	}
	st.end(ctl)
}

// end termina o stream: normal, ou com RST_STREAM se rst=1.
func (st *h2Stream) end(ctl *Controls) {
	if ctl.RST {
		flusher, _ := st.w.(http.Flusher)
		st.abort(flusher)
	}
}

// abort manda o que estiver no buffer e encerra o stream com RST_STREAM (INTERNAL_ERROR): o x/net faz
// isso quando o handler entra em pânico com http.ErrAbortHandler (que ele não loga).
func (st *h2Stream) abort(flusher http.Flusher) {
	if flusher != nil {
		flusher.Flush()
	}
	panic(http.ErrAbortHandler)
}
