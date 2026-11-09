package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// Códigos de erro de stream do HTTP/3 (RFC 9114 seção 8.1) usados nas recusas.
const (
	h3ExcessiveLoad     = 0x107
	h3RequestIncomplete = 0x10d
	qpackDecompression  = 0x200
)

// h3DataPiece é o tamanho padrão de cada frame DATA da resposta.
const h3DataPiece = 16 << 10

// h3NotApplicable são os controles do HTTP/1 e do h2 que não existem em h3 (spec 011 RF-04): respondem
// 400 com explicação e ficam no registro.
var h3NotApplicable = []string{"ver", "frame", "conn", "ka", "close", "rst", "idle", "hsize", "continue", "upgrade"}

// h3Stream é o atendimento de um stream de requisição.
type h3Stream struct {
	h       *h3Conn
	str     *quic.Stream
	index   int
	rs      *quicparse.RequestStream
	probeID string
	status  int
	ctl     *Controls
}

// serve lê a requisição inteira (como no h2, o corpo é lido antes da resposta), responde pelas mesmas
// rotas do h1/h2 e publica fs.v1.web.http3.request no fim.
func (st *h3Stream) serve() {
	h := st.h
	s := h.srv
	s.metrics.Add(MetricH3RequestsTotal, 1)
	st.rs = quicparse.NewRequestStream(uint64(st.str.StreamID()), quicparse.DefaultMaxFieldsPerSection) //nolint:gosec // id >= 0
	defer st.publish()
	err := readAll(st.str, st.rs)
	switch {
	case errors.Is(err, quicparse.ErrH3FrameTooLarge):
		st.str.CancelRead(h3ExcessiveLoad)
		st.writeSimple(textResponse(http.StatusRequestHeaderFieldsTooLarge, "request header section too large\n"), false)
		return
	case err != nil && st.rs.Err() != nil:
		// QPACK ou frame ilegível
		st.str.CancelRead(qpackDecompression)
		st.str.CancelWrite(qpackDecompression)
		return
	case err != nil:
		// stream cancelado pelo cliente ou conexão encerrada
		st.str.CancelWrite(h3RequestIncomplete)
		return
	case !st.rs.HeadersSeen:
		st.str.CancelWrite(h3RequestIncomplete)
		return
	}
	st.route()
}

// pseudo devolve o valor do pseudo-cabeçalho no primeiro HEADERS.
func (st *h3Stream) pseudo(name string) string {
	r := &st.rs.Request
	for _, f := range r.Fields[:min(r.HeadFields, len(r.Fields))] {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func (st *h3Stream) route() {
	method, target, authority := st.pseudo(":method"), st.pseudo(":path"), st.pseudo(":authority")
	st.probeID = st.probeOf(target, authority)
	head := method == http.MethodHead
	if method == http.MethodConnect {
		resp := textResponse(http.StatusMethodNotAllowed, "this server is not a proxy\n")
		resp.head.Fields = append(resp.head.Fields, h1.HeaderField{Name: "Allow", Value: "GET, HEAD"})
		st.writeSimple(resp, false)
		return
	}
	if method == "" {
		st.writeSimple(textResponse(http.StatusBadRequest, "missing :method\n"), false)
		return
	}
	path, rawQuery, ok := splitTarget(target)
	kind := routeBadTarget
	if ok {
		kind = classify(path)
	}
	switch kind {
	case routeMirror:
		q := ParseControls(rawQuery, ControlLimits{})
		body, contentType := st.mirrorBody(q.Inline)
		resp := textResponse(http.StatusOK, body)
		resp.head.Fields[0].Value = contentType
		st.writeSimple(resp, head)
	case routeControl:
		st.control(rawQuery, head)
	case routeACME:
		// o HTTP-01 é só pela porta 80 TCP
		st.writeSimple(textResponse(http.StatusNotFound, "404 not found\n"), head)
	case routeStatic:
		st.writeSimple(st.h.srv.static.serve(method, path), head)
	default:
		st.writeSimple(textResponse(http.StatusBadRequest, "unsupported request target\n"), false)
	}
}

// probeOf acha o probe: caminho /p/<id>/, depois :authority, depois o SNI da conexão.
func (st *h3Stream) probeOf(target, authority string) string {
	h := st.h
	id, _ := probe.FromTarget(target)
	if id == "" {
		if p, ok := h.srv.probes.Host(authority); ok {
			id = p.ID
		}
	}
	h.setProbe(id)
	if id == "" {
		id = h.probe()
	}
	return id
}

// mirrorBody é o corpo padrão do espelho: conn_id, índice da requisição e stream, ou o JSON do registro.
func (st *h3Stream) mirrorBody(inline bool) (body, contentType string) {
	if inline {
		if data, err := json.Marshal(&st.rs.Request); err == nil {
			return string(data) + "\n", "application/json"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conn_id: %s\nrequest: %d\nstream_id: %d\n", st.h.connID.get(), st.index, st.str.StreamID())
	if st.probeID != "" {
		fmt.Fprintf(&b, "probe_id: %s\n", st.probeID)
	}
	return b.String(), "text/plain; charset=utf-8"
}

// sleep espera d, a parada do serviço ou o fim da conexão; false se não deu para esperar.
func (st *h3Stream) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	ctx, cancel := context.WithCancel(st.h.ctx)
	defer cancel()
	stop := context.AfterFunc(st.h.qc.Context(), cancel)
	defer stop()
	return sleepCtx(ctx, d)
}

// h3Fields converte os campos do cabeçalho para h3: nomes em minúsculas (RFC 9114 seção 4.2) e sem os
// campos de conexão.
func h3Fields(status int, fields []h1.HeaderField) [][2]string {
	out := [][2]string{{":status", strconv.Itoa(status)}}
	for _, f := range fields {
		name := strings.ToLower(f.Name)
		if hopByHop[name] {
			continue
		}
		out = append(out, [2]string{name, f.Value})
	}
	return out
}

func (st *h3Stream) writeHeaders(fields [][2]string) error {
	b := quicparse.AppendH3Frame(nil, quicparse.H3FrameHeaders, quicparse.AppendFieldSection(nil, fields))
	_, err := st.str.Write(b)
	return err
}

// writeData manda até limit bytes de r em frames DATA de piece bytes.
func (st *h3Stream) writeData(r io.Reader, limit int64, piece int) error {
	if piece <= 0 {
		piece = h3DataPiece
	}
	// os 16 primeiros bytes guardam o cabeçalho do frame, escrito logo antes dos dados
	buf := make([]byte, 16+min(int64(piece), max(limit, 1)))
	data := buf[16:]
	for left := limit; left > 0; {
		n, err := r.Read(data[:min(int64(len(data)), left)])
		if n > 0 {
			frame := quicparse.AppendH3FrameHeader(buf[:0], quicparse.H3FrameData, uint64(n))
			start := 16 - len(frame)
			copy(buf[start:16], frame)
			if _, werr := st.str.Write(buf[start : 16+n]); werr != nil {
				return werr
			}
			left -= int64(n)
		}
		if err != nil {
			break
		}
	}
	return nil
}

// writeSimple escreve uma resposta sem controles (rotas do espelho, htdocs, erros) e fecha o stream.
func (st *h3Stream) writeSimple(resp response, head bool) {
	if resp.closer != nil {
		defer func() { _ = resp.closer.Close() }()
	}
	fields := resp.head.Fields
	if resp.head.Framing == h1.FramingContentLength {
		fields = append(fields, h1.HeaderField{Name: "Content-Length", Value: strconv.FormatInt(resp.head.BodyLen, 10)})
	}
	st.status = resp.head.Status
	if err := st.writeHeaders(h3Fields(resp.head.Status, fields)); err != nil {
		return
	}
	if resp.body != nil && !head && resp.head.BodyLen > 0 {
		if err := st.writeData(resp.body, resp.head.BodyLen, 0); err != nil {
			return
		}
	}
	_ = st.str.Close()
}

// control monta a resposta controlada de /r e /p/<id>/r em h3: status (1xx incluídas), size, chunk=
// (tamanho de cada DATA), trailers, h=, delay_head, delay_body, inline e alt_svc; os controles de
// h3NotApplicable respondem 400 explicado (spec 011 RF-04).
func (st *h3Stream) control(rawQuery string, head bool) {
	ctl := ParseControls(rawQuery, st.h.srv.controlLimits())
	st.ctl = ctl
	for _, k := range h3NotApplicable {
		if v, ok := ctl.Record.Params[k]; ok {
			ctl.invalid(k, v, "not applicable to HTTP/3")
		}
	}
	st.rs.Request.Controls = &ctl.Record
	if !ctl.Valid() {
		st.writeSimple(textResponse(http.StatusBadRequest, ctl.InvalidText()), false)
		return
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
	for _, code := range ctl.Interim {
		if code == http.StatusSwitchingProtocols {
			continue // 101 não existe em h3
		}
		if st.writeHeaders([][2]string{{":status", strconv.Itoa(code)}}) != nil {
			return
		}
	}
	if !st.sleep(ctl.DelayHead) {
		return
	}
	noBody := head || status == http.StatusNoContent || status == http.StatusNotModified
	fields := []h1.HeaderField{{Name: "Content-Type", Value: contentType}, {Name: "Cache-Control", Value: "no-store"}}
	if status != http.StatusNoContent && status != http.StatusNotModified {
		fields = append(fields, h1.HeaderField{Name: "Content-Length", Value: strconv.FormatInt(size, 10)})
	}
	if ctl.Trailers && !noBody {
		fields = append(fields, h1.HeaderField{Name: "Trailer", Value: TrailerName})
	}
	fields = append(fields, ctl.Fields...)
	st.status = status
	if st.writeHeaders(h3Fields(status, fields)) != nil {
		return
	}
	if !noBody {
		if !st.sleep(ctl.DelayBody) {
			return
		}
		if st.writeData(body, size, ctl.Chunk) != nil {
			return
		}
		if ctl.Trailers {
			if st.writeHeaders([][2]string{{strings.ToLower(TrailerName), "1"}}) != nil {
				return
			}
		}
	}
	_ = st.str.Close()
}

// publish publica fs.v1.web.http3.request quando a resposta termina.
func (st *h3Stream) publish() {
	h := st.h
	s := h.srv
	req := st.rs.Request
	req.Status = st.status
	req.JA4H = ja4hOfH3(&req)
	probeID := st.probeID
	if probeID == "" {
		probeID = h.probe()
	}
	data := s.fitH3Request(h.flow, probeID, &req)
	if data != nil {
		s.publishRaw(event.SubjectWebHTTP3Request, data)
	}
}

// ja4hOfH3 calcula o JA4H (FoxIO License, ADR 0010) do primeiro HEADERS.
func ja4hOfH3(r *quicparse.HTTP3Request) *string {
	if r.HeadFields == 0 {
		return nil
	}
	in := ja4plus.JA4HInput{Version: "HTTP/3"}
	for _, f := range r.Fields[:min(r.HeadFields, len(r.Fields))] {
		if f.Name == ":method" {
			in.Method = f.Value
		}
		in.Fields = append(in.Fields, ja4plus.JA4HField{Name: f.Name, Value: f.Value})
	}
	return ptr(ja4plus.JA4H(in).JA4H)
}

// fitH3Request serializa a requisição dentro do teto do evento (ADR 0018): valores longos cortados em
// FS_EVENT_INLINE_MAX (values_truncated) e, se ainda não couber, a lista de campos pela metade
// (fields_truncated).
func (s *Server) fitH3Request(flow *event.Flow, probeID string, r *quicparse.HTTP3Request) []byte {
	ts := s.now()
	data := s.encode(ts, flow, probeID, r)
	inline := max(s.cfg.EventInlineMax, 64)
	for i := 0; i < 64 && data != nil && len(data) > event.MaxEventBytes; i++ {
		for j := range r.Fields {
			if len(r.Fields[j].Value) > inline {
				r.Fields[j].Value = r.Fields[j].Value[:inline]
				r.ValuesTruncated = true
			}
		}
		inline = max(inline/2, 64)
		if i > 0 && len(r.Fields) > 0 {
			r.Fields = halve(r.Fields)
			r.FieldsTruncated = true
		}
		data = s.encode(ts, flow, probeID, r)
	}
	return data
}
