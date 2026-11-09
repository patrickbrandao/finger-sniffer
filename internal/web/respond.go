package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// Cortes da resposta (close=before-body, close=mid-body).
const (
	cutNone = iota
	cutBeforeBody
	cutMidBody
)

// errStopped indica que o serviço parou durante um atraso (delay_head/delay_body).
var errStopped = errors.New("web: server stopping")

// bodyPattern é o padrão repetido do corpo de size=N: o byte do offset i é bodyPattern[i%64], o que deixa
// ver cortes e deslocamentos no corpo recebido.
const bodyPattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// patternReader gera left bytes de bodyPattern sem alocar o corpo inteiro (size até 64 MiB).
type patternReader struct {
	off, left int64
}

func (p *patternReader) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(b)), p.left))
	for i := 0; i < n; {
		k := copy(b[i:n], bodyPattern[(p.off+int64(i))%int64(len(bodyPattern)):])
		i += k
	}
	p.off += int64(n)
	p.left -= int64(n)
	return n, nil
}

// controlLimits devolve os tetos dos controles da configuração.
func (s *Server) controlLimits() ControlLimits {
	l := s.cfg.Limits
	l.IdleMax = s.cfg.IdleMax
	return l
}

// controlsOf interpreta os controles quando a rota é /r ou /p/<id>/r (nil nas outras). Sai antes do
// corpo, porque continue= decide o que fazer com Expect: 100-continue.
func (s *h1Session) controlsOf(req *h1.Request) *Controls {
	path, rawQuery, ok := target(req.RequestLine)
	if !ok || classify(path) != routeControl {
		return nil
	}
	return ParseControls(rawQuery, s.c.srv.controlLimits())
}

// mirrorBody é o corpo padrão do espelho (RF-06): conn_id e índice, ou o JSON da requisição com inline.
func (s *h1Session) mirrorBody(req *h1.Request, probeID string, inline bool) (body, contentType string) {
	if inline {
		req.LimitInline(s.c.srv.cfg.EventInlineMax)
		if data, err := json.Marshal(req); err == nil {
			return string(data) + "\n", "application/json"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "conn_id: %s\nrequest: %d\n", s.c.connID.get(), req.Index)
	if probeID != "" {
		fmt.Fprintf(&b, "probe_id: %s\n", probeID)
	}
	return b.String(), "text/plain; charset=utf-8"
}

// control monta a resposta controlada de /r e /p/<id>/r (spec 005 RF-07).
func (s *h1Session) control(req *h1.Request, probeID, rawQuery string) response {
	ctl := s.ctl
	if ctl == nil {
		ctl = ParseControls(rawQuery, s.c.srv.controlLimits())
	}
	if !ctl.Valid() {
		return textResponse(http.StatusBadRequest, ctl.InvalidText())
	}
	text, contentType := s.mirrorBody(req, probeID, ctl.Inline)
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
	fields := []h1.HeaderField{
		{Name: "Content-Type", Value: contentType},
		{Name: "Cache-Control", Value: "no-store"},
	}
	switch ctl.Conn {
	case ConnKeep:
		fields = append(fields, h1.HeaderField{Name: "Connection", Value: "keep-alive"})
	case ConnClose:
		fields = append(fields, h1.HeaderField{Name: "Connection", Value: "close"})
	}
	if ctl.KeepAlive != "" {
		fields = append(fields, h1.HeaderField{Name: "Keep-Alive", Value: ctl.KeepAlive})
	}
	head := &h1.Response{
		Version: ctl.Version, Status: status, Framing: h1.FramingContentLength, BodyLen: size,
		ChunkSize: ctl.Chunk, HeadSize: ctl.HSize,
	}
	switch ctl.Frame {
	case FrameChunked:
		head.Framing = h1.FramingChunked
		if ctl.Trailers {
			fields = append(fields, h1.HeaderField{Name: "Trailer", Value: TrailerName})
			head.Trailers = []h1.HeaderField{{Name: TrailerName, Value: "1"}}
		}
	case FrameClose:
		head.Framing = h1.FramingClose
	}
	head.Fields = append(fields, ctl.Fields...)

	r := response{head: head, body: body, delayHead: ctl.DelayHead, delayBody: ctl.DelayBody, noDate: ctl.NoDate}
	if len(ctl.Fields) > 0 {
		r.userAt = len(fields)
	}
	for _, st := range ctl.Interim {
		r.interim = append(r.interim, h1.Interim{Status: st})
	}
	switch {
	case req.RequestLine.Method == http.MethodHead:
		headOnly(head)
	case status == http.StatusNoContent || status == http.StatusNotModified:
		// RFC 9110 §15.3.5/§15.4.5: sem corpo e sem Content-Length.
		head.Framing, head.BodyLen = h1.FramingNone, 0
	}
	if ctl.closes() {
		r.closeConn, r.rst = true, ctl.RST
		switch ctl.Close {
		case CloseBeforeBody:
			r.cut = cutBeforeBody
		case CloseMidBody:
			r.cut = cutMidBody
		}
		// Fechamento no meio da resposta ou com RST: sem close_notify no TLS, como uma queda.
		r.abrupt = r.cut != cutNone || r.rst
	}
	return r
}

// sleep espera d ou a parada do serviço; false se o serviço parou.
func (s *h1Session) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	ctx := s.c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// write escreve a resposta (1xx incluídas) com os atrasos e cortes pedidos e fecha o corpo, se for
// arquivo. As 1xx saem antes de delay_head: com status=103 o cliente vê o Early Hints e depois espera.
func (s *h1Session) write(r response) error {
	if r.closer != nil {
		defer func() { _ = r.closer.Close() }()
	}
	body := r.body
	if body == nil {
		body = strings.NewReader("")
	}
	for _, i := range r.interim {
		if err := s.w.WriteInterim(r.head.Version, i); err != nil {
			return err
		}
	}
	if !s.sleep(r.delayHead) {
		return errStopped
	}
	// Date com a hora em que o cabeçalho sai, depois de delay_head (ADR 0021).
	r.head.Fields = withDate(r.head.Status, r.head.Fields, r.noDate, s.c.srv.now())
	if err := s.w.WriteHead(r.head); err != nil {
		return err
	}
	if r.cut == cutBeforeBody || r.head.Framing == h1.FramingNone {
		return nil
	}
	if !s.sleep(r.delayBody) {
		return errStopped
	}
	if r.cut == cutMidBody {
		// Metade do corpo em bytes no fio (em chunked inclui os tamanhos dos pedaços).
		s.w.CutAfter(r.head.BodyLen / 2)
	}
	err := s.w.WriteBody(r.head, body)
	if errors.Is(err, h1.ErrCut) {
		return nil
	}
	return err
}

// closeAfter prepara o fechamento pedido pelos controles: SO_LINGER 0 para RST e, no TLS, sem
// close_notify quando o fechamento é abrupto. O fechamento em si acontece ao sair do laço HTTP/1.
func (s *h1Session) closeAfter(r response) {
	if r.rst {
		if tc, ok := s.c.raw.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
	}
	if r.abrupt {
		s.c.abrupt.Store(true)
	}
}
