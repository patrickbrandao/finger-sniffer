package web

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// readBufSize é o buffer de leitura do HTTP/1.
const readBufSize = 64 << 10

// h1Session é o estado do laço HTTP/1 de uma conexão.
type h1Session struct {
	c  *conn
	t  *tap
	ic *idleConn
	br *bufio.Reader
	rd *h1.Reader
	w  *h1.ResponseWriter
	// handshakeEnd é o fim do handshake TCP (accept) ou TLS: base de t_first_byte_ms (spec 009 RF-06).
	handshakeEnd time.Time
	prevRespEnd  time.Time
}

// serveHTTP1 atende requisições HTTP/1 em sequência (keep-alive e pipelining) até o cliente fechar ou a
// ociosidade vencer. O servidor nunca fecha antes disso (spec 005 RF-08).
func (c *conn) serveHTTP1(t *tap, ic *idleConn, handshakeEnd time.Time) {
	br := bufio.NewReaderSize(t, readBufSize)
	rd := h1.NewReader(br)
	rd.MaxHeadBytes = c.srv.cfg.MaxHeadBytes
	sess := &h1Session{
		c: c, t: t, ic: ic, br: br, rd: rd,
		w:            h1.NewResponseWriter(t, c.srv.cfg.EventInlineMax),
		handshakeEnd: handshakeEnd,
	}
	for idx := 0; ; idx++ {
		if !sess.serveOne(idx) {
			return
		}
	}
}

// serveOne atende uma requisição; false encerra o laço.
func (s *h1Session) serveOne(idx int) bool {
	srv := s.c.srv
	buffered := s.br.Buffered() > 0
	if !buffered {
		s.t.markRead()
	}
	req, err := s.rd.ReadHead()
	if req == nil {
		// EOF limpo entre requisições, ociosidade vencida ou erro de leitura sem nenhum byte.
		return false
	}
	firstByteAt := s.t.firstRead()
	if buffered || firstByteAt.IsZero() {
		firstByteAt = s.t.lastRead()
	}
	req.Index = idx
	s.fillTimes(req, idx, buffered, firstByteAt)
	srv.metrics.Add(MetricRequestsTotal, 1)

	if err != nil {
		return s.headError(req, err)
	}

	probeID := s.probeOf(req)
	req.ProxySignals = h1.DetectProxySignals(req, h1.ProxyContext{
		Rules: srv.cfg.ProxyRules, Direct: true, SNI: s.c.sniName(),
	})

	// Expect: 100-continue padrão: manda o 100 antes de ler o corpo e mede a espera do cliente (RF-04).
	s.w.Reset()
	outOffset := s.t.outTotal()
	if req.ExpectsContinue() && hasBody(req) {
		ec := &h1.ExpectContinue{Waited: s.br.Buffered() == 0}
		if err := s.w.WriteInterim("HTTP/1.1", h1.Interim{Status: http.StatusContinue}); err != nil {
			s.finish(req, probeID, outOffset, http.StatusContinue)
			return false
		}
		sentAt := srv.now()
		if ec.Waited {
			s.t.markRead()
		}
		req.ExpectContinue = ec
		berr := s.rd.ReadBody(req, h1.BodyOptions{RawMax: s.rawBodyMax()})
		if ec.Waited {
			if at := s.t.firstRead(); !at.IsZero() {
				ec.WaitMs = ptr(msSince(sentAt, at))
			}
		}
		if berr != nil {
			return s.bodyError(req, probeID, outOffset, berr)
		}
	} else if berr := s.rd.ReadBody(req, h1.BodyOptions{RawMax: s.rawBodyMax()}); berr != nil {
		return s.bodyError(req, probeID, outOffset, berr)
	}

	resp := s.route(req, probeID)
	werr := s.write(resp)
	s.finish(req, probeID, outOffset, resp.head.Status)
	return werr == nil
}

// fillTimes preenche pipelined, t_first_byte_ms e t_since_prev_response_ms (spec 009 RF-05/RF-06).
func (s *h1Session) fillTimes(req *h1.Request, idx int, buffered bool, firstByteAt time.Time) {
	if idx == 0 {
		req.TFirstByteMs = ptr(max(msSince(s.handshakeEnd, firstByteAt), 0))
		return
	}
	// Pipelining: a requisição já estava no buffer (ou chegou) antes de a resposta anterior terminar.
	req.Pipelined = buffered || firstByteAt.Before(s.prevRespEnd)
	req.TSincePrevResponseMs = ptr(max(msSince(s.prevRespEnd, firstByteAt), 0))
}

func (s *h1Session) rawBodyMax() int {
	if s.c.srv.cfg.RawBodyMax <= 0 {
		return -1
	}
	return s.c.srv.cfg.RawBodyMax
}

// hasBody informa se a requisição declara corpo (chunked ou Content-Length > 0).
func hasBody(req *h1.Request) bool {
	framing, n, err := req.Framing()
	return err == nil && (framing == h1.FramingChunked || (framing == h1.FramingContentLength && n > 0))
}

// probeOf acha o probe da requisição: caminho /p/<id>/, depois Host, depois SNI; guarda o primeiro na
// conexão.
func (s *h1Session) probeOf(req *h1.Request) string {
	id, _ := probe.FromTarget(req.RequestLine.Target)
	if id == "" {
		if host, ok := req.Get("Host"); ok {
			if h, ok := s.c.srv.probes.Host(host); ok {
				id = h.ID
			}
		}
	}
	if id == "" && req.RequestLine.Form == h1.FormAbsolute {
		if h, ok := s.c.srv.probes.Host(authorityOf(req.RequestLine.Target)); ok {
			id = h.ID
		}
	}
	s.c.setProbe(id)
	if id == "" {
		id = s.c.probe()
	}
	return id
}

// authorityOf devolve o host de um alvo absolute-form ("http://host:porta/...").
func authorityOf(target string) string {
	_, rest, ok := strings.Cut(target, "://")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	host, _, _ = strings.Cut(host, "?")
	return host
}

// headError responde 431 ou 400 a um cabeçalho que não deu para ler inteiro e registra os bytes crus.
// Depois disso não dá para achar o início da próxima requisição: a conexão só descarta o que chegar até o
// cliente fechar ou a ociosidade vencer (RF-08).
func (s *h1Session) headError(req *h1.Request, err error) bool {
	probeID := s.c.probe()
	if id, ok := probe.FromTarget(req.RequestLine.Target); ok {
		probeID = id
		s.c.setProbe(id)
	}
	var status int
	switch {
	case errors.Is(err, h1.ErrHeadTooLarge):
		status = http.StatusRequestHeaderFieldsTooLarge
	case errors.Is(err, h1.ErrMalformedRequestLine), errors.Is(err, h1.ErrMalformedField),
		errors.Is(err, h1.ErrObsFoldFirst):
		status = http.StatusBadRequest
	default:
		// Cliente fechou no meio do cabeçalho ou a ociosidade venceu: registra o que chegou e encerra.
		s.publish(req, probeID)
		return false
	}
	s.w.Reset()
	outOffset := s.t.outTotal()
	werr := s.write(textResponse(status, http.StatusText(status)+"\n"))
	s.finish(req, probeID, outOffset, status)
	if werr == nil {
		drain(s.br)
	}
	return false
}

// bodyError trata um corpo inválido (400) ou interrompido (registra e encerra).
func (s *h1Session) bodyError(req *h1.Request, probeID string, outOffset int64, err error) bool {
	if errors.Is(err, h1.ErrBadContentLength) || errors.Is(err, h1.ErrBadTransferEncoding) ||
		errors.Is(err, h1.ErrBadChunk) || errors.Is(err, h1.ErrMalformedField) ||
		errors.Is(err, h1.ErrObsFoldFirst) || errors.Is(err, h1.ErrHeadTooLarge) {
		werr := s.write(textResponse(http.StatusBadRequest, "invalid request body framing\n"))
		s.finish(req, probeID, outOffset, http.StatusBadRequest)
		if werr == nil {
			drain(s.br)
		}
		return false
	}
	s.finish(req, probeID, outOffset, 0)
	return false
}

// finish registra a resposta enviada e publica o evento da requisição.
// status é o código da resposta final (0 se nada foi enviado).
func (s *h1Session) finish(req *h1.Request, probeID string, outOffset int64, status int) {
	s.prevRespEnd = s.c.srv.now()
	sent := s.w.Sent()
	if sent.Size > 0 {
		req.OutOffset = ptr(outOffset)
		req.ResponseSent = sent.Bytes
		req.ResponseSentTruncated = sent.Truncated
		req.ResponseSentSize = sent.Size
		if status == 0 {
			// Só a 100 saiu antes de o corpo falhar.
			status = http.StatusContinue
		}
		req.Status = status
	}
	s.publish(req, probeID)
}

func (s *h1Session) publish(req *h1.Request, probeID string) {
	if req.ResponseSent == nil {
		req.ResponseSent = []byte{}
	}
	if req.RawHead == nil {
		req.RawHead = []byte{}
	}
	// Os bytes do fluxo saem antes do registro, para que /raw?dir= já tenha o que o registro aponta.
	s.t.flush()
	srv := s.c.srv
	data := srv.fitHTTP1(srv.now(), s.c.flow, probeID, req)
	if data == nil {
		return
	}
	srv.publishRaw(event.SubjectWebHTTP1Request, data)
}

// response é a resposta escolhida pela rota.
type response struct {
	interim []h1.Interim
	head    *h1.Response
	body    io.Reader
	closer  io.Closer
}

// write escreve a resposta (1xx incluídas) e fecha o corpo, se for arquivo.
func (s *h1Session) write(r response) error {
	if r.closer != nil {
		defer func() { _ = r.closer.Close() }()
	}
	body := r.body
	if body == nil {
		body = strings.NewReader("")
	}
	return s.w.WriteResponse(r.interim, r.head, body)
}

// textResponse monta uma resposta text/plain pequena.
func textResponse(status int, body string) response {
	return response{
		head: &h1.Response{
			Status: status,
			Fields: []h1.HeaderField{
				{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
				{Name: "Cache-Control", Value: "no-store"},
			},
			Framing: h1.FramingContentLength,
			BodyLen: int64(len(body)),
		},
		body: strings.NewReader(body),
	}
}
