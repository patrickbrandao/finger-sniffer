package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	// Liga o CONNECT estendido do h2 (RFC 8441) antes do init do net/http.
	_ "github.com/patrickbrandao/finger-sniffer/internal/web/xconnect"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// Métricas do h2 no heartbeat.
const (
	MetricH2ConnsTotal   = "web_http2_connections_total"
	MetricH2StreamsTotal = "web_http2_streams_total"
)

// h2Upgrade é o pedido de Upgrade: h2c aceito pelo laço HTTP/1 (spec 010 RF-05).
type h2Upgrade struct {
	// req é a requisição HTTP/1 que vira o stream 1.
	req *http.Request
	// settings é o payload de HTTP2-Settings já decodificado.
	settings []byte
	// buffered são os bytes que o laço HTTP/1 já tinha lido depois da requisição (o começo do h2).
	buffered []byte
	// ja4h é o JA4H da requisição HTTP/1 (o stream 1 não tem HEADERS próprio).
	ja4h *string
}

// h2Conn é o estado de uma conexão HTTP/2: o servidor x/net/http2 (sem fork, ADR 0009) atende os streams e
// o parser passivo (pkg/h2passive) lê a cópia dos bytes dos dois sentidos (spec 010).
type h2Conn struct {
	c    *conn
	t    *tap
	ic   *idleConn
	mode string
	up   *h2Upgrade
	ctx  context.Context

	mu sync.Mutex
	in *h2passive.Parser
	// out lê os frames enviados pelo servidor (RF-07).
	out *h2passive.Parser
	// claimed são os streams do parser já ligados a um handler.
	claimed map[uint32]bool
	// requests conta os streams atendidos (índice da requisição na conexão).
	requests    int
	upClaimed   bool
	connEmitted bool
	closed      bool
	wg          sync.WaitGroup
	// gen é fechado (e trocado) a cada pedaço de bytes lido por um dos parsers (in ou out).
	gen chan struct{}
}

// h2NetConn é a conexão entregue ao x/net/http2: escreve no tap e lê de r (o tap, ou os bytes já lidos
// pelo HTTP/1 seguidos do tap no Upgrade). Não expõe ConnectionState: o espelho atende h2 mesmo com TLS
// abaixo de 1.2 ou suíte proibida (RFC 9113 §9.2), para registrar esses clientes em vez de recusá-los.
type h2NetConn struct {
	net.Conn
	r io.Reader
}

func (c *h2NetConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveH2 atende a conexão em HTTP/2 até o cliente fechar, a ociosidade vencer ou o servidor mandar
// GOAWAY (close=). t é o fluxo de aplicação com tap; os bytes ainda não lidos começam no prefácio.
func (c *conn) serveH2(t *tap, ic *idleConn, mode string, up *h2Upgrade) {
	s := c.srv
	s.metrics.Add(MetricH2ConnsTotal, 1)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	h := &h2Conn{
		c: c, t: t, ic: ic, mode: mode, up: up, ctx: ctx,
		in:      h2passive.NewParser(h2passive.Options{Dir: h2passive.DirIn, Mode: mode, Limits: s.cfg.H2Limits}),
		out:     h2passive.NewParser(h2passive.Options{Dir: h2passive.DirOut, Limits: s.cfg.H2Limits}),
		claimed: map[uint32]bool{},
	}
	var r io.Reader = t
	if up != nil && len(up.buffered) > 0 {
		// Esses bytes já passaram pelo tap (fluxo in) antes do observador: entram no parser à mão.
		h.observe(event.DirectionIn, s.now(), up.buffered)
		r = io.MultiReader(bytes.NewReader(up.buffered), t)
	}
	t.setObserver(h.observe)
	defer t.setObserver(nil)

	// O prefácio é lido aqui, e não pelo x/net, que fecha a conexão se ele não chegar em 10 s: o espelho
	// espera a ociosidade inteira (spec 005 RF-08).
	pre := make([]byte, len(h2passive.Preface))
	if _, err := io.ReadFull(r, pre); err != nil || string(pre) != h2passive.Preface {
		h.publishConn()
		if err == nil {
			drain(r)
		}
		return
	}
	// ServeConn/ServeConnOpts estão marcados como obsoletos no x/net v0.62 (no Go 1.27 o x/net/http2 embrulha
	// o h2 do net/http), mas são a única API que atende uma net.Conn já aceita, com o prefácio já lido e
	// com o Upgrade: h2c; o http.Server.Serve não faz nenhuma das três coisas (ADR 0009: x/net sem fork).
	// O BaseConfig só leva o ErrorLog: os prazos do HTTP/1 (ReadHeaderTimeout) não valem no h2.
	opts := &http2.ServeConnOpts{ //nolint:staticcheck // ver acima
		Context:          ctx,
		Handler:          h,
		BaseConfig:       &http.Server{ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug)}, //nolint:gosec // ver acima
		SawClientPreface: true,
	}
	if up != nil {
		opts.UpgradeRequest = up.req.WithContext(context.WithValue(ctx, h2UpgradeKey{}, true))
		opts.Settings = up.settings
	}
	// IdleTimeout fica 0: a ociosidade é a do idleConn, que não corre com stream em atendimento e muda com
	// idle= (o IdleTimeout do x/net é fixo por servidor).
	(&http2.Server{}).ServeConn(&h2NetConn{Conn: t, r: r}, opts) //nolint:staticcheck // ver acima

	// Espera os handlers que ainda estejam rodando (o x/net não espera) antes do evento final.
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	cancel()
	h.wg.Wait()
	h.publishConn()
}

// h2UpgradeKey marca no contexto a requisição do Upgrade: h2c (stream 1).
type h2UpgradeKey struct{}

// observe alimenta o parser passivo do sentido com a cópia dos bytes.
func (h *h2Conn) observe(dir string, at time.Time, p []byte) {
	tMs := msSince(h.c.acceptAt, at)
	h.mu.Lock()
	defer h.mu.Unlock()
	if dir == event.DirectionIn {
		h.in.FeedAt(at, tMs, p)
	} else {
		h.out.FeedAt(at, tMs, p)
	}
	// Acorda quem espera o fim de um stream (fillInstants): END_STREAM/RST_STREAM do servidor ou
	// RST_STREAM do cliente.
	if h.gen != nil {
		close(h.gen)
	}
	h.gen = make(chan struct{})
}

// h2cUpgrade decide se a requisição HTTP/1 pede Upgrade: h2c (RFC 7540 §3.2) e o servidor aceita: só em
// texto claro, sem corpo, com um único HTTP2-Settings válido. Fora disso o Upgrade é ignorado e a
// requisição segue em HTTP/1, como a RFC permite.
func (s *h1Session) h2cUpgrade(req *h1.Request) *h2Upgrade {
	if s.c.tlsOn || hasBody(req) || !hasToken(req, "Upgrade", "h2c") {
		return nil
	}
	var values []string
	for _, f := range req.Fields {
		if strings.EqualFold(f.Name(), "HTTP2-Settings") {
			values = append(values, f.Value())
		}
	}
	if len(values) != 1 {
		return nil
	}
	settings, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(values[0]), "="))
	if err != nil || len(settings)%6 != 0 {
		return nil
	}
	hr, ok := httpRequestOf(req, s.c)
	if !ok {
		return nil
	}
	return &h2Upgrade{req: hr, settings: settings, ja4h: req.JA4H}
}

// hasToken informa se algum campo name tem o token na lista separada por vírgulas (sem caixa).
func hasToken(req *h1.Request, name, token string) bool {
	for _, f := range req.Fields {
		if !strings.EqualFold(f.Name(), name) {
			continue
		}
		for part := range strings.SplitSeq(f.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// hopByHop são os campos de conexão, que não existem em HTTP/2 (RFC 9113 §8.2.2).
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true, "transfer-encoding": true,
	"upgrade": true, "te": true, "http2-settings": true,
}

// httpRequestOf converte a requisição HTTP/1 do Upgrade na *http.Request do stream 1.
func httpRequestOf(req *h1.Request, c *conn) (*http.Request, bool) {
	rl := req.RequestLine
	u, err := url.ParseRequestURI(rl.Target)
	if err != nil {
		return nil, false
	}
	hr := &http.Request{
		Method: rl.Method, URL: u, RequestURI: rl.Target,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: http.NoBody, RemoteAddr: c.raw.RemoteAddr().String(),
	}
	for _, f := range req.Fields {
		name := f.Name()
		if hopByHop[strings.ToLower(name)] {
			continue
		}
		if strings.EqualFold(name, "Host") {
			if hr.Host == "" {
				hr.Host = f.Value()
			}
			continue
		}
		hr.Header.Add(name, strings.TrimSpace(f.Value()))
	}
	if hr.Host == "" {
		hr.Host = u.Host
	}
	return hr, true
}
