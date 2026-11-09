package web

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/patrickbrandao/finger-sniffer/pkg/detect"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// connIDWait é a espera máxima pelo conn_id contada a partir do accept (ADR 0017: 250 ms), com folga para
// o agendamento da goroutine.
const connIDWait = service.ConnIDTimeout + 20*time.Millisecond

// connIDFuture guarda o pedido assíncrono do conn_id feito logo após o accept.
type connIDFuture struct {
	done     chan struct{}
	deadline time.Time
	id       string
}

func (f *connIDFuture) get() string {
	if f == nil {
		return service.ConnIDUnknown
	}
	t := time.NewTimer(time.Until(f.deadline))
	defer t.Stop()
	select {
	case <-f.done:
		if f.id != "" {
			return f.id
		}
	case <-t.C:
	}
	return service.ConnIDUnknown
}

// conn é o estado de uma conexão aceita.
type conn struct {
	srv *Server
	// ctx acaba na parada do serviço (interrompe delay_head/delay_body).
	ctx      context.Context
	raw      net.Conn
	flow     *event.Flow
	acceptAt time.Time
	connID   *connIDFuture

	mu      sync.Mutex
	probeID string
	sni     string
	tlsOn   bool
	// abrupt pede o fechamento sem close_notify no TLS (close=before-body|mid-body, rst=1).
	abrupt atomic.Bool
}

// probe devolve o probe da conexão (o primeiro achado).
func (c *conn) probe() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeID
}

// sniName devolve o SNI do ClientHello ("" em texto claro).
func (c *conn) sniName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sni
}

// setProbe guarda o probe da conexão se ela ainda não tem um.
func (c *conn) setProbe(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	if c.probeID == "" {
		c.probeID = id
	}
	c.mu.Unlock()
}

func (c *conn) publish(subject string, ts time.Time, probeID string, payload any) {
	if probeID == "" {
		probeID = c.probe()
	}
	c.srv.publish(subject, ts, c.flow, probeID, payload)
}

func (c *conn) emitStream(sb event.StreamBytes) {
	c.publish(event.SubjectWebStreamBytes, c.srv.now(), "", sb)
}

// handle atende uma conexão do accept ao fechamento.
func (s *Server) handle(ctx context.Context, raw net.Conn, at time.Time) {
	defer func() { _ = raw.Close() }()
	c := &conn{srv: s, ctx: ctx, raw: raw, flow: flowOf(raw), acceptAt: at}
	c.connID = s.requestConnID(ctx, *c.flow, at)

	dc, res, err := detect.Detect(raw, s.cfg.DetectBytes, s.cfg.DetectTimeout)
	if err != nil {
		s.log.Debug("web detect", "err", err)
		return
	}
	last := at
	if len(res.Peeked) > 0 {
		last = s.now()
	}
	ic := newIdleConn(dc, s.cfg.IdleDefault, last, s.now)

	switch res.Protocol {
	case detect.TLS:
		c.serveTLS(ic)
	case detect.HTTP1:
		t := newTap(ic, s.cfg.RawStreamMax, s.now, c.emitStream)
		c.serveHTTP1(t, ic, at)
		t.flush()
	case detect.H2CPriorKnowledge:
		t := newTap(ic, s.cfg.RawStreamMax, s.now, c.emitStream)
		c.serveH2(t, ic, h2passive.ModePriorKnowledge, nil)
		t.flush()
	default:
		c.serveRaw(ic, res)
	}
}

// requestConnID dispara o pedido do conn_id em segundo plano (ADR 0017).
func (s *Server) requestConnID(ctx context.Context, flow event.Flow, at time.Time) *connIDFuture {
	f := &connIDFuture{done: make(chan struct{}), deadline: at.Add(connIDWait)}
	if s.deps.ConnID == nil {
		close(f.done)
		return f
	}
	go func() {
		defer close(f.done)
		rctx, cancel := context.WithDeadline(ctx, f.deadline)
		defer cancel()
		id, err := s.deps.ConnID(rctx, flow, at)
		if err == nil {
			f.id = id
		}
	}()
	return f
}

// serveTLS faz o handshake com o ClientHello capturado (spec 008) e segue, pelo ALPN, para o h2 (spec 010)
// ou para o HTTP/1 em texto claro (spec 005 RF-03).
func (c *conn) serveTLS(ic *idleConn) {
	s := c.srv
	start := s.now()
	if s.deps.TLS == nil {
		c.serveRaw(ic, detect.Result{Protocol: detect.TLS})
		return
	}
	// Os bytes crus dos dois sentidos passam pelos leitores de alertas durante o handshake (ADR 0029).
	ac := newAlertConn(ic)
	tc := tlsparse.NewConn(ac)
	published := false
	publishHello := func() {
		if published {
			return
		}
		published = true
		c.publishClientHello(tc)
	}
	cfg := s.deps.TLS.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		publishHello()
		return nil, nil
	}
	ts := tls.Server(tc, cfg)
	err := ts.Handshake()
	end := s.now()
	seen := ac.stop()
	// Handshake que falhou antes do callback (ClientHello que o crypto/tls recusou): publica o que houver.
	publishHello()
	c.publishHandshake(ts, err, seen, start, end)
	if err != nil {
		// Sessão TLS morta: espera o cliente fechar (ou a ociosidade) sem fechar antes (RF-08).
		drain(ic)
		return
	}
	c.mu.Lock()
	c.tlsOn = true
	c.mu.Unlock()
	t := newTap(ts, s.cfg.RawStreamMax, s.now, c.emitStream)
	if ts.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		c.serveH2(t, ic, h2passive.ModeALPN, nil)
	} else {
		c.serveHTTP1(t, ic, end)
	}
	t.flush()
	if c.abrupt.Load() {
		// Fechamento abrupto pedido pelos controles: só o TCP (FIN ou RST), sem close_notify.
		_ = c.raw.Close()
		return
	}
	// close_notify em vez de só FIN, como um servidor TLS normal.
	_ = ts.Close()
}

// publishClientHello publica fs.v1.web.tls.client_hello com JA3/JA4 (spec 008).
func (c *conn) publishClientHello(tc *tlsparse.Conn) {
	records, rerr := tc.Records()
	ch, perr := tlsparse.Parse(records)
	if ch == nil {
		c.srv.log.Debug("web client hello", "records_err", rerr, "parse_err", perr)
		return
	}
	info := tlsparse.NewInfo(ch, records, c.srv.cfg.EventInlineMax)
	if perr == nil {
		ja3.Fill(info, ch)
		ja4.Fill(info, ch, ja4.TCP)
	}
	var probeID string
	if ch.HasSNI {
		c.mu.Lock()
		c.sni = ch.SNI
		c.mu.Unlock()
		if h, ok := c.srv.probes.Host(ch.SNI); ok {
			probeID = h.ID
			c.setProbe(h.ID)
		}
	}
	c.publish(event.SubjectWebTLSClientHello, c.srv.now(), probeID, info)
}

// publishHandshake publica fs.v1.web.tls.handshake (negociado, tempo, alertas). seen são os alertas em
// texto claro lidos nos bytes dos dois sentidos, na ordem.
func (c *conn) publishHandshake(ts *tls.Conn, herr error, seen []event.TLSAlert, start, end time.Time) {
	p := event.TLSHandshake{Alerts: append([]event.TLSAlert{}, seen...)}
	if herr == nil {
		st := ts.ConnectionState()
		n := &event.TLSNegotiated{
			Version: tls.VersionName(st.Version),
			Cipher:  tls.CipherSuiteName(st.CipherSuite),
			Resumed: st.DidResume,
		}
		if st.CurveID != 0 {
			n.Group = st.CurveID.String()
		}
		if st.NegotiatedProtocol != "" {
			n.ALPN = ptr(st.NegotiatedProtocol)
		}
		p.Negotiated = n
		p.HandshakeMs = ptr(msSince(start, end))
	}
	if herr != nil {
		p.Alerts = mergeAlerts(p.Alerts, herr)
	}
	c.publish(event.SubjectWebTLSHandshake, end, "", p)
}

// mergeAlerts acrescenta aos alertas vistos nos bytes o que o crypto/tls informa no erro (o cifrado, que só
// ele vê), só se não houver um igual: mesma direção e descrição (spec 008 RF-04, ADR 0029).
func mergeAlerts(seen []event.TLSAlert, herr error) []event.TLSAlert {
	a, ok := alertFromError(herr)
	if !ok {
		return seen
	}
	for _, s := range seen {
		if s.Dir == a.Dir && s.Description == a.Description {
			return seen
		}
	}
	return append(seen, a)
}

// alertConn copia os bytes crus lidos (in) e escritos (out) para um leitor de alertas TLS por sentido até
// stop; os alertas em texto claro ficam na ordem em que apareceram nos dois sentidos.
type alertConn struct {
	net.Conn

	// done evita o mutex nas leituras e escritas depois do handshake.
	done    atomic.Bool
	mu      sync.Mutex
	in, out *tlsparse.AlertReader
	alerts  []event.TLSAlert
	stopped bool
}

func newAlertConn(c net.Conn) *alertConn {
	return &alertConn{Conn: c, in: tlsparse.NewAlertReader(), out: tlsparse.NewAlertReader()}
}

func (a *alertConn) Read(p []byte) (int, error) {
	n, err := a.Conn.Read(p)
	if n > 0 && !a.done.Load() {
		a.feed(event.DirectionIn, p[:n])
	}
	return n, err
}

func (a *alertConn) Write(p []byte) (int, error) {
	n, err := a.Conn.Write(p)
	if n > 0 && !a.done.Load() {
		a.feed(event.DirectionOut, p[:n])
	}
	return n, err
}

func (a *alertConn) feed(dir string, p []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return
	}
	r := a.in
	if dir == event.DirectionOut {
		r = a.out
	}
	for _, x := range r.Feed(p) {
		a.alerts = append(a.alerts, event.TLSAlert{Dir: dir, Level: int(x.Level), Description: int(x.Description)})
	}
}

// stop encerra a cópia (fim do handshake) e devolve os alertas vistos.
func (a *alertConn) stop() []event.TLSAlert {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	a.done.Store(true)
	return a.alerts
}

// goAlerts mapeia o texto dos alertas do crypto/tls para o código (RFC 8446 §6 e registro IANA). O
// crypto/tls não exporta o tipo do alerta recebido/enviado num handshake TCP; o texto do erro é estável.
var goAlerts = map[string]int{
	"close notify": 0, "unexpected message": 10, "bad record MAC": 20, "decryption failed": 21,
	"record overflow": 22, "decompression failure": 30, "handshake failure": 40, "bad certificate": 42,
	"unsupported certificate": 43, "revoked certificate": 44, "expired certificate": 45,
	"unknown certificate": 46, "illegal parameter": 47, "unknown certificate authority": 48,
	"access denied": 49, "error decoding message": 50, "error decrypting message": 51,
	"export restriction": 60, "protocol version not supported": 70, "insufficient security level": 71,
	"internal error": 80, "inappropriate fallback": 86, "user canceled": 90, "no renegotiation": 100,
	"missing extension": 109, "unsupported extension": 110, "certificate unobtainable": 111,
	"unrecognized name": 112, "bad certificate status response": 113, "bad certificate hash value": 114,
	"unknown PSK identity": 115, "certificate required": 116, "no application protocol": 120,
	"encrypted client hello required": 121,
}

// alertFromError extrai o alerta de um erro de handshake: "remote error: tls: X" (recebido, in) ou
// "local error: tls: X" (enviado, out).
func alertFromError(err error) (event.TLSAlert, bool) {
	msg := err.Error()
	for _, k := range []struct{ prefix, dir string }{
		{"remote error: tls: ", event.DirectionIn},
		{"local error: tls: ", event.DirectionOut},
	} {
		i := strings.Index(msg, k.prefix)
		if i < 0 {
			continue
		}
		code, ok := goAlerts[msg[i+len(k.prefix):]]
		if !ok {
			return event.TLSAlert{}, false
		}
		level := 2
		if code == 0 || code == 90 {
			level = 1
		}
		return event.TLSAlert{Dir: k.dir, Level: level, Description: code}, true
	}
	return event.TLSAlert{}, false
}

// drain lê e descarta até o cliente fechar ou a ociosidade vencer.
func drain(r io.Reader) {
	buf := make([]byte, 16<<10)
	for {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
}

// isTimeout informa se o erro é prazo vencido (ociosidade).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
