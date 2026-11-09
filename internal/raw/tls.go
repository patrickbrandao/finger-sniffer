package raw

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// prefixConn entrega primeiro os bytes já lidos pela detecção (0x16 0x03...) e depois os do socket, para o
// crypto/tls enxergar o ClientHello completo.
type prefixConn struct {
	net.Conn
	pending []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// startTLS termina o TLS na conexão (spec 006 RF-02/RF-03), publica fs.v1.web.tls.client_hello e
// fs.v1.web.tls.handshake e passa a sessão para dentro do túnel. prefix são os bytes do cliente já lidos
// (TLS automático) ou nil (porta tls-*). Devolve false se o handshake falhou; nesse caso a conexão já foi
// esgotada até o cliente fechar ou a ociosidade.
func (s *session) startTLS(prefix []byte) bool {
	start := time.Now()
	s.info.TLS = true
	tcp := s.conn
	under := tcp
	if len(prefix) > 0 {
		under = &prefixConn{Conn: tcp, pending: append([]byte(nil), prefix...)}
	}
	// Os bytes crus dos dois sentidos (incluindo o prefixo já lido) passam pelo leitor de alertas até o fim
	// do handshake (spec 006 RF-08, spec 008 RF-04).
	ac := newAlertConn(under)
	tc := tlsparse.NewConn(ac)
	published := false
	publishHello := func() {
		if !published {
			published = true
			s.publishClientHello(tc)
		}
	}
	cfg := s.tlsCfg.Clone()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		publishHello()
		return nil, nil
	}
	ts := tls.Server(tc, cfg)
	_ = tcp.SetDeadline(start.Add(s.cfg.Idle))
	err := ts.HandshakeContext(context.Background())
	end := time.Now()
	_ = tcp.SetDeadline(time.Time{})
	// ClientHello que o crypto/tls recusou antes do callback: publica o que foi capturado.
	publishHello()
	s.publishHandshake(ts, err, ac.stop(), start, end)
	if err != nil {
		// Sessão TLS morta: espera o cliente fechar (ou a ociosidade), sem fechar antes (RF-07).
		drainUntilIdle(tcp, s.cfg.Idle)
		return false
	}
	s.conn = ts
	s.tlsOn = true
	// Dentro do túnel tudo recomeça: a linha PROBE é a primeira linha em claro, o banner vem depois do
	// handshake e a espera do source conta a partir dele.
	s.lineDone, s.lineBuf = false, nil
	s.bannerSent = false
	s.waitFrom = end
	return true
}

// publishClientHello publica o ClientHello cru e analisado com JA3/JA4 (spec 008); o SNI de uma zona dos
// probes associa o probe.
func (s *session) publishClientHello(tc *tlsparse.Conn) {
	records, _ := tc.Records()
	ch, perr := tlsparse.Parse(records)
	if ch == nil {
		return
	}
	info := tlsparse.NewInfo(ch, records, s.cfg.EventInlineMax)
	if perr == nil {
		ja3.Fill(info, ch)
		ja4.Fill(info, ch, ja4.TCP)
	}
	if ch.HasSNI && s.probes != nil && s.probeID == "" {
		if h, ok := s.probes.Host(ch.SNI); ok && h.ID != "" {
			s.probeID = h.ID
		}
	}
	s.em.publish(event.SubjectWebTLSClientHello, time.Now(), s.probeID, info)
}

// publishHandshake publica o resultado do handshake: negociado, tempo e alertas.
// seen são os alertas lidos nos bytes crus, na ordem; o do erro do crypto/tls entra depois, sem duplicar.
func (s *session) publishHandshake(ts *tls.Conn, herr error, seen []event.TLSAlert, start, end time.Time) {
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
			alpn := st.NegotiatedProtocol
			n.ALPN = &alpn
		}
		p.Negotiated = n
		ms := float64(end.Sub(start).Nanoseconds()) / 1e6
		p.HandshakeMs = &ms
	} else {
		p.Alerts = mergeAlerts(p.Alerts, herr)
	}
	s.em.publish(event.SubjectWebTLSHandshake, end, s.probeID, p)
}

// mergeAlerts acrescenta aos alertas vistos nos bytes o que o crypto/tls informa no erro (o cifrado, que só
// ele vê), só se não houver um igual: mesma direção e descrição (spec 008 RF-04, ADR 0029).
func mergeAlerts(seen []event.TLSAlert, herr error) []event.TLSAlert {
	a, ok := alertFromError(herr)
	if !ok {
		return seen
	}
	for _, x := range seen {
		if x.Dir == a.Dir && x.Description == a.Description {
			return seen
		}
	}
	return append(seen, a)
}

// alertConn copia os bytes crus lidos (in) e escritos (out) para um leitor de alertas TLS por sentido até
// stop; os alertas em texto claro ficam na ordem em que apareceram nos dois sentidos. Antes de stop só a
// goroutine do handshake usa a conexão; depois dele as leituras e escritas só passam adiante.
type alertConn struct {
	net.Conn

	done    atomic.Bool
	in, out *tlsparse.AlertReader
	alerts  []event.TLSAlert
}

func newAlertConn(c net.Conn) *alertConn {
	return &alertConn{Conn: c, in: tlsparse.NewAlertReader(), out: tlsparse.NewAlertReader()}
}

func (a *alertConn) Read(p []byte) (int, error) {
	n, err := a.Conn.Read(p)
	if n > 0 && !a.done.Load() {
		a.feed(event.DirectionIn, a.in, p[:n])
	}
	return n, err
}

func (a *alertConn) Write(p []byte) (int, error) {
	n, err := a.Conn.Write(p)
	if n > 0 && !a.done.Load() {
		a.feed(event.DirectionOut, a.out, p[:n])
	}
	return n, err
}

func (a *alertConn) feed(dir string, r *tlsparse.AlertReader, p []byte) {
	for _, x := range r.Feed(p) {
		a.alerts = append(a.alerts, event.TLSAlert{Dir: dir, Level: int(x.Level), Description: int(x.Description)})
	}
}

// stop encerra a cópia (fim do handshake) e devolve os alertas vistos.
func (a *alertConn) stop() []event.TLSAlert {
	a.done.Store(true)
	return a.alerts
}

// goAlerts mapeia o texto dos alertas do crypto/tls para o código (RFC 8446 §6); o crypto/tls não exporta o
// alerta de um handshake TCP, mas o texto do erro é estável (mesma técnica do web).
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

// drainUntilIdle lê e descarta até o cliente fechar, um erro ou idle sem atividade.
func drainUntilIdle(c net.Conn, idle time.Duration) {
	buf := make([]byte, 16<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

// isClientEOF informa se o erro de leitura é o fim do cliente: FIN em TCP; close_notify ou FIN sem
// close_notify dentro do TLS.
func isClientEOF(err error, tlsOn bool) bool {
	if err == io.EOF {
		return true
	}
	return tlsOn && err == io.ErrUnexpectedEOF
}
