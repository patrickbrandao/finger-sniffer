package raw

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// testTLS devolve a configuração TLS do espelho com o autoassinado em memória (diretório vazio).
func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	store, err := certs.Open(certs.Config{
		Dir:         t.TempDir(),
		NamesDNS01:  certs.SplitNames(certs.DefaultNamesDNS01),
		NamesHTTP01: certs.SplitNames(certs.DefaultNamesHTTP01),
	}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store.TLSConfig()
}

func withTLS(t *testing.T) func(*Config) {
	cfg := testTLS(t)
	return func(c *Config) { c.TLS = cfg }
}

// dialTLS faz o handshake como um cliente Go (equivalente a openssl s_client sem verificação).
func dialTLS(t *testing.T, addr, sni string, extra func(*tls.Config)) *tls.Conn {
	t.Helper()
	raw := dial(t, addr)
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: sni} //nolint:gosec // autoassinado de teste
	if extra != nil {
		extra(cfg)
	}
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return c
}

func decodeTLSInfo(t *testing.T, env *event.Envelope) tlsparse.Info {
	t.Helper()
	if env == nil {
		t.Fatal("no client_hello event")
	}
	var info tlsparse.Info
	if err := json.Unmarshal(env.Payload, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestTLSBannerPort(t *testing.T) {
	// Critério da spec 006: TLS na 993 completa e recebe "* OK".
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", TLS: true, Banner: BannerFor(993)}}, withTLS(t))
	c := dialTLS(t, env.addr[0], "", nil)
	if got := readN(t, c, len(BannerFor(993))); got != "* OK finger-sniffer IMAP ready\r\n" {
		t.Fatalf("banner = %q", got)
	}
	if _, err := c.Write([]byte("a1 LOGOUT\r\n")); err != nil {
		t.Fatal(err)
	}
	// close_notify do cliente: o servidor ainda manda o half-close dentro do túnel.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != HalfCloseMessage {
		t.Fatalf("after close_notify = %q", rest)
	}
	r := env.waitSession(t)
	if !r.info.TLS || r.info.Mode != "banner" || string(r.in) != "a1 LOGOUT\r\n" {
		t.Errorf("info = %+v in=%q", r.info, r.in)
	}
	if string(r.out) != BannerFor(993)+HalfCloseMessage {
		t.Errorf("out = %q", r.out)
	}
	if r.info.HalfClose == nil || !r.info.HalfClose.ServerSentAfterClientFIN {
		t.Errorf("half_close = %+v", r.info.HalfClose)
	}
	info := decodeTLSInfo(t, r.clientHello)
	if !strings.HasPrefix(info.JA4, "t13") || info.JA3MD5 == "" || len(info.ClientHelloB64) == 0 || info.ClientHelloRecords != 1 {
		t.Errorf("client_hello ja4=%q ja3=%q records=%d", info.JA4, info.JA3MD5, info.ClientHelloRecords)
	}
	if r.clientHello.Service != event.ServiceRaw || r.clientHello.Flow == nil {
		t.Errorf("client_hello envelope = %+v", r.clientHello)
	}
	var hs event.TLSHandshake
	if r.handshake == nil {
		t.Fatal("no handshake event")
	}
	if err := json.Unmarshal(r.handshake.Payload, &hs); err != nil {
		t.Fatal(err)
	}
	if hs.Negotiated == nil || hs.Negotiated.Version != "TLS 1.3" || hs.HandshakeMs == nil || *hs.HandshakeMs <= 0 {
		t.Errorf("handshake = %+v", hs)
	}
}

func TestAutoTLSOnEchoPort(t *testing.T) {
	// RF-03: 0x16 0x03 numa porta echo termina TLS e ecoa dentro do túnel; o SNI de probe associa o probe.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, withTLS(t))
	c := dialTLS(t, env.addr[0], "abcdefgh.dns-monitor.tmsoft.com.br", func(cfg *tls.Config) {
		cfg.MaxVersion = tls.VersionTLS12
	})
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, 5); got != "ping\n" {
		t.Fatalf("echo = %q", got)
	}
	_ = c.Close()
	r := env.waitSession(t)
	if !r.info.TLS || r.info.Mode != "echo" || string(r.in) != "ping\n" || !strings.HasPrefix(string(r.out), "ping\n") {
		t.Errorf("info = %+v in=%q out=%q", r.info, r.in, r.out)
	}
	if r.env.ProbeID == nil || *r.env.ProbeID != "abcdefgh" {
		t.Errorf("probe_id = %v", r.env.ProbeID)
	}
	info := decodeTLSInfo(t, r.clientHello)
	if info.JA4 == "" || info.SNI == nil || *info.SNI != "abcdefgh.dns-monitor.tmsoft.com.br" {
		t.Errorf("client_hello ja4=%q sni=%v", info.JA4, info.SNI)
	}
	if r.clientHello.ProbeID == nil || *r.clientHello.ProbeID != "abcdefgh" {
		t.Errorf("client_hello probe_id = %v", r.clientHello.ProbeID)
	}
	var hs event.TLSHandshake
	_ = json.Unmarshal(r.handshake.Payload, &hs)
	if hs.Negotiated == nil || hs.Negotiated.Version != "TLS 1.2" {
		t.Errorf("handshake = %+v", hs)
	}
}

func TestAutoTLSSplitFirstByte(t *testing.T) {
	// O 0x16 chega sozinho: o servidor espera o próximo byte antes de decidir.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, withTLS(t))
	raw := dial(t, env.addr[0])
	sc := &splitConn{TCPConn: raw}
	c := tls.Client(sc, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // teste
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("x"))
	if got := readN(t, c, 1); got != "x" {
		t.Fatalf("echo = %q", got)
	}
	_ = c.Close()
	if r := env.waitSession(t); !r.info.TLS {
		t.Error("tls = false")
	}
}

// splitConn manda o primeiro byte do cliente num write separado.
type splitConn struct {
	*net.TCPConn
	done bool
}

func (s *splitConn) Write(b []byte) (int, error) {
	if !s.done && len(b) > 1 {
		s.done = true
		if _, err := s.TCPConn.Write(b[:1]); err != nil {
			return 0, err
		}
		time.Sleep(50 * time.Millisecond)
		n, err := s.TCPConn.Write(b[1:])
		return n + 1, err
	}
	return s.TCPConn.Write(b)
}

func TestAutoTLSProbeSourceInsideTunnel(t *testing.T) {
	// Dentro do túnel a primeira linha em claro pode ser a PROBE; o banner é reenviado dentro do TLS.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "banner", Banner: BannerFor(21)}}, withTLS(t))
	raw := dial(t, env.addr[0])
	// O banner em claro sai antes de o cliente falar.
	if got := readN(t, raw, len(BannerFor(21))); got != BannerFor(21) {
		t.Fatalf("plain banner = %q", got)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // teste
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c, len(BannerFor(21))); got != BannerFor(21) {
		t.Fatalf("tls banner = %q", got)
	}
	if _, err := c.Write([]byte("PROBE abcdefgh mode=source n=1000\r\n")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(data) != 1000 {
		t.Fatalf("source got %d", len(data))
	}
	r := env.waitSession(t)
	if !r.info.TLS || r.info.Mode != "source" || r.env.ProbeID == nil {
		t.Errorf("info = %+v", r.info)
	}
}

func TestTLSHandshakeFailure(t *testing.T) {
	// Handshake recusado pelo cliente: eventos publicados com o alerta recebido; a sessão fecha quando o
	// cliente fecha.
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", TLS: true}}, withTLS(t))
	raw := dial(t, env.addr[0])
	// Cliente que verifica o certificado recusa o autoassinado e manda o alerta bad_certificate.
	c := tls.Client(raw, &tls.Config{ServerName: "vps602.tmsoft.com.br", MaxVersion: tls.VersionTLS12})
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake accepted a self-signed certificate")
	}
	_ = raw.Close()
	r := env.waitSession(t)
	if !r.info.TLS || len(r.info.ReadsIn) != 0 {
		t.Errorf("info = %+v", r.info)
	}
	info := decodeTLSInfo(t, r.clientHello)
	if info.JA4 == "" {
		t.Error("ja4 empty")
	}
	var hs event.TLSHandshake
	_ = json.Unmarshal(r.handshake.Payload, &hs)
	if hs.Negotiated != nil || len(hs.Alerts) != 1 || hs.Alerts[0].Description != 42 || hs.Alerts[0].Dir != event.DirectionIn {
		t.Errorf("handshake = %+v", hs)
	}
}

func TestNotTLSWith0x16(t *testing.T) {
	// 0x16 seguido de outra coisa não é TLS: segue como dado comum (ecoado).
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo"}}, withTLS(t))
	c := dial(t, env.addr[0])
	_, _ = c.Write([]byte{0x16})
	time.Sleep(30 * time.Millisecond)
	_, _ = c.Write([]byte{0x01, 'a'})
	if got := readN(t, c, 3); got != "\x16\x01a" {
		t.Fatalf("echo = %q", got)
	}
	// Um 0x16 sozinho seguido do FIN também é ecoado antes do half-close.
	c2 := dial(t, env.addr[0])
	_, _ = c2.Write([]byte{0x16})
	_ = c2.CloseWrite()
	got, _ := io.ReadAll(c2)
	if string(got) != "\x16"+HalfCloseMessage {
		t.Fatalf("lone 0x16 = %q", got)
	}
}

func TestAlertFromError(t *testing.T) {
	cases := []struct {
		err   string
		ok    bool
		dir   string
		code  int
		level int
	}{
		{"remote error: tls: bad certificate", true, event.DirectionIn, 42, 2},
		{"local error: tls: user canceled", true, event.DirectionOut, 90, 1},
		{"remote error: tls: something new", false, "", 0, 0},
		{"EOF", false, "", 0, 0},
	}
	for _, c := range cases {
		a, ok := alertFromError(errors.New(c.err))
		if ok != c.ok || a.Dir != c.dir || a.Description != c.code || a.Level != c.level {
			t.Errorf("%q = %+v %v", c.err, a, ok)
		}
	}
}

// clientHelloBytes devolve o registro do ClientHello de um cliente Go (TLS ≤ 1.2), capturado por um pipe.
func clientHelloBytes(t *testing.T) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: "vps602.tmsoft.com.br", MaxVersion: tls.VersionTLS12}) //nolint:gosec // só o ClientHello
		_ = c.Handshake()
		_ = cli.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

func TestTLSAlertFromBytes(t *testing.T) {
	// Cliente TLS cru manda o ClientHello e, depois da resposta do servidor, um alerta em texto claro: o
	// alerta sai dos bytes com a descrição exata; o mesmo alerta no erro do crypto/tls não duplica.
	for _, c := range []struct {
		name string
		desc byte
	}{
		{"unknown_ca", 48},
		{"not_in_go_map", 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", TLS: true}}, withTLS(t))
			conn := dial(t, env.addr[0])
			if _, err := conn.Write(clientHelloBytes(t)); err != nil {
				t.Fatal(err)
			}
			// Espera o primeiro registro do servidor (ServerHello) antes de mandar o alerta.
			if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, c.desc}); err != nil {
				t.Fatal(err)
			}
			_ = conn.CloseWrite()
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
			r := env.waitSession(t)
			if r.handshake == nil {
				t.Fatal("no handshake event")
			}
			var hs event.TLSHandshake
			_ = json.Unmarshal(r.handshake.Payload, &hs)
			if hs.Negotiated != nil || len(hs.Alerts) != 1 {
				t.Fatalf("handshake = %+v", hs)
			}
			if a := hs.Alerts[0]; a.Dir != event.DirectionIn || a.Level != 2 || a.Description != int(c.desc) {
				t.Errorf("alert = %+v", a)
			}
		})
	}
}

func TestMergeAlerts(t *testing.T) {
	seen := []event.TLSAlert{{Dir: event.DirectionIn, Level: 2, Description: 42}}
	// Igual (direção e descrição): não duplica.
	if got := mergeAlerts(seen, errors.New("remote error: tls: bad certificate")); len(got) != 1 {
		t.Errorf("dup = %+v", got)
	}
	// Diferente: entra depois dos dos bytes.
	got := mergeAlerts(seen, errors.New("local error: tls: bad record MAC"))
	if len(got) != 2 || got[1].Dir != event.DirectionOut || got[1].Description != 20 {
		t.Errorf("merge = %+v", got)
	}
	// Erro sem alerta: só os dos bytes.
	if got := mergeAlerts(nil, errors.New("EOF")); len(got) != 0 {
		t.Errorf("eof = %+v", got)
	}
}
