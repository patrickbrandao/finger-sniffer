//go:build e2e

package e2e

// Caso 6 da matriz da spec 017 no caminho direto (task 066): ociosidade. Conexões h1 (porta 80), h2 (TLS na 443)
// e raw (echo na 7) ficam ociosas, depois de uma troca, por 30, 90 e 180 s. Abaixo de FS_IDLE_DEFAULT (120 s) quem
// fecha é o cliente e o registro tem de dizer isso (spec 005 RF-08, spec 006 RF-07); com 180 s o servidor fecha
// aos 120 s; com idle=30 (h1 e h2) o servidor fecha aos 30 s e não antes. O registro mostra quem fechou, como e
// o tempo ocioso antes do fechamento (spec 013 RF-01/RF-02).
//
// As sessões rodam ao mesmo tempo em goroutines dentro de um só teste (ocupam uma vaga do -parallel, não 11) e
// as conferências vêm depois, uma subtarefa por sessão. Duração total: ~2,5 min.

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// serverIdleDefault é o FS_IDLE_DEFAULT da vps602 (web e raw).
const serverIdleDefault = 120 * time.Second

// idleConn6 é uma conexão do caso 6 depois da primeira troca: wait espera o servidor fechar até d (true = o
// servidor fechou, com o instante); closeClient faz o fechamento do lado do cliente (FIN, lê o resto, fecha).
type idleConn6 interface {
	wait(d time.Duration) (bool, error)
	closeClient() error
	close()
}

type idleCase6 struct {
	proto string
	hold  time.Duration // quanto o cliente aceita ficar ocioso
	idle  time.Duration // controle idle= (0 = padrão do servidor)
}

// expectServer diz se, neste caso, é o servidor quem fecha, e depois de quanto tempo.
func (c idleCase6) expectServer() (bool, time.Duration) {
	srv := serverIdleDefault
	if c.idle > 0 {
		srv = c.idle
	}
	return c.hold > srv, srv
}

func (c idleCase6) name() string {
	s := fmt.Sprintf("%s/hold=%s", c.proto, c.hold)
	if c.idle > 0 {
		s += fmt.Sprintf("/idle=%s", c.idle)
	}
	return s
}

type idleResult6 struct {
	id          string
	serverClose bool          // o servidor fechou antes do cliente
	took        time.Duration // da última troca até o fechamento (de quem fechou)
	err         error
}

func TestCase6Idle(t *testing.T) {
	t.Parallel()
	var cases []idleCase6
	for _, proto := range []string{"h1", "h2", "raw"} {
		for _, hold := range []time.Duration{30 * time.Second, 90 * time.Second, 180 * time.Second} {
			cases = append(cases, idleCase6{proto: proto, hold: hold})
		}
	}
	// com idle=30 o servidor fecha aos 30 s (o raw não tem controle de ociosidade)
	cases = append(cases, idleCase6{proto: "h1", hold: 180 * time.Second, idle: 30 * time.Second},
		idleCase6{proto: "h2", hold: 180 * time.Second, idle: 30 * time.Second})

	results := make([]idleResult6, len(cases))
	var wg sync.WaitGroup
	for i, tc := range cases {
		wg.Go(func() { results[i] = runIdle6(tc) })
	}
	wg.Wait()

	for i, tc := range cases {
		res := results[i]
		t.Run(tc.name(), func(t *testing.T) {
			if res.err != nil {
				t.Fatalf("sessão: %v", res.err)
			}
			checkIdle6(t, tc, res)
		})
	}
}

// runIdle6 abre a conexão, faz a troca, espera e fecha do lado de quem tiver de fechar.
func runIdle6(tc idleCase6) idleResult6 {
	res := idleResult6{id: newIDNoT()}
	query := ""
	if tc.idle > 0 {
		query = fmt.Sprintf("r?idle=%d", int(tc.idle/time.Second))
	}
	var c idleConn6
	var err error
	switch tc.proto {
	case "h1":
		c, err = openIdleH1(res.id, query)
	case "h2":
		c, err = openIdleH2(res.id, query)
	case "raw":
		c, err = openIdleRaw(res.id)
	}
	if err != nil {
		res.err = err
		return res
	}
	defer c.close()
	t0 := time.Now()
	// espera um pouco além do prazo do servidor, quando é ele quem tem de fechar
	wait := tc.hold
	if srv, d := tc.expectServer(); srv {
		wait = d + 30*time.Second
	}
	closed, err := c.wait(wait)
	res.took = time.Since(t0)
	switch {
	case err != nil:
		res.err = fmt.Errorf("esperando %s: %w (depois de %s)", wait, err, res.took.Round(time.Millisecond))
	case closed:
		res.serverClose = true
	default:
		if err := c.closeClient(); err != nil {
			res.err = fmt.Errorf("fechando do lado do cliente: %w", err)
		}
	}
	return res
}

func checkIdle6(t *testing.T, tc idleCase6, res idleResult6) {
	t.Helper()
	wantServer, srvIdle := tc.expectServer()
	switch {
	case wantServer && !res.serverClose:
		t.Fatalf("o servidor não fechou a conexão ociosa em %s (esperado aos %s)", res.took.Round(time.Second), srvIdle)
	case !wantServer && res.serverClose:
		t.Fatalf("o servidor fechou a conexão aos %s, antes do cliente (%s; spec 005 RF-08)", res.took.Round(10*time.Millisecond), tc.hold)
	case wantServer && (res.took < srvIdle-time.Second || res.took > srvIdle+5*time.Second):
		t.Errorf("o servidor fechou aos %s, esperado %s", res.took.Round(10*time.Millisecond), srvIdle)
	}
	t.Logf("probe %s: %s fechou após %s ociosa", res.id, map[bool]string{true: "servidor", false: "cliente"}[res.serverClose],
		res.took.Round(10*time.Millisecond))

	port := map[string]int{"h1": 80, "h2": 443, "raw": 7}[tc.proto]
	p := waitProbe(t, res.id, atLeast(1, port))
	cs := p.conns(port)
	if len(cs) != 1 {
		t.Fatalf("%d conexões na porta %d, esperado 1", len(cs), port)
	}
	rc := cs[0]
	keys := []string{"6", "6/" + tc.proto}
	if tc.proto == "h1" {
		keys = append(keys, "6/idle")
	}
	wantBy, wantIdle := "client", tc.hold
	if wantServer {
		wantBy, wantIdle = "server", srvIdle
		keys = append(keys, "6/server")
	} else {
		keys = append(keys, "6/client")
	}
	requireConnFields(t, []record{rc}, keys...)
	if rc.Close.By != wantBy || rc.Close.How != "fin" {
		t.Errorf("close = %+v, esperado %s/fin", rc.Close, wantBy)
	}
	full := connRaw(t, rc.ConnID)
	idleV := full["close"].(map[string]any)["idle_before_close_ms"]
	idleMs, _ := idleV.(float64)
	// quem fechou primeiro tem o FIN antes do outro na linha do tempo
	times, _ := full["times"].(map[string]any)
	cf, sf := tsOf(times["client_fin"]), tsOf(times["server_fin"])
	switch {
	case wantBy == "client" && (cf.IsZero() || !sf.IsZero() && sf.Before(cf)):
		t.Errorf("times: client_fin=%v server_fin=%v, esperado o FIN do cliente primeiro", times["client_fin"], times["server_fin"])
	case wantBy == "server" && (sf.IsZero() || !cf.IsZero() && cf.Before(sf)):
		t.Errorf("times: client_fin=%v server_fin=%v, esperado o FIN do servidor primeiro", times["client_fin"], times["server_fin"])
	}
	t.Logf("%s %s: close=%s/%s idle_before_close_ms=%v client_fin=%v server_fin=%v", rc.ConnID, rc.Proto, rc.Close.By,
		rc.Close.How, idleV, times["client_fin"], times["server_fin"])

	// tempo ocioso entre a última troca com dados e o fechamento (spec 013 RF-02, task 075)
	d := time.Duration(idleMs * float64(time.Millisecond))
	if idleV == nil || d < wantIdle-time.Second || d > wantIdle+5*time.Second {
		t.Errorf("close.idle_before_close_ms = %v, esperado ~%d", idleV, wantIdle.Milliseconds())
	}
}

func tsOf(v any) time.Time {
	s, _ := v.(string)
	ts, _ := time.Parse(time.RFC3339Nano, s)
	return ts
}

// newIDNoT é o newID para goroutines (sem *testing.T; mesmo formato "f3" + 14).
func newIDNoT() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 14)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "f3" + string(b)
}

// ---------------------------------------------------------------- h1 e raw (socket TCP)

type idleTCP struct {
	c *net.TCPConn
}

func dialIdle(port int) (*net.TCPConn, error) {
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", vps4, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func openIdleH1(id, query string) (idleConn6, error) {
	c, err := dialIdle(80)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("GET /p/%s/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: fs-e2e-case6\r\n\r\n", id, query, probeHost(id))
	if _, err := io.WriteString(c, req); err != nil {
		_ = c.Close()
		return nil, err
	}
	// a resposta do espelho tem Content-Length: lê até o fim do corpo
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var buf []byte
	tmp := make([]byte, 64<<10)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if done, bad := h1Complete(buf); bad != nil {
			_ = c.Close()
			return nil, bad
		} else if done {
			break
		}
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("resposta h1: %w (lido %q)", err, buf)
		}
	}
	return &idleTCP{c}, nil
}

// h1Complete diz se buf tem uma resposta 200 completa (cabeçalho e corpo por Content-Length).
func h1Complete(buf []byte) (bool, error) {
	head, body, ok := bytes.Cut(buf, []byte("\r\n\r\n"))
	if !ok {
		return false, nil
	}
	if !bytes.HasPrefix(head, []byte("HTTP/1.1 200 ")) {
		return false, fmt.Errorf("resposta h1 inesperada: %q", head)
	}
	for l := range bytes.SplitSeq(head, []byte("\r\n")) {
		var n int
		if _, err := fmt.Sscanf(string(bytes.ToLower(l)), "content-length: %d", &n); err == nil {
			return len(body) >= n, nil
		}
	}
	return false, fmt.Errorf("resposta h1 sem Content-Length: %q", head)
}

func openIdleRaw(id string) (idleConn6, error) {
	c, err := dialIdle(7)
	if err != nil {
		return nil, err
	}
	const ping = "case 6 ping\r\n"
	if _, err := io.WriteString(c, "PROBE "+id+"\r\n"+ping); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	b := make([]byte, len(ping))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != ping {
		_ = c.Close()
		return nil, fmt.Errorf("eco: %q / %v", b, err)
	}
	return &idleTCP{c}, nil
}

func (c *idleTCP) wait(d time.Duration) (bool, error) {
	_ = c.c.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(c.c)
	var ne net.Error
	switch {
	case len(b) > 0:
		return false, fmt.Errorf("bytes inesperados do servidor: %q", b)
	case err == nil:
		return true, nil // FIN do servidor
	case errors.As(err, &ne) && ne.Timeout():
		return false, nil
	}
	return false, err
}

func (c *idleTCP) closeClient() error {
	if err := c.c.CloseWrite(); err != nil {
		return err
	}
	// o raw manda "half-close test" depois do FIN do cliente; o web só fecha
	_ = c.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadAll(c.c)
	return err
}

func (c *idleTCP) close() { _ = c.c.Close() }

// ---------------------------------------------------------------- h2 (TLS + ALPN h2, frames à mão)

type idleH2 struct {
	tc *tls.Conn
	fr *http2.Framer
}

func openIdleH2(id, query string) (idleConn6, error) {
	host := probeHost(id)
	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp4", vps4+":443",
		&tls.Config{ServerName: host, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (idleConn6, error) {
		_ = tc.Close()
		return nil, err
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != "h2" {
		return fail(fmt.Errorf("ALPN = %q", p))
	}
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		return fail(err)
	}
	fr := http2.NewFramer(tc, tc)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return fail(err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{
		{":method", "GET"},
		{":scheme", "https"},
		{":authority", host},
		{":path", "/p/" + id + "/" + query},
		{"user-agent", "fs-e2e-case6"},
	} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		return fail(err)
	}
	// SETTINGS do servidor (com ACK) e a resposta inteira do stream 1
	for done := false; !done; {
		f, err := fr.ReadFrame()
		if err != nil {
			return fail(fmt.Errorf("lendo resposta h2: %w", err))
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return fail(err)
				}
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID == 1 && f.PseudoValue("status") != "" && f.PseudoValue("status") != "200" {
				return fail(fmt.Errorf(":status %s", f.PseudoValue("status")))
			}
			done = f.StreamID == 1 && f.StreamEnded()
		case *http2.DataFrame:
			done = f.StreamID == 1 && f.StreamEnded()
		case *http2.RSTStreamFrame:
			return fail(fmt.Errorf("RST_STREAM %v", f.ErrCode))
		case *http2.GoAwayFrame:
			return fail(fmt.Errorf("GOAWAY %v", f.ErrCode))
		}
	}
	_ = tc.SetDeadline(time.Time{})
	return &idleH2{tc: tc, fr: fr}, nil
}

func (c *idleH2) wait(d time.Duration) (bool, error) {
	_ = c.tc.SetReadDeadline(time.Now().Add(d))
	for {
		f, err := c.fr.ReadFrame()
		var ne net.Error
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return true, nil // close_notify/FIN do servidor
		case errors.As(err, &ne) && ne.Timeout():
			return false, nil
		case err != nil:
			return false, err
		}
		switch f := f.(type) {
		case *http2.GoAwayFrame, *http2.PingFrame, *http2.WindowUpdateFrame, *http2.SettingsFrame:
			// o servidor pode anunciar o fim com GOAWAY antes de fechar
		default:
			return false, fmt.Errorf("frame inesperado na conexão ociosa: %v", f.Header())
		}
	}
}

func (c *idleH2) closeClient() error {
	// só o FIN do TCP, sem GOAWAY nem close_notify: com eles o servidor fecha ao recebê-los e o FIN dele pode
	// chegar antes do FIN do cliente (visto num ensaio: 3 ms), e o registro diria, com razão, "server"
	tcp, ok := c.tc.NetConn().(*net.TCPConn)
	if !ok {
		return errors.New("conexão TLS sem TCP por baixo")
	}
	if err := tcp.CloseWrite(); err != nil {
		return err
	}
	_ = c.tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.Copy(io.Discard, c.tc)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil // o servidor também fecha sem close_notify
	}
	return err
}

// close fecha só o TCP: o tls.Conn.Close mandaria close_notify, e esses dados chegando depois do close() do
// servidor (quando é ele quem fecha) provocam um RST dele antes do FIN do cliente, e o registro diria, com razão
// (spec 013 RF-02), server/rst
func (c *idleH2) close() { _ = c.tc.NetConn().Close() }
