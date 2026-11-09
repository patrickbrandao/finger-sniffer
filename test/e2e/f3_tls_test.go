//go:build e2e

package e2e

// Caso 7 da matriz da spec 017 no caminho direto: HTTPS de curl (LibreSSL do macOS e OpenSSL do Homebrew), Go e
// Chrome headless. Para cada conexão TLS do probe: o ClientHello do registro é byte a byte o início do fluxo do
// cliente no pcap da própria conexão; JA3/JA4/JA4_r batem com o tshark 4.4 e o ja4 da FoxIO sobre esse pcap; o
// Akamai h2 (e o JA4H) batem com o tshark/ja4 decifrando o pcap com o keylog do cliente (SSLKEYLOGFILE). Também
// os critérios de saída da F3: certificado válido (sem -k) em *.dns-monitor e na 9000, TLS na 80 e HTTP em
// claro na 443 (spec 005).

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	curlLibreSSL = "/usr/bin/curl"
	chromeBin    = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)

var curlOpenSSL = env("CURL_OPENSSL", "/opt/homebrew/opt/curl/bin/curl")

// tlsClient é um cliente do caso 7: run faz as requisições para url gravando as chaves TLS em keylog
// (quando o cliente sabe gravar).
type tlsClient struct {
	name  string
	h2    bool
	keys  bool // grava SSLKEYLOGFILE (Akamai e JA4H conferidos)
	needs string
	run   func(ctx context.Context, url, keylog string) error
}

func curlRun(bin string, args ...string) func(ctx context.Context, url, keylog string) error {
	return func(ctx context.Context, url, keylog string) error {
		cmd := exec.CommandContext(ctx, bin, append([]string{"-4", "-sS", "-o", "/dev/null", "--max-time", "20"}, append(args, url)...)...)
		cmd.Env = append(os.Environ(), "SSLKEYLOGFILE="+keylog)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
}

func goRun(h2 bool) func(ctx context.Context, url, keylog string) error {
	return func(ctx context.Context, url, keylog string) error {
		f, err := os.Create(keylog) //nolint:gosec // temporário do teste
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // keylog
		tr := &http.Transport{TLSClientConfig: &tls.Config{KeyLogWriter: f}, ForceAttemptHTTP2: h2}
		tr.Protocols = new(http.Protocols)
		if h2 {
			tr.Protocols.SetHTTP2(true)
		} else {
			tr.Protocols.SetHTTP1(true)
		}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
}

func chromeRun(ctx context.Context, url, keylog string) error {
	dir, err := os.MkdirTemp("", "fs-e2e-chrome-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir) //nolint:errcheck // perfil descartável
	// QUIC desligado: o HTTPS RR anuncia h3 e o servidor h3 é da F4; o caso 7 é TLS sobre TCP
	cmd := exec.CommandContext(ctx, chromeBin, "--headless=new", "--disable-gpu", "--no-first-run",
		"--no-default-browser-check", "--disable-quic", "--user-data-dir="+dir, "--ssl-key-log-file="+keylog,
		"--dump-dom", url)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	if !bytes.Contains(out, []byte("conn_id: ")) {
		return fmt.Errorf("chrome: página sem conn_id: %.300s", out)
	}
	return nil
}

// TestCase7TLSFingerprints: ClientHello byte a byte, JA3/JA4 e Akamai de cada cliente conferidos com as
// ferramentas de referência sobre o pcap da mesma conexão.
func TestCase7TLSFingerprints(t *testing.T) {
	clients := []tlsClient{
		{name: "curl-libressl-h2", h2: true, run: curlRun(curlLibreSSL, "--http2"), needs: curlLibreSSL},
		{name: "curl-libressl-h1", run: curlRun(curlLibreSSL, "--http1.1"), needs: curlLibreSSL},
		{name: "curl-openssl-h2", h2: true, keys: true, run: curlRun(curlOpenSSL, "--http2"), needs: curlOpenSSL},
		{name: "curl-openssl-h1", keys: true, run: curlRun(curlOpenSSL, "--http1.1"), needs: curlOpenSSL},
		{name: "go-h2", h2: true, keys: true, run: goRun(true)},
		{name: "go-h1", keys: true, run: goRun(false)},
		{name: "chrome-h2", h2: true, keys: true, run: chromeRun, needs: chromeBin},
	}
	for _, cl := range clients {
		t.Run(cl.name, func(t *testing.T) {
			t.Parallel()
			if cl.needs != "" {
				if _, err := os.Stat(cl.needs); err != nil {
					t.Skipf("%s não está instalado nesta máquina", cl.needs)
				}
			}
			id := newID(t)
			url := "https://" + probeHost(id) + "/p/" + id + "/"
			keylog := filepath.Join(t.TempDir(), "keys")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := cl.run(ctx, url, keylog); err != nil {
				t.Fatalf("%s: %v", cl.name, err)
			}
			keys, _ := os.ReadFile(keylog) //nolint:gosec // temporário do teste
			if cl.keys && len(keys) == 0 {
				t.Fatalf("%s não gravou o SSLKEYLOGFILE", cl.name)
			}
			p := waitProbe(t, id, func(p *probeResp) bool {
				for _, c := range p.conns(443) {
					if c.TLS != nil && len(c.HTTP)+h2Streams(c) > 0 {
						return true
					}
				}
				return false
			})
			checked := 0
			for _, c := range p.conns(443) {
				if c.TLS == nil {
					continue // ex.: preconnect do Chrome sem dados de aplicação
				}
				checkTLSConn(t, cl, c, keys)
				checked++
			}
			t.Logf("%s: %d conexões TLS conferidas", cl.name, checked)
		})
	}
}

func h2Streams(c record) int {
	if c.HTTP2 == nil {
		return 0
	}
	return len(c.HTTP2.Streams)
}

func checkTLSConn(t *testing.T, cl tlsClient, c record, keys []byte) {
	t.Helper()
	tl := c.TLS
	wantProto := "tls/http1.1"
	if cl.h2 {
		wantProto = "tls/h2"
	}
	if c.Proto != wantProto && (len(c.HTTP) > 0 || h2Streams(c) > 0) {
		t.Errorf("%s: proto = %q, esperado %q", c.ConnID, c.Proto, wantProto)
	}
	if tl.Negotiated == nil || !strings.HasPrefix(tl.Negotiated.Version, "TLS") || tl.HandshakeMs == nil {
		t.Errorf("%s: negotiated=%+v handshake_ms=%v", c.ConnID, tl.Negotiated, ptr(tl.HandshakeMs))
	}
	if tl.SNI == nil || !strings.HasSuffix(*tl.SNI, "."+zone) {
		t.Errorf("%s: SNI = %v", c.ConnID, ptr(tl.SNI))
	}
	// o registro completo por /connections/{id} é o mesmo do probe (e entra na validação de contrato)
	if full := connRecord(t, c.ConnID); full.TLS == nil || full.TLS.ClientHelloB64 != tl.ClientHelloB64 || full.Proto != c.Proto {
		t.Errorf("%s: /connections/{id} difere do registro do probe", c.ConnID)
	}
	keysF := []string{"7"}
	switch {
	case cl.h2 && h2Streams(c) > 0:
		keysF = append(keysF, "7/h2")
	case !cl.h2 && len(c.HTTP) > 0:
		keysF = append(keysF, "7/h1")
	}
	requireConnFields(t, []record{c}, keysF...)
	ref := analyzePcap(t, c.ConnID, 443, keys)
	if len(ref.ClientHellos) != 1 {
		t.Fatalf("%s: tshark achou %d ClientHellos no pcap da conexão", c.ConnID, len(ref.ClientHellos))
	}
	tool := ref.ClientHellos[0]

	// ClientHello byte a byte: o registro guarda o(s) registro(s) TLS inteiros; o fluxo do cliente no pcap
	// começa por eles
	ch := b64(t, tl.ClientHelloB64)
	if len(ch) < 5 || !bytes.HasPrefix(ref.ClientBytes, ch) {
		n := min(len(ch), len(ref.ClientBytes), 64)
		t.Errorf("%s: client_hello_b64 (%d bytes) não é o início do fluxo do cliente no pcap (%d bytes); início %x × %x",
			c.ConnID, len(ch), len(ref.ClientBytes), ch[:n], ref.ClientBytes[:n])
	}
	if tl.ClientHelloRecords < 1 || tl.ClientHelloSegments < 1 {
		t.Errorf("%s: client_hello_records=%d client_hello_segments=%d", c.ConnID, tl.ClientHelloRecords, tl.ClientHelloSegments)
	}

	// fingerprints contra tshark (JA3) e ja4 da FoxIO (JA4, JA4_r)
	if tl.JA3MD5 != tool.JA3 {
		t.Errorf("%s: ja3_md5 = %s, tshark = %s", c.ConnID, tl.JA3MD5, tool.JA3)
	}
	if tl.JA4 != tool.JA4Tool || tl.JA4R != tool.JA4R {
		t.Errorf("%s: ja4 = %s / ja4_r = %s; ja4 da FoxIO = %s / %s", c.ConnID, tl.JA4, tl.JA4R, tool.JA4Tool, tool.JA4R)
	}
	if strings.Join(tl.ALPN, ",") != strings.Join(tool.ALPN, ",") {
		t.Errorf("%s: alpn = %v, tshark = %v", c.ConnID, tl.ALPN, tool.ALPN)
	}
	t.Logf("%s %s: ja3=%s ja4=%s", cl.name, c.ConnID, tl.JA3MD5, tl.JA4)

	if !cl.keys {
		return
	}
	// com as chaves do cliente: Akamai h2 (tshark, técnica do fingerproxy no ref.py) e JA4H (ja4)
	if cl.h2 && c.HTTP2 != nil && len(c.HTTP2.Streams) > 0 {
		if ref.Akamai == nil {
			t.Errorf("%s: tshark não montou o Akamai com o keylog do cliente", c.ConnID)
		} else if c.HTTP2.Akamai != *ref.Akamai {
			t.Errorf("%s: akamai = %q, tshark = %q", c.ConnID, c.HTTP2.Akamai, *ref.Akamai)
		}
		if ref.JA4H != nil && ptr(c.HTTP2.Streams[0].JA4H) != *ref.JA4H {
			t.Errorf("%s: ja4h h2 = %v, ja4 = %s", c.ConnID, ptr(c.HTTP2.Streams[0].JA4H), *ref.JA4H)
		}
		t.Logf("%s %s: akamai=%s", cl.name, c.ConnID, c.HTTP2.Akamai)
	}
	if !cl.h2 && len(c.HTTP) > 0 && ref.JA4H != nil && ptr(c.HTTP[0].JA4H) != *ref.JA4H {
		t.Errorf("%s: ja4h h1 = %v, ja4 = %s", c.ConnID, ptr(c.HTTP[0].JA4H), *ref.JA4H)
	}
}

// TestF3Certificates: curl sem -k (cadeia do sistema) em <id>.dns-monitor nas portas web TLS e na 9000 da API;
// e o Go com a verificação padrão.
func TestF3Certificates(t *testing.T) {
	t.Parallel()
	id := newID(t)
	urls := []string{
		"https://" + probeHost(id) + "/p/" + id + "/",
		"https://" + probeHost(id) + ":8443/p/" + id + "/",
		"https://" + zone + "/",
		"https://" + vpsHost + ":9000/api/v1/health",
	}
	for _, u := range urls {
		out, err := exec.Command(curlLibreSSL, "-4", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{ssl_verify_result}", "--max-time", "20", u).CombinedOutput()
		if err != nil || !strings.HasSuffix(string(out), " 0") || strings.HasPrefix(string(out), "000") {
			t.Errorf("curl sem -k %s: %v %s", u, err, out)
		}
		resp, err := http.Get(u) //nolint:gosec // URL do teste
		if err != nil {
			t.Errorf("Go %s: %v", u, err)
			continue
		}
		_ = resp.Body.Close()
		if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
			t.Errorf("Go %s: sem cadeia verificada", u)
		}
		t.Logf("%s: %d, certificado %s, expira %s", u, resp.StatusCode, resp.TLS.PeerCertificates[0].Subject.CommonName,
			resp.TLS.PeerCertificates[0].NotAfter.Format(time.DateOnly))
	}
	// a resposta da 9000 também entra na validação do contrato
	resp, err := http.Get("https://" + vpsHost + ":9000/api/v1/health") //nolint:gosec // URL do teste
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	addLive("health-example.json", b)
}

// TestF3CrossPortDetection: TLS na porta 80 e HTTP em claro na 443 (detecção pelos primeiros bytes, spec 005
// RF-02).
func TestF3CrossPortDetection(t *testing.T) {
	t.Parallel()
	id := newID(t)
	for _, u := range []string{
		"https://" + probeHost(id) + ":80/p/" + id + "/",
		"http://" + probeHost(id) + ":443/p/" + id + "/",
	} {
		out, err := exec.Command(curlLibreSSL, "-4", "-sS", "--http1.1", "--max-time", "20", u).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "probe_id: "+id) {
			t.Errorf("%s: %v %s", u, err, out)
		}
	}
	p := waitProbe(t, id, func(p *probeResp) bool { return len(p.conns(80)) >= 1 && len(p.conns(443)) >= 1 })
	if c := p.conns(80)[0]; c.Proto != "tls/http1.1" || c.TLS == nil {
		t.Errorf("porta 80 com TLS: proto = %q", c.Proto)
	}
	if c := p.conns(443)[0]; c.Proto != "http1.1" || c.TLS != nil {
		t.Errorf("porta 443 em claro: proto = %q", c.Proto)
	}
}
