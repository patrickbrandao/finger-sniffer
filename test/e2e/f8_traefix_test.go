//go:build e2e

package e2e

// Casos do traefix real da F8 (spec 017 RF-17, spec 019 "Critérios de aceite", ADRs 0062 e 0063; task 273). Rodam
// contra o container de teste do traefix no finger-01 (tmsoftbrasil/traefix:latest, rede do host, entrada própria
// com o perfil da spec 019 RF-03) e contra os routers de teste dele; sem FS_E2E_TRAEFIX_URL todos pulam com aviso.
// Os routers têm o web do espelho (porta 8080) como backend, com o prefixo tirado por stripPrefix: a página
// /p/<id>/ devolve o conn_id e o índice da requisição da conexão traefix → web, e o registro dela no store mostra os
// campos que o backend recebeu (os X-Traefix-* inclusive).
//   - FS_E2E_TRAEFIX_URL: router com o forwardAuth da spec 019 RF-04 sem chave (observe, failOpen);
//   - FS_E2E_TRAEFIX_BLOCK_URL: router com o forwardAuth e a chave de uma chave --mode block;
//   - FS_E2E_TRAEFIX_REVOKED_URL: router com o forwardAuth e a chave de uma chave revogada;
//   - FS_E2E_TRAEFIX_PLAIN_URL e FS_E2E_TRAEFIK_UPSTREAM_URL: entrada do traefix sem o bloco fingerprint e o
//     traefik upstream com a mesma configuração dinâmica (paridade da spec 019 RF-01);
//   - FS_E2E_TRAEFIX_METRICS_CMD: comando no servidor que imprime o /metrics do traefix de teste;
//   - FS_E2E_TRAEFIX_CONTAINER: nome do container de teste (digest e sender no log, ADR 0062 item 7);
//   - FS_E2E_TRAEFIX_STOP_BOT=1: autoriza parar o finger-sniffer-bot por alguns segundos (fail-open com o bot parado);
//   - FS_E2E_TRAEFIX_SOCKS: SOCKS5 local (host:porta) de um `ssh -D` até o finger-01, para o caso do relay (task 313,
//     ADR 0065): o TCP do traefix vê o próprio host e o TLS a volta desta máquina.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	traefixURL         = os.Getenv("FS_E2E_TRAEFIX_URL")
	traefixBlockURL    = os.Getenv("FS_E2E_TRAEFIX_BLOCK_URL")
	traefixRevokedURL  = os.Getenv("FS_E2E_TRAEFIX_REVOKED_URL")
	traefixPlainURL    = os.Getenv("FS_E2E_TRAEFIX_PLAIN_URL")
	traefikUpstreamURL = os.Getenv("FS_E2E_TRAEFIK_UPSTREAM_URL")
	traefixMetricsCmd  = env("FS_E2E_TRAEFIX_METRICS_CMD", "curl -sf http://127.0.0.1:18082/metrics")
	traefixContainer   = env("FS_E2E_TRAEFIX_CONTAINER", "fs-traefix-test")
	traefixSOCKS       = os.Getenv("FS_E2E_TRAEFIX_SOCKS")
)

// requireTraefix pula o caso enquanto o router de teste do traefix não existir.
func requireTraefix(t *testing.T, u string, name string) {
	t.Helper()
	if u == "" {
		t.Skipf("AVISO: traefix real não configurado: defina %s para rodar este caso (task 273)", name)
	}
}

// connIDBody e reqIndexBody acham, no corpo da página /p/<id>/ do web (texto puro, ou dentro do <pre> do
// --dump-dom do Chrome), a conexão traefix → web e o índice da requisição nela.
var (
	connIDBody   = regexp.MustCompile(`conn_id: ([0-9A-HJKMNP-TV-Z]{26})`)
	reqIndexBody = regexp.MustCompile(`request: ([0-9]+)`)
)

// traefixRun abre a URL e devolve o corpo da resposta.
type traefixRun func(ctx context.Context, u string) (string, error)

// curlBody roda o curl (OpenSSL) com os argumentos e devolve a saída padrão.
func curlBody(args ...string) traefixRun {
	return func(ctx context.Context, u string) (string, error) {
		a := append([]string{"-sS", "--max-time", "20"}, args...)
		out, err := exec.CommandContext(ctx, curlOpenSSL, append(a, u)...).Output()
		if err != nil {
			return "", fmt.Errorf("curl %s: %w", u, err)
		}
		return string(out), nil
	}
}

// goBody é o cliente net/http do Go (h2 ou h1) numa conexão nova, pela família dada (tcp4|tcp6).
func goBody(network string, h2 bool) traefixRun {
	return func(ctx context.Context, u string) (string, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			Protocols: new(http.Protocols), DisableKeepAlives: true,
		}
		if h2 {
			tr.Protocols.SetHTTP2(true)
		} else {
			tr.Protocols.SetHTTP1(true)
			tr.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
		}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close() //nolint:errcheck // leitura
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
}

// chromeBody abre a URL no Chrome headless (UA de desktop) e devolve o DOM; quic força h3 na origem da URL.
func chromeBody(quic bool) traefixRun {
	return func(ctx context.Context, u string) (string, error) {
		dir, err := os.MkdirTemp("", "fs-e2e-chrome-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir) //nolint:errcheck // perfil descartável
		args := []string{
			"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
			"--user-data-dir=" + dir, "--user-agent=" + chromeUA(), "--dump-dom",
		}
		if quic {
			pu, _ := url.Parse(u)
			args = append(args, "--enable-quic", "--origin-to-force-quic-on="+pu.Host)
		} else {
			args = append(args, "--disable-quic")
		}
		out, err := exec.CommandContext(ctx, chromeBin, append(args, u)...).Output()
		if err != nil {
			return "", fmt.Errorf("chrome %s: %w", u, err)
		}
		return string(out), nil
	}
}

// backendRequest são os campos (nome em minúsculas → valor) que o backend recebeu na requisição index da conexão
// connID do web, pelo registro do store (que só aparece quando a conexão traefix → web fecha).
func backendRequest(t *testing.T, connID string, index int) map[string]string {
	t.Helper()
	var rec struct {
		HTTP []struct {
			Fields [][4]string `json:"fields"`
		} `json:"http"`
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(api + "/connections/" + connID)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				rec.HTTP = nil
				if json.Unmarshal(b, &rec) == nil && len(rec.HTTP) > index {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("store sem a requisição %d da conexão do backend %s", index, connID)
		}
		time.Sleep(time.Second)
	}
	fields := map[string]string{}
	for _, f := range rec.HTTP[index].Fields {
		n := strings.ToLower(f[0])
		if _, dup := fields[n]; dup {
			fields[n] += "\x00" + f[2] // repetido: guarda os dois para o teste ver
			continue
		}
		fields[n] = f[2]
	}
	return fields
}

// traefixFetch abre <base>/p/<id>/ com o cliente e devolve os campos que o backend recebeu.
func traefixFetch(t *testing.T, base string, run traefixRun) map[string]string {
	t.Helper()
	id := newID(t)
	u := strings.TrimSuffix(base, "/") + "/p/" + id + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	body, err := run(ctx, u)
	if err != nil {
		t.Fatalf("%s: %v", u, err)
	}
	m, n := connIDBody.FindStringSubmatch(body), reqIndexBody.FindStringSubmatch(body)
	if m == nil || n == nil {
		t.Fatalf("%s: resposta sem conn_id/request do web: %.300q", u, body)
	}
	idx, _ := strconv.Atoi(n[1])
	return backendRequest(t, m[1], idx)
}

// traefixGet faz um GET de curl (h2, IPv4) ao router e devolve o status, os cabeçalhos da resposta e os campos que
// o backend recebeu (nil quando a resposta não veio do backend, ex.: o 403 do modo block).
func traefixGet(t *testing.T, base string, extra ...string) (int, http.Header, map[string]string) {
	t.Helper()
	id := newID(t)
	u := strings.TrimSuffix(base, "/") + "/p/" + id + "/"
	args := append([]string{"-4", "-sS", "-i", "--http2", "--max-time", "20"}, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, curlOpenSSL, append(args, u)...).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s: %v %s", u, err, out)
	}
	head, body, _ := strings.Cut(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n\n")
	lines := strings.Split(head, "\n")
	status := 0
	if f := strings.Fields(lines[0]); len(f) >= 2 {
		_, _ = fmt.Sscan(f[1], &status)
	}
	h := http.Header{}
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	m, n := connIDBody.FindStringSubmatch(body), reqIndexBody.FindStringSubmatch(body)
	if m == nil || n == nil {
		return status, h, nil
	}
	idx, _ := strconv.Atoi(n[1])
	return status, h, backendRequest(t, m[1], idx)
}

// traefixMetrics lê o /metrics do traefix de teste (formato Prometheus) como nome{rótulos} → valor.
func traefixMetrics(t *testing.T) map[string]float64 {
	t.Helper()
	out := remote(t, traefixMetricsCmd)
	m := map[string]float64{}
	for l := range strings.Lines(out) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		if v, err := strconv.ParseFloat(l[i+1:], 64); err == nil {
			m[l[:i]] = v
		}
	}
	return m
}

// mirrorRef abre o probe direto no web do espelho (8443) com o mesmo cliente e devolve o JA4 e o Akamai que o
// espelho calculou para ele (a referência da spec 019 "Critérios de aceite").
func mirrorRef(t *testing.T, run traefixRun) (ja4, akamai string) {
	t.Helper()
	id := newID(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := run(ctx, probeURL(id)); err != nil {
		t.Fatalf("probe direto: %v", err)
	}
	p := waitProbe(t, id, func(p *probeResp) bool {
		for _, c := range p.conns(portTLS) {
			if c.TLS != nil && c.Requests > 0 {
				return true
			}
		}
		return false
	})
	for _, pc := range p.conns(portTLS) {
		if pc.TLS == nil || pc.Requests == 0 {
			continue
		}
		var c f8Conn
		get(t, "/connections/"+pc.ConnID, &c)
		if c.TLS != nil {
			ja4 = c.TLS.JA4
		}
		if c.HTTP2 != nil {
			akamai = c.HTTP2.Akamai
		}
		return ja4, akamai
	}
	t.Fatalf("probe %s sem conexão TLS com requisição", id)
	return "", ""
}

// traefixVerdict é o veredito da consulta pela conexão do traefix, com o que a conferência da task 273 lê.
type traefixVerdict struct {
	Class        string      `json:"class"`
	Signals      []botSignal `json:"signals"`
	Fingerprints struct {
		JA4        *string `json:"ja4"`
		Akamai     *string `json:"akamai"`
		JA4H       *string `json:"ja4h"`
		JA4T       *string `json:"ja4t"`
		P0fOS      *string `json:"p0f_os"`
		TTLInitial *int    `json:"ttl_initial"`
		TCPRTT     *int64  `json:"tcp_rtt_us"`
		TLSRTT     *int64  `json:"tls_rtt_us"`
		RTTGap     *int64  `json:"rtt_gap_us"`
		EstToFirst *int64  `json:"est_to_first_us"`
		TimingSrc  *string `json:"timing_source"`
	} `json:"fingerprints"`
	View struct {
		TCP bool `json:"tcp"`
		TLS bool `json:"tls"`
		H2  bool `json:"h2"`
		H3  bool `json:"h3"`
	} `json:"view"`
	Subject struct {
		Src      *endpoint `json:"src"`
		FsConnID *string   `json:"fs_conn_id"`
		ConnID   *string   `json:"conn_id"`
	} `json:"subject"`
}

// verdictOfTraefixConn consulta o veredito da conexão do traefix (X-Traefix-Conn-Id) pela 9002.
func verdictOfTraefixConn(t *testing.T, k *botKey, tid string) traefixVerdict {
	t.Helper()
	r := botDo(t, http.MethodGet, "/verdict/conn/"+tid+"?wait=1000", k, nil, nil)
	if r.status != http.StatusOK {
		t.Fatalf("verdict/conn/%s: %d %s", tid, r.status, r.body)
	}
	var v traefixVerdict
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("verdict/conn/%s: %v", tid, err)
	}
	return v
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// fpCase é um cliente da conferência de fingerprints (spec 019 critério 1).
type fpCase struct {
	name   string
	needs  string
	proto  string // h1 | h2 | h3, o X-Traefix-Proto esperado
	family int    // 4 | 6 | 0 (o navegador escolhe)
	run    traefixRun
}

func fpCases() []fpCase {
	return []fpCase{
		{"curl-h1-v4", curlOpenSSL, "h1", 4, curlBody("-4", "--http1.1")},
		{"curl-h2-v4", curlOpenSSL, "h2", 4, curlBody("-4", "--http2")},
		{"curl-h2-v6", curlOpenSSL, "h2", 6, curlBody("-6", "--http2")},
		{"curl-h3-v4", curlOpenSSL, "h3", 4, curlBody("-4", "--http3-only")},
		{"curl-h3-v6", curlOpenSSL, "h3", 6, curlBody("-6", "--http3-only")},
		{"go-h1-v4", "", "h1", 4, goBody("tcp4", false)},
		{"go-h2-v4", "", "h2", 4, goBody("tcp4", true)},
		{"go-h2-v6", "", "h2", 6, goBody("tcp6", true)},
		{"chrome-h2", chromeBin, "h2", 0, chromeBody(false)},
		{"chrome-h3", chromeBin, "h3", 0, chromeBody(true)},
	}
}

// storeTCPOf é a visão TCP do store da conexão casada.
func storeTCPOf(t *testing.T, connID string) (ja4t, p0f, os string) {
	t.Helper()
	var c struct {
		TCP *struct {
			JA4T    *string `json:"ja4t"`
			P0f     *string `json:"p0f"`
			OSGuess *string `json:"os_guess"`
		} `json:"tcp"`
	}
	get(t, "/connections/"+connID, &c)
	if c.TCP == nil {
		return "", "", ""
	}
	return derefOr(c.TCP.JA4T), derefOr(c.TCP.P0f), derefOr(c.TCP.OSGuess)
}

// TestF8TraefixReal são os casos do traefix real (pulam sem o container de teste).
func TestF8TraefixReal(t *testing.T) {
	requireTraefix(t, traefixURL, "FS_E2E_TRAEFIX_URL")
	img := remote(t, "docker inspect --format '{{.Image}}' "+traefixContainer+" && docker exec "+traefixContainer+
		" /traefik version | sed -n 's/^Version: *//p'")
	t.Logf("traefix de teste: %s", strings.ReplaceAll(img, "\n", " sender traefix/"))
	pub := macIPv4(t)
	key := newBotKey(t)
	before := botMetricsNow(t)
	firstAuths := 0

	t.Run("observe", func(t *testing.T) {
		f := traefixFetch(t, traefixURL, curlBody("-4", "--http2"))
		firstAuths++
		for _, n := range []string{
			"x-traefix-conn-id", "x-traefix-ja4h", "x-traefix-ja4", "x-traefix-ja3", "x-traefix-h2",
			"x-traefix-alpn", "x-traefix-ja4t", "x-traefix-src-port", "x-traefix-dst-port",
		} {
			if f[n] == "" {
				t.Errorf("backend sem %s: %v", n, f)
			}
		}
		if f["x-traefix-src-ip"] != pub || f["x-traefix-proto"] != "h2" {
			t.Errorf("backend: X-Traefix-Src-Ip %q (gerador %s) X-Traefix-Proto %q", f["x-traefix-src-ip"], pub, f["x-traefix-proto"])
		}
		if f["x-traefix-verdict"] != "bot" {
			t.Errorf("curl pelo router em observe: X-Traefix-Verdict %q, esperado bot (primeira requisição pelos cabeçalhos, ADR 0062 item 4)",
				f["x-traefix-verdict"])
		}
		v := verdictOfTraefixConn(t, key, f["x-traefix-conn-id"])
		if derefOr(v.Subject.ConnID) == "" || !v.View.TCP || !v.View.TLS || !v.View.H2 {
			t.Errorf("consulta pela conexão do traefix sem casamento com o store ou sem visões: %+v", v)
		}
	})

	t.Run("forged-headers", func(t *testing.T) {
		const forgedJA4H = "ge11cr99enus_000000000000_000000000000_000000000000"
		const forgedJA4 = "t13d9999h2_000000000000_000000000000"
		const forgedID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
		f := traefixFetch(t, traefixURL, curlBody("-4", "--http2",
			"-H", "X-Traefix-Src-Ip: 203.0.113.7", "-H", "x-traefix-ja4h: "+forgedJA4H, "-H", "X-TRAEFIX-JA4: "+forgedJA4,
			"-H", "X_Traefix_Conn_Id: "+forgedID, "-H", "X-Traefix-Verdict: human"))
		firstAuths++
		for n, bad := range map[string]string{
			"x-traefix-src-ip": "203.0.113.7", "x-traefix-ja4h": forgedJA4H,
			"x-traefix-ja4": forgedJA4, "x-traefix-conn-id": forgedID, "x-traefix-verdict": "human",
		} {
			if strings.Contains(f[n], bad) {
				t.Errorf("%s forjado chegou ao backend: %q (spec 019 RF-05)", n, f[n])
			}
		}
		if _, ok := f["x_traefix_conn_id"]; ok {
			t.Errorf("X_Traefix_Conn_Id forjado chegou ao backend: %v", f)
		}
		if f["x-traefix-src-ip"] != pub || f["x-traefix-conn-id"] == "" {
			t.Errorf("com X-Traefix-* forjados: X-Traefix-Src-Ip %q (gerador %s) X-Traefix-Conn-Id %q", f["x-traefix-src-ip"], pub, f["x-traefix-conn-id"])
		}
		v := verdictOfTraefixConn(t, key, f["x-traefix-conn-id"])
		if derefOr(v.Fingerprints.JA4H) == forgedJA4H || derefOr(v.Fingerprints.JA4) == forgedJA4 || v.Subject.Src == nil || v.Subject.Src.IP != pub {
			t.Errorf("X-Traefix-* forjados chegaram ao bot: src %+v ja4 %q ja4h %q", v.Subject.Src, derefOr(v.Fingerprints.JA4), derefOr(v.Fingerprints.JA4H))
		}
		// X-Fs-* forjados não mudam o veredito (ADR 0063 item 1): o par tem os mesmos campos com nomes neutros do
		// mesmo tamanho, para o JA4H ter a mesma contagem de campos nos dois
		verdictWith := func(prefix string) (traefixVerdict, map[string]string) {
			f := traefixFetch(t, traefixURL, curlBody("-4", "--http2", "-H", prefix+"-Verdict: human",
				"-H", prefix+"-Ja4h: "+forgedJA4H, "-H", prefix+"-Src-Ip: 203.0.113.7", "-H", prefix+"-Conn-Id: "+forgedID))
			firstAuths++
			return verdictOfTraefixConn(t, key, f["x-traefix-conn-id"]), f
		}
		vFs, fFs := verdictWith("X-Fs")
		vNeutral, fNeutral := verdictWith("X-Zz")
		// relay_rtt_gap depende dos tempos de cada conexão (ADR 0065 item 3) e sai da comparação; com ele em só um
		// dos dois, a classe pode mudar pelo peso dele e também não se compara
		ids := func(v traefixVerdict) []string {
			var out []string
			for _, s := range v.Signals {
				if s.ID != "relay_rtt_gap" {
					out = append(out, s.ID)
				}
			}
			return out
		}
		sameTiming := slices.ContainsFunc(vFs.Signals, isRelaySignal) == slices.ContainsFunc(vNeutral.Signals, isRelaySignal)
		if (sameTiming && (vFs.Class != vNeutral.Class || fFs["x-traefix-verdict"] != fNeutral["x-traefix-verdict"])) ||
			!slices.Equal(ids(vFs), ids(vNeutral)) || derefOr(vFs.Fingerprints.JA4H) == forgedJA4H {
			t.Errorf("X-Fs-* forjados mudaram o veredito: %s %v (backend %q), com nomes neutros %s %v (backend %q)",
				vFs.Class, ids(vFs), fFs["x-traefix-verdict"], vNeutral.Class, ids(vNeutral), fNeutral["x-traefix-verdict"])
		}
		t.Logf("X-Fs-* forjados: veredito %s %v igual ao dos nomes neutros; chegam ao backend como vieram (X-Fs-Verdict %q): os backends leem só X-Traefix-*",
			vFs.Class, ids(vFs), fFs["x-fs-verdict"])
	})

	t.Run("fingerprints", func(t *testing.T) {
		matched, tcpConns := 0, 0
		for _, c := range fpCases() {
			t.Run(c.name, func(t *testing.T) {
				if c.needs != "" {
					if _, err := os.Stat(c.needs); err != nil {
						t.Skipf("AVISO: %s ausente", c.needs)
					}
				}
				if c.family == 6 && !hasIPv6Route() {
					t.Skip("AVISO: esta máquina está sem rota IPv6 até o finger-01")
				}
				f := traefixFetch(t, traefixURL, c.run)
				firstAuths++
				tid := f["x-traefix-conn-id"]
				ip := net.ParseIP(f["x-traefix-src-ip"])
				if f["x-traefix-proto"] != c.proto || tid == "" || ip == nil ||
					(c.family == 4 && ip.To4() == nil) || (c.family == 6 && ip.To4() != nil) {
					t.Fatalf("backend: proto %q (quer %s) conn %q src %q (família %d)", f["x-traefix-proto"], c.proto, tid,
						f["x-traefix-src-ip"], c.family)
				}
				v := verdictOfTraefixConn(t, key, tid)
				ja4, akamai := mirrorRef(t, c.run)
				botJA4, botAk := derefOr(v.Fingerprints.JA4), derefOr(v.Fingerprints.Akamai)
				if botJA4 != ja4 || f["x-traefix-ja4"] != ja4 {
					t.Errorf("JA4: bot %q, X-Traefix-Ja4 %q, espelho %q", botJA4, f["x-traefix-ja4"], ja4)
				}
				if c.proto == "h2" && (botAk != akamai || f["x-traefix-h2"] != akamai) {
					t.Errorf("Akamai: bot %q, X-Traefix-H2 %q, espelho %q", botAk, f["x-traefix-h2"], akamai)
				}
				line := fmt.Sprintf("%-11s %s src %-39s ja4 %s akamai %q", c.name, c.proto, f["x-traefix-src-ip"], botJA4, botAk)
				if c.proto == "h3" {
					if f["x-traefix-ja4t"] != "" || !v.View.H3 {
						t.Errorf("h3: X-Traefix-Ja4t %q view.h3 %v", f["x-traefix-ja4t"], v.View.H3)
					}
					t.Logf("%s conn_id %q", line, derefOr(v.Subject.ConnID))
					return
				}
				tcpConns++
				cid := derefOr(v.Subject.ConnID)
				if cid == "" {
					t.Errorf("conexão do traefix %s sem casamento com o store (spec 018 RF-04)", tid)
					return
				}
				matched++
				sJA4T, sP0f, sOS := storeTCPOf(t, cid)
				if f["x-traefix-ja4t"] != sJA4T || derefOr(v.Fingerprints.JA4T) != sJA4T {
					t.Errorf("JA4T: X-Traefix-Ja4t %q, bot %q, store %q", f["x-traefix-ja4t"], derefOr(v.Fingerprints.JA4T), sJA4T)
				}
				t.Logf("%s ja4t %s os %q (store %q, p0f %s) conn_id %s", line, sJA4T, derefOr(v.Fingerprints.P0fOS), sOS, sP0f, cid)
			})
		}
		t.Logf("casamento traefix ↔ store nas conexões TCP da conferência: %d de %d", matched, tcpConns)
	})

	t.Run("match-rate", func(t *testing.T) {
		testTraefixRealMatch(t, key, pub)
	})

	t.Run("relay", func(t *testing.T) {
		if traefixSOCKS == "" {
			t.Skip("AVISO: defina FS_E2E_TRAEFIX_SOCKS (ssh -D até o finger-01) para o caso do relay (task 313)")
		}
		testTraefixRelay(t, key, pub)
	})

	t.Run("h3-ttl", func(t *testing.T) {
		testTraefixH3TTL(t, key)
	})

	t.Run("block-first-request", func(t *testing.T) {
		requireTraefix(t, traefixBlockURL, "FS_E2E_TRAEFIX_BLOCK_URL")
		status, h, _ := traefixGet(t, traefixBlockURL)
		firstAuths++
		// 403 mínimo do bot devolvido pelo traefix com o perfil denyRequiresResponseHeader: X-Traefix-Deny (ADR 0074)
		if status != http.StatusForbidden || h.Get("X-Traefix-Deny") != "1" || h.Get("X-Traefix-Verdict") != "" {
			t.Errorf("curl na primeira requisição em block: %d X-Traefix-Deny %q X-Traefix-Verdict %q, esperado 403 com só o marcador (spec 019 RF-04, ADR 0074)",
				status, h.Get("X-Traefix-Deny"), h.Get("X-Traefix-Verdict"))
		}
	})

	t.Run("fail-open-revoked-key", func(t *testing.T) {
		requireTraefix(t, traefixRevokedURL, "FS_E2E_TRAEFIX_REVOKED_URL")
		m0 := traefixMetrics(t)
		status, _, f := traefixGet(t, traefixRevokedURL)
		if status != http.StatusOK || f["x-traefix-verdict"] != "unavailable" {
			t.Errorf("chave revogada no forwardAuth: %d X-Traefix-Verdict %q, esperado 200 unavailable (fail-open de 4xx, spec 019 RF-04)",
				status, f["x-traefix-verdict"])
		}
		if d := metricDelta(m0, traefixMetrics(t), "traefik_forwardauth_failopen_total", `reason="http_4xx"`); d < 1 {
			t.Errorf("traefik_forwardauth_failopen_total{reason=\"http_4xx\"} Δ %v, esperado ≥ 1", d)
		}
	})

	t.Run("upstream-parity", func(t *testing.T) {
		requireTraefix(t, traefixPlainURL, "FS_E2E_TRAEFIX_PLAIN_URL")
		requireTraefix(t, traefikUpstreamURL, "FS_E2E_TRAEFIK_UPSTREAM_URL")
		testUpstreamParity(t)
	})

	t.Run("metrics", func(t *testing.T) {
		testBotMetricsReal(t, before, firstAuths)
	})

	// por último: parar o bot zera os contadores do heartbeat lidos pelo caso "metrics"
	t.Run("fail-open-bot-stopped", func(t *testing.T) {
		if os.Getenv("FS_E2E_TRAEFIX_STOP_BOT") != "1" {
			t.Skip("AVISO: defina FS_E2E_TRAEFIX_STOP_BOT=1 para parar o bot no finger-01 durante o caso")
		}
		m0 := traefixMetrics(t)
		remote(t, "systemctl stop finger-sniffer-bot")
		t.Cleanup(func() {
			remote(t, "systemctl start finger-sniffer-bot")
			// a 9002 volta em alguns segundos; os casos seguintes dependem dela
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if r, err := botHTTP.Get(botBase + "/health"); err == nil {
					_ = r.Body.Close()
					if r.StatusCode == http.StatusOK {
						return
					}
				}
				time.Sleep(time.Second)
			}
		})
		status, _, f := traefixGet(t, traefixURL)
		time.Sleep(time.Second) // o lote da conexão sai em até flushInterval (100 ms)
		m1 := traefixMetrics(t)
		if status != http.StatusOK || f["x-traefix-verdict"] != "unavailable" {
			t.Errorf("bot parado: %d X-Traefix-Verdict %q, esperado 200 unavailable (fail-open, spec 019 RF-04)", status, f["x-traefix-verdict"])
		}
		fo := metricDelta(m0, m1, "traefik_forwardauth_failopen_total")
		dr := metricDelta(m0, m1, "traefik_fingerprint_export_dropped_total")
		t.Logf("bot parado: failopen Δ %v, export_dropped Δ %v", fo, dr)
		if fo < 1 || dr < 1 {
			t.Errorf("bot parado: traefik_forwardauth_failopen_total Δ %v e traefik_fingerprint_export_dropped_total Δ %v, esperado ≥ 1", fo, dr)
		}
	})
}

// testTraefixRealMatch é a rodada de casamento: 100 conexões novas de um cliente Go (h2, IPv4) pelo router; o
// veredito pela origem (porta local de cada uma) tem de vir da conexão do traefix casada com a do store (≥ 99%).
func testTraefixRealMatch(t *testing.T, key *botKey, pub string) {
	const rounds = 100
	matched := 0
	for i := range rounds {
		var local int
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				c, err := d.DialContext(ctx, "tcp4", addr)
				if err == nil {
					local = c.LocalAddr().(*net.TCPAddr).Port
				}
				return c, err
			},
			Protocols: new(http.Protocols), DisableKeepAlives: true,
		}
		tr.Protocols.SetHTTP2(true)
		resp, err := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Get(strings.TrimSuffix(traefixURL, "/") + "/p/" + newID(t) + "/")
		if err != nil {
			t.Fatalf("conexão %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		r := botDo(t, http.MethodGet, fmt.Sprintf("/verdict?src_ip=%s&src_port=%d&site=%s&wait=1000", pub, local, vpsHost), key, nil, nil)
		var v traefixVerdict
		_ = json.Unmarshal(r.body, &v)
		if r.status == http.StatusOK && derefOr(v.Subject.FsConnID) != "" && derefOr(v.Subject.ConnID) != "" {
			matched++
		} else {
			t.Logf("conexão %d (%s:%d) sem casamento: %d %.300s", i, pub, local, r.status, r.body)
		}
	}
	pct := 100 * float64(matched) / rounds
	t.Logf("casamento traefix ↔ store (traefix real): %d de %d (%.1f%%)", matched, rounds, pct)
	if pct < 99 {
		t.Errorf("casamento %.1f%%, esperado ≥ 99%% (spec 019 critério 1)", pct)
	}
}

// testUpstreamParity: a entrada do traefix sem o bloco fingerprint responde como o traefik upstream com a mesma
// configuração dinâmica (spec 019 RF-01): mesmo status e cabeçalhos na resposta e mesmos campos no backend.
func testUpstreamParity(t *testing.T) {
	cl := &http.Client{Timeout: 10 * time.Second}
	names := func(h http.Header) []string {
		var out []string
		for k := range h {
			if k != "Date" {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	for _, p := range []string{"/ping", "/nao-existe-" + newID(t)} {
		var got [2]string
		for i, base := range []string{traefixPlainURL, traefikUpstreamURL} {
			resp, err := cl.Get(strings.TrimSuffix(base, "/") + p)
			if err != nil {
				t.Fatalf("%s%s: %v", base, p, err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			got[i] = fmt.Sprintf("%d %v %q", resp.StatusCode, names(resp.Header), b)
		}
		if got[0] != got[1] {
			t.Errorf("%s: traefix sem fingerprint %s, upstream %s", p, got[0], got[1])
		}
	}
	var fields [2][]string
	for i, base := range []string{traefixPlainURL, traefikUpstreamURL} {
		f := traefixFetch(t, base, curlBody("-4", "--http2"))
		for n := range f {
			fields[i] = append(fields[i], n)
		}
		slices.Sort(fields[i])
	}
	// o traefix acrescenta sempre Forwarded (RFC 7239) e X-Real-Port ao backend, com ou sem fingerprint (commit
	// 193af416c do traefix): diferença conhecida, registrada na task 273; qualquer outra é falha
	known := []string{"forwarded", "x-real-port"}
	extra := slices.DeleteFunc(slices.Clone(fields[0]), func(n string) bool { return slices.Contains(fields[1], n) })
	missing := slices.DeleteFunc(slices.Clone(fields[1]), func(n string) bool { return slices.Contains(fields[0], n) })
	if len(missing) > 0 || slices.ContainsFunc(extra, func(n string) bool { return !slices.Contains(known, n) }) {
		t.Errorf("campos no backend: traefix sem fingerprint %v, upstream %v", fields[0], fields[1])
	} else if len(extra) > 0 {
		t.Logf("AVISO: o traefix sem fingerprint manda ao backend %v, que o traefik upstream não manda", extra)
	}
}

// testBotMetricsReal confere as métricas do bot ao fim dos casos do traefix real: nenhuma divergência entre as
// fingerprints prontas do traefix e as calculadas (exceto ja4o, sem golden), nenhum erro de análise e as primeiras
// requisições julgadas pelos cabeçalhos.
func testBotMetricsReal(t *testing.T, before map[string]float64, firstAuths int) {
	time.Sleep(6 * time.Second) // heartbeat a cada 5 s
	after := botMetricsNow(t)
	for _, kind := range []string{"ja3", "ja3n", "ja4", "ja4r", "ja4o", "akamai", "ja4t"} {
		d := metricDelta(before, after, "bot_ingest_fingerprint_mismatch_total", `kind="`+kind+`"`)
		switch {
		case d != 0 && kind == "ja4o":
			t.Logf("AVISO: bot_ingest_fingerprint_mismatch_total{kind=\"ja4o\"} Δ %v (sem golden de JA4_o, ADR 0063 item 4)", d)
		case d != 0:
			t.Errorf("bot_ingest_fingerprint_mismatch_total{kind=%q} Δ %v, esperado 0 com o traefix real (spec 019 RF-14)", kind, d)
		}
	}
	if d := metricDelta(before, after, "bot_ingest_parse_errors_total"); d != 0 {
		t.Errorf("bot_ingest_parse_errors_total Δ %v, esperado 0", d)
	}
	rec := metricDelta(before, after, "bot_ingest_records_total")
	tlsHdr := metricDelta(before, after, "bot_auth_fingerprint_total", `kind="tls"`, `source="header"`)
	t.Logf("bot_ingest_records_total Δ %v; bot_auth_fingerprint_total{kind=\"tls\",source=\"header\"} Δ %v; primeiras requisições %d",
		rec, tlsHdr, firstAuths)
	if rec == 0 {
		t.Error("bot_ingest_records_total não subiu com o traefix real")
	}
	if tlsHdr < float64(firstAuths) {
		t.Errorf("bot_auth_fingerprint_total{kind=\"tls\",source=\"header\"} Δ %v, esperado ≥ %d", tlsHdr, firstAuths)
	}
}

// hasIPv6Route diz se esta máquina alcança o finger-01 por IPv6 (um socket UDP conectado só consulta a rota).
func hasIPv6Route() bool {
	c, err := net.Dial("udp6", net.JoinHostPort(vpsHost, "443"))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// isRelaySignal diz se o sinal é o relay_rtt_gap, que varia com os tempos de cada conexão.
func isRelaySignal(s botSignal) bool { return s.ID == "relay_rtt_gap" }

// Limiares do relay_rtt_gap (ADR 0065 item 3), repetidos aqui para conferir a decisão do bot conexão a conexão.
const (
	relayGapMicros   = 20_000
	relayGapFrac     = 0.3
	relayFirstMicros = 10_000
)

// relayRun é uma conexão da rodada direto × relay: os tempos e os sinais do veredito.
type relayRun struct {
	src                string
	tcp, tls, gap, est int64
	signal, authSignal bool
}

func (r relayRun) expected() bool {
	return r.gap > relayGapMicros && float64(r.gap) > float64(r.tcp)*relayGapFrac && r.est > relayFirstMicros
}

// relayRound abre n conexões novas (curl h2) pelo router e devolve os tempos e o relay_rtt_gap de cada uma.
func relayRound(t *testing.T, key *botKey, n int, args ...string) []relayRun {
	t.Helper()
	var out []relayRun
	for range n {
		f := traefixFetch(t, traefixURL, curlBody(append([]string{"--http2"}, args...)...))
		v := verdictOfTraefixConn(t, key, f["x-traefix-conn-id"])
		fp := v.Fingerprints
		if fp.TCPRTT == nil || fp.TLSRTT == nil || fp.RTTGap == nil || fp.EstToFirst == nil || derefOr(fp.TimingSrc) != "kernel" {
			t.Fatalf("veredito sem os tempos do traefix (headerDetail: full, tcp): %+v; X-Traefix-Timing %q", fp, f["x-traefix-timing"])
		}
		r := relayRun{
			src: f["x-traefix-src-ip"], tcp: *fp.TCPRTT, tls: *fp.TLSRTT, gap: *fp.RTTGap, est: *fp.EstToFirst,
			authSignal: slices.Contains(strings.Split(f["x-traefix-signals"], ","), "relay_rtt_gap"),
		}
		for _, s := range v.Signals {
			r.signal = r.signal || s.ID == "relay_rtt_gap"
		}
		out = append(out, r)
	}
	return out
}

// testTraefixRelay: critério da spec 019 (task 313) — o mesmo curl direto e por um SOCKS5 (ssh -D até o finger-01).
// Pelo relay o kernel do traefix mede a volta TCP com o próprio host (< 1 ms) e a volta TLS inclui o caminho até
// esta máquina. Uma conexão isolada é ruidosa (o traefix recomenda agregar): o caso confere que o bot decide cada
// conexão pelos limiares da ADR 0065 (no veredito e no forwardAuth), que o relay sai com relay_rtt_gap em pelo menos
// uma de n e registra a taxa dos dois lados.
func testTraefixRelay(t *testing.T, key *botKey, pub string) {
	const n = 10
	direct := relayRound(t, key, n, "-4")
	relay := relayRound(t, key, n, "--socks5-hostname", traefixSOCKS)
	hits := func(rs []relayRun) (c int) {
		for _, r := range rs {
			if r.signal {
				c++
			}
		}
		return c
	}
	ms := func(us int64) float64 { return float64(us) / 1000 }
	for name, rs := range map[string][]relayRun{"direto": direct, "relay": relay} {
		for _, r := range rs {
			t.Logf("%-6s src %-24s tcp_rtt %6.1f tls_rtt %6.1f rtt_gap %6.1f est_to_first %6.1f ms relay_rtt_gap %v", name, r.src,
				ms(r.tcp), ms(r.tls), ms(r.gap), ms(r.est), r.signal)
			if r.signal != r.expected() || r.authSignal != r.signal {
				t.Errorf("%s: relay_rtt_gap no veredito %v, no forwardAuth %v, pelos limiares da ADR 0065 %v (%+v)", name, r.signal,
					r.authSignal, r.expected(), r)
			}
			switch {
			case name == "direto" && (r.src != pub || r.tcp < 1000):
				t.Errorf("direto: origem %s (gerador %s), tcp_rtt %d µs", r.src, pub, r.tcp)
			case name == "relay" && (r.src == pub || r.tcp >= 1000):
				t.Errorf("relay: origem %s (o próprio finger-01, não o gerador %s), tcp_rtt %d µs (< 1 ms com o host)", r.src, pub, r.tcp)
			}
		}
	}
	dh, rh := hits(direct), hits(relay)
	t.Logf("relay_rtt_gap: relay %d de %d, direto %d de %d", rh, n, dh, n)
	if rh == 0 {
		t.Errorf("nenhuma das %d conexões pelo relay saiu com relay_rtt_gap", n)
	}
	if dh >= rh {
		t.Logf("AVISO: direto com relay_rtt_gap %d vezes, relay %d: a volta até o finger-01 é curta para uma conexão isolada", dh, rh)
	}
}

// testTraefixH3TTL: critério da spec 019 (task 313, ADR 0065 item 4) — em h3 o traefix manda X-Traefix-Ttl e
// X-Traefix-Transport com proto=udp, e o veredito traz o TTL inicial dele, sem os tempos de TCP.
func testTraefixH3TTL(t *testing.T, key *botKey) {
	cases := []fpCase{
		{"curl-h3-v4", curlOpenSSL, "h3", 4, curlBody("-4", "--http3-only")},
		{"chrome-h3", chromeBin, "h3", 0, chromeBody(true)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := os.Stat(c.needs); err != nil {
				t.Skipf("AVISO: %s ausente", c.needs)
			}
			f := traefixFetch(t, traefixURL, c.run)
			tr := map[string]string{}
			for p := range strings.SplitSeq(f["x-traefix-transport"], ",") {
				if k, v, ok := strings.Cut(p, "="); ok {
					tr[k] = v
				}
			}
			if f["x-traefix-proto"] != "h3" || f["x-traefix-ttl"] == "" || tr["proto"] != "udp" || tr["ttl"] != f["x-traefix-ttl"] || tr["ttl_init"] == "" {
				t.Fatalf("backend em h3: proto %q X-Traefix-Ttl %q X-Traefix-Transport %q", f["x-traefix-proto"], f["x-traefix-ttl"], f["x-traefix-transport"])
			}
			v := verdictOfTraefixConn(t, key, f["x-traefix-conn-id"])
			if v.Fingerprints.TTLInitial == nil || strconv.Itoa(*v.Fingerprints.TTLInitial) != tr["ttl_init"] || !v.View.H3 ||
				v.Fingerprints.TCPRTT != nil || v.Fingerprints.JA4T != nil {
				t.Errorf("veredito h3: ttl_initial %v (traefix ttl_init %s) view %+v tcp_rtt %v ja4t %v", v.Fingerprints.TTLInitial, tr["ttl_init"],
					v.View, v.Fingerprints.TCPRTT, v.Fingerprints.JA4T)
			}
			var ids []string
			for _, s := range v.Signals {
				ids = append(ids, s.ID)
			}
			if slices.Contains(ids, "ua_missing") {
				// PT-14: sem http3HeaderOrder o registro de requisição h3 vem sem fields, e o veredito pelo ingest fica sem UA
				t.Logf("AVISO: ua_missing no veredito h3 pelo ingest (PT-14 pendente no traefix)")
			}
			t.Logf("%s: X-Traefix-Ttl %s ttl_init %s hops %s, veredito %s %v ttl_initial %d, X-Traefix-Timing %q", c.name, f["x-traefix-ttl"],
				tr["ttl_init"], tr["hops"], v.Class, ids, *v.Fingerprints.TTLInitial, f["x-traefix-timing"])
		})
	}
}
