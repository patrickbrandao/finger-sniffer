//go:build e2e

package e2e

// e2e da F8 do lado do bot (task 284; spec 017 RF-14 e RF-17, spec 018 e 020 "Critérios de aceite", ADRs 0057 e
// 0058), contra o bot da main no finger-01:
//   - probe: curl, Go, python-requests, Chrome, Firefox e um Googlebot falso abrem o probe com Origin (linha de
//     comando) ou Referer (navegadores, por uma página local em fs-e2e.localhost) de um domínio da chave, e
//     GET /bot/v1/probes/{id}/verdict dá a classe da tabela da ADR 0057 item 1 (rules v1.3, ADR 0060);
//   - traefix simulado: cada cliente abre o probe sem Origin (o espelho registra o ClientHello, o prefixo h2
//     decifrado e o JA4H da requisição); o teste abre uma conexão real ao traefik-app (443) repetindo esse
//     ClientHello, acha a origem pública dela no store, manda o TraefikIngestBatch ao POST /bot/v1/ingest/traefik
//     da 9002 com a chave (caso (b) da spec 020 "Clientes externos") e confere GET /bot/v1/verdict com view.tcp e
//     JA4/Akamai iguais aos do espelho; uma rodada de 100 conexões de um cliente Go que grava o próprio ClientHello e
//     o próprio prefixo h2 mede o casamento traefix ↔ store (≥ 99%);
//   - forwardAuth na 9002 com os X-Fs-* simulados e a chave; erros sem X-Fs-Verdict (ADR 0058 item 3); feed SSE
//     em ≤ 1 s; forget do IP do gerador.
// A chave de teste é criada pela CLI no servidor e revogada no fim (t.Cleanup, mesmo com falha); chaves e2e-f8-*
// esquecidas por uma execução interrompida são revogadas na próxima. O segredo nunca vai para log nem arquivo.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

var (
	// botBase é a API pública do bot (spec 020 RF-01).
	botBase = env("FS_E2E_BOT", "https://"+vpsHost+":9002/bot/v1")
	// botCLI roda a CLI do bot no servidor como o usuário do serviço (o banco é dele).
	botCLI = env("FS_E2E_BOT_CLI", "runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot")
)

const (
	f8KeyName   = "e2e-f8"           // prefixo do nome das chaves de teste
	f8Site      = "fs-e2e.example"   // Origin dos clientes de linha de comando
	f8Local     = "fs-e2e.localhost" // página local que abre o probe nos navegadores (vai no Referer)
	f8Other     = "fs-e2e-other.example"
	traefikPort = 443 // entrada web do traefik-app no finger-01 (capturada pelo espelho)
	h2Preface   = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

// f8Domains são os domínios das chaves de teste: os do Origin/Referer do probe e o site do traefix simulado.
func f8Domains() string { return f8Site + "," + f8Local + "," + vpsHost }

// ---------------------------------------------------------------- chaves

type botKey struct {
	id     string
	secret string // nunca em log
}

var sweepKeys sync.Once

// newBotKey cria uma chave pela CLI no servidor (extra = opções do key create) e a revoga no fim do teste.
func newBotKey(t *testing.T, extra ...string) *botKey {
	t.Helper()
	sweepKeys.Do(func() { sweepBotKeys(t) })
	name := fmt.Sprintf("%s-%d", f8KeyName, time.Now().UnixNano())
	cmd := botCLI + " key create --name " + name + " --domains " + f8Domains() + " " + strings.Join(extra, " ")
	out, err := exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, cmd).CombinedOutput() //nolint:gosec // destino do teste
	k := &botKey{}
	for l := range strings.Lines(string(out)) {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "id: "); ok {
			k.id = v
		}
		if v, ok := strings.CutPrefix(l, "key: "); ok {
			k.secret = v
		}
	}
	if k.id != "" {
		t.Cleanup(func() { revokeBotKey(t, k.id) })
	}
	if err != nil || k.id == "" || !strings.HasPrefix(k.secret, "fsk_") {
		// a saída só traz o segredo quando a criação deu certo; aqui ela não tem segredo
		t.Fatalf("key create %s: %v (id %q, chave lida: %v)", name, err, k.id, k.secret != "")
	}
	t.Logf("chave de teste %s (%s %s)", k.id, name, strings.Join(extra, " "))
	// a chave vale em até 2 s (keyReload do bot); a de balde 1 não pode gastar fichas na espera
	if slices.Contains(extra, "--rate") {
		time.Sleep(3 * time.Second)
		return k
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := botDo(t, http.MethodGet, "/verdict/conn/"+ulid.Make().String(), k, nil, nil); r.status == http.StatusNotFound {
			return k
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("chave %s não passou a valer em 10 s", k.id)
	return nil
}

// revokeBotKey revoga a chave (no Cleanup: erro vira Errorf para os outros Cleanups rodarem).
func revokeBotKey(t *testing.T, id string) {
	out, err := exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, botCLI+" key revoke "+id).CombinedOutput() //nolint:gosec // destino do teste
	if err != nil && !strings.Contains(string(out), "revoked") {
		t.Errorf("revogar a chave de teste %s: %v %s", id, err, out)
		return
	}
	t.Logf("chave de teste %s revogada", id)
}

// sweepBotKeys revoga as chaves e2e-f8-* ativas há mais de 1 h (de uma execução interrompida antes do Cleanup).
func sweepBotKeys(t *testing.T) {
	t.Helper()
	out := remote(t, botCLI+" key list")
	n := 0
	for l := range strings.Lines(out) {
		f := strings.Fields(l)
		if len(f) < 11 || !strings.HasPrefix(f[2], f8KeyName+"-") || f[len(f)-1] != "-" {
			continue
		}
		created, err := time.Parse(time.RFC3339, f[len(f)-2])
		if err != nil || time.Since(created) < time.Hour {
			continue
		}
		revokeBotKey(t, f[0])
		n++
	}
	if n > 0 {
		t.Logf("AVISO: %d chaves de teste esquecidas por uma execução anterior foram revogadas", n)
	}
}

// ---------------------------------------------------------------- API do bot

var botHTTP = &http.Client{Timeout: 20 * time.Second}

type botResp struct {
	status int
	header http.Header
	body   []byte
}

// botDo chama a API do bot; k nil = sem Authorization.
func botDo(t *testing.T, method, path string, k *botKey, hdr map[string]string, body []byte) botResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, botBase+path, rd) //nolint:noctx // prazo no cliente
	if err != nil {
		t.Fatal(err)
	}
	if k != nil {
		req.Header.Set("Authorization", "Bearer "+k.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for n, v := range hdr {
		req.Header.Set(n, v)
	}
	resp, err := botHTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	return botResp{status: resp.StatusCode, header: resp.Header, body: b}
}

type botSignal struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

type botVerdict struct {
	Class   string      `json:"class"`
	Score   int         `json:"score"`
	Signals []botSignal `json:"signals"`
	View    struct {
		TCP        bool `json:"tcp"`
		TLS        bool `json:"tls"`
		HTTP       bool `json:"http"`
		H2         bool `json:"h2"`
		ParseError bool `json:"parse_error"`
	} `json:"view"`
	Fingerprints struct {
		JA4      *string `json:"ja4"`
		Akamai   *string `json:"akamai"`
		JA4H     *string `json:"ja4h"`
		JA4T     *string `json:"ja4t"`
		UAFamily *string `json:"ua_family"`
	} `json:"fingerprints"`
	RulesVersion string `json:"rules_version"`
	ListsVersion string `json:"lists_version"`
	Subject      struct {
		Kind     string    `json:"kind"`
		Site     *string   `json:"site"`
		Src      *endpoint `json:"src"`
		DstPort  *int      `json:"dst_port"`
		FsConnID *string   `json:"fs_conn_id"`
		ConnID   *string   `json:"conn_id"`
		ProbeID  *string   `json:"probe_id"`
	} `json:"subject"`
}

func (v *botVerdict) ids() []string {
	out := make([]string, 0, len(v.Signals))
	for _, s := range v.Signals {
		out = append(out, s.ID)
	}
	return out
}

func (v *botVerdict) has(id string) bool { return slices.Contains(v.ids(), id) }

func (v *botVerdict) String() string {
	var sig []string
	for _, s := range v.Signals {
		sig = append(sig, fmt.Sprintf("%s(%d: %s)", s.ID, s.Weight, s.Detail))
	}
	return fmt.Sprintf("%s score %d [%s] view tcp=%v tls=%v http=%v h2=%v", v.Class, v.Score, strings.Join(sig, ", "),
		v.View.TCP, v.View.TLS, v.View.HTTP, v.View.H2)
}

func decodeVerdict(t *testing.T, what string, r botResp) botVerdict {
	t.Helper()
	var v botVerdict
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("%s: %d %v %.300s", what, r.status, err, r.body)
	}
	return v
}

// f8Expected é a tabela da ADR 0057 item 1 (ja4db desligada, IP residencial, sem comportamento; rules v1.3: a v1.2 da ADR
// 0058 dá o known_client a Chrome e Firefox e a v1.3 da ADR 0060 o ja4h_library às bibliotecas pelo probe).
var f8Expected = map[string]struct {
	class   string
	signals []string
}{
	"curl":            {"bot", []string{"ja4h_library", "library_client"}},
	"go":              {"bot", []string{"ja4h_library", "library_client"}},
	"python-requests": {"bot", []string{"ja4h_library", "library_client"}},
	"chrome":          {"human", []string{"known_client"}},
	"firefox":         {"human", []string{"known_client"}},
	"googlebot":       {"bot", []string{"ja4h_library", "ua_claims_crawler"}},
}

// checkClass confere classe, sinais e versões. Além dos sinais da tabela podem aparecer tunnel_mss (peso 5, só
// informativo: o grampo de MSS do caminho do Mac ao finger-01, ADR 0058 contexto) e os de comportamento
// (no_reuse, rate_high...), que o próprio e2e cria no IP do gerador ao repetir conexões na mesma hora; a classe
// tem de ser a da tabela mesmo com eles.
func checkClass(t *testing.T, client string, v botVerdict) {
	t.Helper()
	want := f8Expected[client]
	var got []string
	for _, s := range v.Signals {
		if s.ID != "tunnel_mss" && s.Kind != "behavior" {
			got = append(got, s.ID)
		}
	}
	sort.Strings(got)
	ws := slices.Clone(want.signals)
	sort.Strings(ws)
	if v.Class != want.class || !slices.Equal(got, ws) {
		t.Errorf("%s: veredito %s; esperado %s com %v (ADR 0057 item 1, rules %s)", client, v.String(), want.class, ws, rules.RulesVersion)
	}
	// a versão das regras é a do código desta árvore (o bot implantado tem de ser o mesmo)
	if v.RulesVersion != rules.RulesVersion {
		t.Errorf("%s: rules_version %q, esperado %s", client, v.RulesVersion, rules.RulesVersion)
	}
	if v.ListsVersion == "" || v.ListsVersion == "none" {
		t.Errorf("%s: lists_version %q", client, v.ListsVersion)
	}
}

// ---------------------------------------------------------------- feed

type f8Event struct {
	at time.Time
	v  botVerdict
}

type f8Feed struct {
	mu   sync.Mutex
	evs  []f8Event
	done chan struct{}
}

// startFeed abre GET /bot/v1/stream com a chave e guarda os vereditos com o instante de chegada.
func startFeed(t *testing.T, k *botKey) *f8Feed {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, botBase+"/stream", nil)
	req.Header.Set("Authorization", "Bearer "+k.secret)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		cancel()
		t.Fatalf("stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()
		t.Fatalf("stream: %d %s", resp.StatusCode, b)
	}
	f := &f8Feed{done: make(chan struct{})}
	go func() {
		defer close(f.done)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				event = v
				continue
			}
			if v, ok := strings.CutPrefix(line, "data: "); ok && event == "verdict" {
				var e struct {
					Verdict botVerdict `json:"verdict"`
				}
				if json.Unmarshal([]byte(v), &e) == nil {
					f.mu.Lock()
					f.evs = append(f.evs, f8Event{at: time.Now(), v: e.Verdict})
					f.mu.Unlock()
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = resp.Body.Close()
		<-f.done
	})
	return f
}

// wait espera até d por um veredito que case e devolve a latência desde trigger.
func (f *f8Feed) wait(trigger time.Time, d time.Duration, match func(*botVerdict) bool) (time.Duration, *botVerdict) {
	deadline := time.Now().Add(d)
	for {
		f.mu.Lock()
		for i := range f.evs {
			if !f.evs[i].at.Before(trigger) && match(&f.evs[i].v) {
				e := f.evs[i]
				f.mu.Unlock()
				return e.at.Sub(trigger), &e.v
			}
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkFeed confere que o veredito chegou ao feed em ≤ 1 s (spec 018 RNF-01, último item).
func checkFeed(t *testing.T, f *f8Feed, trigger time.Time, what string, match func(*botVerdict) bool) {
	t.Helper()
	lat, v := f.wait(trigger, 3*time.Second, match)
	switch {
	case v == nil:
		t.Errorf("feed: veredito de %s não chegou em 3 s", what)
	case lat > time.Second:
		t.Errorf("feed: veredito de %s chegou em %v (> 1 s)", what, lat.Round(time.Millisecond))
	default:
		t.Logf("feed: veredito de %s (%s) em %v", what, v.Class, lat.Round(time.Millisecond))
	}
}

func fsConn(id string) func(*botVerdict) bool {
	return func(v *botVerdict) bool { return v.Subject.FsConnID != nil && *v.Subject.FsConnID == id }
}

// ---------------------------------------------------------------- clientes

// f8Client abre o probe id; origin = com o Origin (Referer nos navegadores) de um domínio da chave.
type f8Client struct {
	name  string
	needs string
	run   func(ctx context.Context, id string, origin bool) error
}

func probeURL(id string) string { return "https://" + probeHost(id) + onTLS + "/p/" + id + "/" }

func f8Curl(extra ...string) func(ctx context.Context, id string, origin bool) error {
	return func(ctx context.Context, id string, origin bool) error {
		args := append([]string{"-4", "-sS", "-o", "/dev/null", "--max-time", "20", "--http2"}, extra...)
		if origin {
			args = append(args, "-H", "Origin: https://"+f8Site)
		}
		out, err := exec.CommandContext(ctx, curlOpenSSL, append(args, probeURL(id))...).CombinedOutput() //nolint:gosec // cliente local
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
}

func f8Go(ctx context.Context, id string, origin bool) error {
	tr := &http.Transport{ForceAttemptHTTP2: true, Protocols: new(http.Protocols)}
	tr.Protocols.SetHTTP2(true)
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probeURL(id), nil)
	if origin {
		req.Header.Set("Origin", "https://"+f8Site)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// f8Python é o pythonRequestsRun com o Origin opcional (requests acrescenta o campo depois dos padrões).
func f8Python(ctx context.Context, id string, origin bool) error {
	const script = `import socket, sys, warnings
warnings.filterwarnings("ignore")
import urllib3.util.connection as c
c.allowed_gai_family = lambda: socket.AF_INET
import requests
h = {"Origin": sys.argv[2]} if len(sys.argv) > 2 else {}
r = requests.get(sys.argv[1], headers=h, timeout=20)
r.raise_for_status()
`
	args := []string{"-c", script, probeURL(id)}
	if origin {
		args = append(args, "https://"+f8Site)
	}
	out, err := exec.CommandContext(ctx, pythonBin, args...).CombinedOutput() //nolint:gosec // Python local
	if err != nil {
		return fmt.Errorf("%w: %.500s", err, out)
	}
	return nil
}

// chromeUA é o User-Agent do Chrome de desktop da mesma versão: o headless declara HeadlessChrome (ua_automation,
// ADR 0057), e o caso "Chrome" é o navegador de uma pessoa com a mesma pilha.
func chromeUA() string {
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
		chromeVersion() + ".0.0.0 Safari/537.36"
}

// f8Chrome abre o probe direto ou pela página local (iframe; o Referer é http://fs-e2e.localhost:porta/).
func f8Chrome(page func(string) string) func(ctx context.Context, id string, origin bool) error {
	return func(ctx context.Context, id string, origin bool) error {
		dir, err := os.MkdirTemp("", "fs-e2e-chrome-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir) //nolint:errcheck // perfil descartável
		u := probeURL(id)
		if origin {
			u = page(id)
		}
		args := []string{
			"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-quic",
			"--user-data-dir=" + dir, "--user-agent=" + chromeUA(), "--dump-dom", u,
		}
		out, err := exec.CommandContext(ctx, chromeBin, args...).CombinedOutput() //nolint:gosec // navegador local
		if err != nil {
			return fmt.Errorf("%w: %.300s", err, out)
		}
		return nil
	}
}

func f8Firefox(page func(string) string) func(ctx context.Context, id string, origin bool) error {
	run := firefoxPrefsRun(func(host string) []string {
		return append(ffTCP(true)(host), `"network.dns.localDomains", "`+f8Local+`"`)
	})
	return func(ctx context.Context, id string, origin bool) error {
		u := probeURL(id)
		if origin {
			u = page(id)
		}
		return run(ctx, u, os.DevNull)
	}
}

func f8Clients(page func(string) string) []f8Client {
	return []f8Client{
		{name: "curl", needs: curlOpenSSL, run: f8Curl()},
		{name: "go", run: f8Go},
		{name: "python-requests", needs: pythonBin, run: f8Python},
		{name: "chrome", needs: chromeBin, run: f8Chrome(page)},
		{name: "firefox", needs: firefoxBin, run: f8Firefox(page)},
		{name: "googlebot", needs: curlOpenSSL, run: f8Curl("-A", googlebotUA)},
	}
}

// startPage serve a página local que abre o probe num iframe e devolve a URL dela para um probe id.
func startPage(t *testing.T) func(string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/f8/")
		if !probeIDRe(id) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><title>f8 %[1]s</title><iframe src=\"%[2]s\"></iframe>\n", id, probeURL(id))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	return func(id string) string { return fmt.Sprintf("http://%s:%d/f8/%s", f8Local, port, id) }
}

func probeIDRe(s string) bool {
	if len(s) < 8 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- registro do espelho

// f8Conn é o registro da conexão do probe com o que o traefix simulado reaproveita.
type f8Conn struct {
	ConnID string   `json:"conn_id"`
	Src    endpoint `json:"src"`
	Dst    endpoint `json:"dst"`
	TLS    *struct {
		ClientHelloB64 string   `json:"client_hello_b64"`
		JA4            string   `json:"ja4"`
		ALPN           []string `json:"alpn"`
	} `json:"tls"`
	TCP *struct {
		JA4T *string `json:"ja4t"`
	} `json:"tcp"`
	HTTP []struct {
		Fields      [][4]string `json:"fields"`
		JA4H        *string     `json:"ja4h"`
		RequestLine struct {
			Version string `json:"version"`
		} `json:"request_line"`
	} `json:"http"`
	HTTP2 *struct {
		Akamai  string `json:"akamai"`
		Streams []struct {
			Fields []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
			JA4H *string `json:"ja4h"`
		} `json:"streams"`
	} `json:"http2"`
}

// f8App é a visão de aplicação de um cliente como o traefix a mandaria (spec 019 RF-03 e RF-04).
type f8App struct {
	client      string
	pub         string // IP público (IPv4) do gerador, o das conexões ao traefik-app
	hello       []byte
	h2Prefix    []byte // nil no HTTP/1.1
	alpnOffered []string
	proto       string // h1 | h2
	httpVersion string
	names       []string
	fields      map[string]string
	ua          string
	ja4h        string
	ja4         string // do espelho
	akamai      string // do espelho ("" no h1)
}

// allowedField são os campos com valor no resumo da requisição (spec 019 RF-04).
func allowedField(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "user-agent", "accept", "accept-language", "accept-encoding":
		return true
	}
	return strings.HasPrefix(n, "sec-ch-ua") || strings.HasPrefix(n, "sec-fetch-")
}

// probeApp abre o probe com o cliente (sem Origin) e monta a visão de aplicação da primeira conexão com
// requisição: ClientHello do registro, prefixo h2 do fluxo decifrado (/raw?dir=in) e o resumo da requisição.
func probeApp(t *testing.T, cl f8Client) f8App {
	t.Helper()
	id := newID(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := cl.run(ctx, id, false); err != nil {
		t.Fatalf("%s: %v", cl.name, err)
	}
	return appFromProbe(t, cl.name, id)
}

// appFromProbe monta a visão de aplicação a partir do registro do probe já aberto.
func appFromProbe(t *testing.T, client, id string) f8App {
	t.Helper()
	p := waitProbe(t, id, readyTLSRequest)
	var c f8Conn
	for _, pc := range p.conns(portTLS) {
		if pc.TLS != nil && len(pc.HTTP)+h2Streams(pc) > 0 {
			get(t, "/connections/"+pc.ConnID, &c)
			break
		}
	}
	if c.TLS == nil {
		t.Fatalf("%s: probe %s sem conexão TLS com requisição", client, id)
	}
	a := f8App{client: client, pub: c.Src.IP, hello: b64(t, c.TLS.ClientHelloB64), alpnOffered: c.TLS.ALPN, ja4: c.TLS.JA4, fields: map[string]string{}}
	add := func(name, value string) {
		a.names = append(a.names, name)
		if allowedField(name) {
			a.fields[name] = value
		}
		if strings.EqualFold(name, "user-agent") {
			a.ua = value
		}
	}
	switch {
	case c.HTTP2 != nil && len(c.HTTP2.Streams) > 0:
		a.proto, a.httpVersion, a.akamai = "h2", "HTTP/2.0", c.HTTP2.Akamai
		for _, f := range c.HTTP2.Streams[0].Fields {
			if !strings.HasPrefix(f.Name, ":") {
				add(f.Name, f.Value)
			}
		}
		a.ja4h = deref(c.HTTP2.Streams[0].JA4H)
		a.h2Prefix = h2PrefixOf(rawStream(t, c.ConnID, "in"))
		if a.h2Prefix == nil {
			t.Fatalf("%s: %s sem prefixo h2 completo no fluxo do cliente", client, c.ConnID)
		}
	case len(c.HTTP) > 0:
		a.proto, a.httpVersion = "h1", c.HTTP[0].RequestLine.Version
		for _, f := range c.HTTP[0].Fields {
			add(f[0], f[2])
		}
		a.ja4h = deref(c.HTTP[0].JA4H)
	}
	if a.ja4h == "" {
		t.Fatalf("%s: %s sem ja4h", client, c.ConnID)
	}
	return a
}

func readyTLSRequest(p *probeResp) bool {
	for _, c := range p.conns(portTLS) {
		if c.TLS != nil && len(c.HTTP)+h2Streams(c) > 0 {
			return true
		}
	}
	return false
}

// h2PrefixOf devolve os bytes do cliente depois do prefácio até o fim do primeiro HEADERS (com os CONTINUATION),
// como o traefix os manda (spec 019 RF-03); nil se o fluxo não tem isso inteiro.
func h2PrefixOf(in []byte) []byte {
	if !bytes.HasPrefix(in, []byte(h2Preface)) {
		return nil
	}
	const (
		frameHeaders, frameContinuation = 0x1, 0x9
		flagEndHeaders                  = 0x4
	)
	off := len(h2Preface)
	for off+9 <= len(in) {
		n := int(in[off])<<16 | int(in[off+1])<<8 | int(in[off+2])
		typ, flags := in[off+3], in[off+4]
		end := off + 9 + n
		if end > len(in) {
			return nil
		}
		off = end
		if (typ == frameHeaders || typ == frameContinuation) && flags&flagEndHeaders != 0 {
			return in[len(h2Preface):off]
		}
	}
	return nil
}

// clientHelloOf devolve os registros TLS do começo do fluxo até o fim da mensagem ClientHello.
func clientHelloOf(in []byte) []byte {
	var hs []byte
	off := 0
	for off+5 <= len(in) && in[off] == 0x16 {
		n := int(in[off+3])<<8 | int(in[off+4])
		if off+5+n > len(in) {
			return nil
		}
		hs = append(hs, in[off+5:off+5+n]...)
		off += 5 + n
		if len(hs) >= 4 && len(hs) >= 4+(int(hs[1])<<16|int(hs[2])<<8|int(hs[3])) {
			return in[:off]
		}
	}
	return nil
}

// ---------------------------------------------------------------- traefix simulado

// f8Origin é a conexão ao traefik-app como o store a viu (a origem pública, depois do NAT).
type f8Origin struct {
	connID  string
	src     endpoint
	dstIP   string
	started time.Time
}

// replayHello abre uma conexão real ao traefik-app, manda o ClientHello do cliente, lê a resposta do servidor
// (ServerHello) e fecha: a visão IP/TCP do store é a deste Mac, a mesma de qualquer cliente dele.
func replayHello(t *testing.T, hello []byte) (localPort int, at time.Time) {
	t.Helper()
	at = time.Now()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort(vps4, strconv.Itoa(traefikPort)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial traefik-app: %v", err)
	}
	defer c.Close() //nolint:errcheck // fim da conexão
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("ClientHello ao traefik-app: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1024)); err != nil {
		t.Logf("AVISO: traefik-app não respondeu ao ClientHello: %v", err)
	}
	return c.LocalAddr().(*net.TCPAddr).Port, at
}

// storeOrigin acha no store a conexão do IP do gerador à 443 aberta depois de at: a da mesma porta, se o NAT a
// manteve; senão a mais recente ainda não usada (o NAT troca a porta).
func storeOrigin(t *testing.T, pub string, localPort int, at time.Time, used map[string]bool) f8Origin {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var cs []struct {
			ConnID  string   `json:"conn_id"`
			Src     endpoint `json:"src"`
			Dst     endpoint `json:"dst"`
			Started string   `json:"started"`
		}
		get(t, "/connections?src_ip="+url.QueryEscape(pub)+"&dst_port=443&limit=1000&since="+since(at.Add(-2*time.Second)), &cs)
		var best *f8Origin
		for _, c := range cs {
			st, err := time.Parse(time.RFC3339Nano, c.Started)
			if err != nil || c.Src.IP != pub || c.Dst.Port != traefikPort || used[c.ConnID] {
				continue
			}
			o := f8Origin{connID: c.ConnID, src: c.Src, dstIP: c.Dst.IP, started: st}
			if c.Src.Port == localPort {
				best = &o
				break
			}
			if best == nil || st.After(best.started) {
				best = &o
			}
		}
		if best != nil {
			used[best.connID] = true
			return *best
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("store sem a conexão de %s à %d depois de %s", pub, traefikPort, at.Format(time.RFC3339Nano))
	return f8Origin{}
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// traefixConn é o registro type=connection (spec 019 RF-03).
func traefixConn(id string, o f8Origin, a f8App) map[string]any {
	alpn := "http/1.1"
	if a.proto == "h2" {
		alpn = "h2"
	}
	r := map[string]any{
		"type": "connection", "fs_conn_id": id, "ts": ts(o.started),
		"src": o.src, "dst": endpoint{IP: o.dstIP, Port: traefikPort}, "entry_point": "websecure",
		"sni": vpsHost, "alpn_offered": a.alpnOffered, "alpn": alpn, "tls_version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256",
		"client_hello": base64.StdEncoding.EncodeToString(a.hello),
	}
	if a.h2Prefix != nil {
		r["h2_prefix"] = base64.StdEncoding.EncodeToString(a.h2Prefix)
	}
	return r
}

// traefixRequest é o registro type=request (spec 019 RF-04).
func traefixRequest(id string, o f8Origin, a f8App, n int) map[string]any {
	start := o.started.Add(time.Duration(50+n*10) * time.Millisecond)
	return map[string]any{
		"type": "request", "fs_conn_id": id, "ts": ts(start), "ended": ts(start.Add(5 * time.Millisecond)),
		"src": o.src, "dst": endpoint{IP: o.dstIP, Port: traefikPort},
		"proto": a.proto, "method": "GET", "authority": vpsHost, "path": "/", "http_version": a.httpVersion,
		"field_names": a.names, "fields": a.fields, "cookie_names": []string{}, "ja4h": a.ja4h, "status": 200,
		"router": "fs-e2e@internal", "service": "fs-e2e@internal",
	}
}

// ingest manda o lote ao bot e confere que todos os registros entraram.
func ingest(t *testing.T, k *botKey, records ...map[string]any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"sender": "v3.6.2-traefix.e2e", "records": records})
	if err != nil {
		t.Fatal(err)
	}
	r := botDo(t, http.MethodPost, "/ingest/traefik", k, nil, b)
	var res struct{ Accepted, Rejected int }
	_ = json.Unmarshal(r.body, &res)
	if r.status != http.StatusAccepted || res.Accepted != len(records) || res.Rejected != 0 {
		t.Fatalf("ingest: %d %s (esperado 202 com %d aceitos)", r.status, r.body, len(records))
	}
}

// verdictBySource é o GET /bot/v1/verdict pela origem pública da conexão.
func verdictBySource(t *testing.T, k *botKey, o f8Origin, site string) botResp {
	t.Helper()
	return botDo(t, http.MethodGet, fmt.Sprintf("/verdict?src_ip=%s&src_port=%d&site=%s&wait=1000",
		url.QueryEscape(o.src.IP), o.src.Port, url.QueryEscape(site)), k, nil, nil)
}

// checkMirror confere JA4 e Akamai do bot (calculados dos bytes do ingest) contra os do espelho.
func checkMirror(t *testing.T, a f8App, v botVerdict) {
	t.Helper()
	if got := deref(v.Fingerprints.JA4); got != a.ja4 {
		t.Errorf("%s: ja4 do bot %q, espelho %q", a.client, got, a.ja4)
	}
	if a.akamai != "" {
		if got := deref(v.Fingerprints.Akamai); got != a.akamai {
			t.Errorf("%s: akamai do bot %q, espelho %q", a.client, got, a.akamai)
		}
	}
}

// ---------------------------------------------------------------- forwardAuth

// authHeaders são os cabeçalhos que o traefix manda ao forwardAuth (spec 019 RF-06 e RF-07a): os X-Fs-* da conexão,
// os X-Forwarded-* da requisição e os campos do visitante (sem Cookie e Authorization).
func authHeaders(id string, o f8Origin, a f8App, ja4h bool) map[string]string {
	h := map[string]string{
		"X-Forwarded-Method": "GET", "X-Forwarded-Host": vpsHost, "X-Forwarded-Uri": "/", "X-Forwarded-Proto": "https",
		"X-Fs-Src-Ip": o.src.IP, "X-Fs-Src-Port": strconv.Itoa(o.src.Port), "X-Fs-Dst-Port": strconv.Itoa(traefikPort),
		"X-Fs-Conn-Id": id, "X-Fs-Proto": a.proto,
	}
	for n, v := range a.fields {
		h[n] = v
	}
	if ja4h {
		h["X-Fs-Ja4h"] = a.ja4h
	}
	return h
}

// newTraefixConn abre a conexão real ao traefik-app com o ClientHello do cliente e manda o registro de conexão.
func newTraefixConn(t *testing.T, k *botKey, a f8App, used map[string]bool) (string, f8Origin) {
	t.Helper()
	port, at := replayHello(t, a.hello)
	o := storeOrigin(t, a.pub, port, at, used)
	id := ulid.Make().String()
	ingest(t, k, traefixConn(id, o, a))
	return id, o
}

// checkNoVerdict confere que a resposta de erro não traz X-Fs-Verdict e tem o código esperado (ADR 0058 item 3).
func checkNoVerdict(t *testing.T, what string, r botResp, status int, code string) {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	if r.status != status || e.Error != code {
		t.Errorf("%s: %d %s, esperado %d %s", what, r.status, r.body, status, code)
	}
	if v := r.header.Values("X-Fs-Verdict"); len(v) > 0 {
		t.Errorf("%s: erro com X-Fs-Verdict %v (ADR 0058 item 3)", what, v)
	}
}

// ---------------------------------------------------------------- teste

// TestF8Bot roda os itens 1–5 da task 284 em ordem (o feed fica aberto o tempo todo). A rodada de casamento vem
// depois do forwardAuth (as 100 conexões dela dão rate_high/no_reuse ao IP do gerador, que mudariam o suspect da
// primeira requisição sem X-Fs-Ja4h), e o forget no fim.
func TestF8Bot(t *testing.T) {
	pub := macIPv4(t)
	key := newBotKey(t, "--rate", "100", "--burst", "200")
	feed := startFeed(t, key)
	page := startPage(t)
	clients := f8Clients(page)
	apps := map[string]f8App{}
	var appsMu sync.Mutex
	used := map[string]bool{}

	t.Run("probe", func(t *testing.T) {
		for _, cl := range clients {
			t.Run(cl.name, func(t *testing.T) {
				t.Parallel()
				if cl.needs != "" {
					if _, err := os.Stat(cl.needs); err != nil {
						t.Skipf("%s não está instalado nesta máquina", cl.needs)
					}
				}
				id := newID(t)
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				if err := cl.run(ctx, id, true); err != nil {
					t.Fatalf("%s: %v", cl.name, err)
				}
				done := time.Now()
				p := waitProbe(t, id, readyTLSRequest)
				r := botDo(t, http.MethodGet, "/probes/"+id+"/verdict?wait=1000", key, nil, nil)
				if r.status != http.StatusOK {
					t.Fatalf("probe verdict %s: %d %s", id, r.status, r.body)
				}
				v := decodeVerdict(t, "probe verdict", r)
				t.Logf("%s probe %s: %s", cl.name, id, v.String())
				checkClass(t, cl.name, v)
				if v.Subject.Kind != "probe" || deref(v.Subject.ProbeID) != id {
					t.Errorf("subject %+v, esperado probe %s", v.Subject, id)
				}
				if s := deref(v.Subject.Site); s != f8Site && s != f8Local {
					t.Errorf("subject.site %q, esperado o domínio do Origin/Referer", s)
				}
				if !v.View.TCP || !v.View.TLS || !v.View.HTTP {
					t.Errorf("view %+v: o probe tem as visões IP/TCP, TLS e HTTP do espelho", v.View)
				}
				var ja4s []string
				for _, c := range p.conns(portTLS) {
					if c.TLS != nil {
						ja4s = append(ja4s, c.TLS.JA4)
					}
				}
				if !slices.Contains(ja4s, deref(v.Fingerprints.JA4)) {
					t.Errorf("ja4 do veredito %q fora dos do espelho %v", deref(v.Fingerprints.JA4), ja4s)
				}
				// o veredito por probe é calculado na consulta e fica fora do feed e do webhook (ADR 0060 item 2):
				// nenhum VerdictEvent do probe pode chegar ao feed na janela de 2 s
				if lat, fv := feed.wait(done, 2*time.Second, func(v *botVerdict) bool { return deref(v.Subject.ProbeID) == id }); fv != nil {
					t.Errorf("veredito do probe %s chegou ao feed em %v (ADR 0060 item 2: o probe não vai ao feed)", id, lat.Round(time.Millisecond))
				}
			})
		}
	})

	t.Run("traefix-sim", func(t *testing.T) {
		for _, cl := range clients {
			t.Run(cl.name, func(t *testing.T) {
				if cl.needs != "" {
					if _, err := os.Stat(cl.needs); err != nil {
						t.Skipf("%s não está instalado nesta máquina", cl.needs)
					}
				}
				a := probeApp(t, cl)
				// o probe pode ter ido por IPv6 (Go e Chrome preferem); a conexão ao traefik-app é sempre IPv4
				a.pub = pub
				appsMu.Lock()
				apps[cl.name] = a
				appsMu.Unlock()
				port, at := replayHello(t, a.hello)
				o := storeOrigin(t, pub, port, at, used)
				id := ulid.Make().String()
				trigger := time.Now()
				ingest(t, key, traefixConn(id, o, a), traefixRequest(id, o, a, 0))
				r := verdictBySource(t, key, o, vpsHost)
				if r.status != http.StatusOK {
					t.Fatalf("verdict %s:%d: %d %s", o.src.IP, o.src.Port, r.status, r.body)
				}
				v := decodeVerdict(t, "verdict", r)
				t.Logf("%s traefix %s (store %s, %s:%d): %s", cl.name, id, o.connID, o.src.IP, o.src.Port, v.String())
				checkClass(t, cl.name, v)
				if !v.View.TCP || deref(v.Subject.ConnID) != o.connID {
					t.Errorf("casamento: view.tcp=%v conn_id %q, esperado %s", v.View.TCP, deref(v.Subject.ConnID), o.connID)
				}
				if v.View.ParseError {
					t.Errorf("parse_error nos bytes do cliente")
				}
				checkMirror(t, a, v)
				checkFeed(t, feed, trigger, cl.name+" pelo ingest", fsConn(id))
			})
		}
	})

	t.Run("forwardauth", func(t *testing.T) {
		a, ok := apps["curl"]
		if !ok {
			t.Skip("sem a visão do curl (traefix-sim/curl não rodou)")
		}
		block := newBotKey(t, "--mode", "block")

		t.Run("observe-ja4h", func(t *testing.T) {
			id, o := newTraefixConn(t, key, a, used)
			trigger := time.Now()
			r := botDo(t, http.MethodGet, "/auth", key, authHeaders(id, o, a, true), nil)
			v := decodeVerdict(t, "auth", r)
			t.Logf("auth observe com X-Fs-Ja4h: %d %s", r.status, v.String())
			if r.status != http.StatusOK || r.header.Get("X-Fs-Verdict") != v.Class || r.header.Get("X-Fs-Score") != strconv.Itoa(v.Score) {
				t.Errorf("auth: %d X-Fs-Verdict %q X-Fs-Score %q, esperado 200 com o veredito do corpo", r.status,
					r.header.Get("X-Fs-Verdict"), r.header.Get("X-Fs-Score"))
			}
			if v.Class != "bot" || !v.has("ja4h_library") || !v.View.TCP {
				t.Errorf("primeira requisição do curl com X-Fs-Ja4h: %s; esperado bot com ja4h_library e view.tcp (ADR 0058 item 1)", v.String())
			}
			if got := r.header.Get("X-Fs-Signals"); got != strings.Join(v.ids(), ",") {
				t.Errorf("X-Fs-Signals %q, corpo %v", got, v.ids())
			}
			checkFeed(t, feed, trigger, "forwardAuth", fsConn(id))
		})

		t.Run("block-ja4h", func(t *testing.T) {
			id, o := newTraefixConn(t, block, a, used)
			r := botDo(t, http.MethodGet, "/auth", block, authHeaders(id, o, a, true), nil)
			v := decodeVerdict(t, "auth", r)
			t.Logf("auth block com X-Fs-Ja4h: %d %s", r.status, v.String())
			if r.status != http.StatusForbidden || r.header.Get("X-Fs-Verdict") != "bot" || r.header.Get("X-Fs-Score") == "" ||
				r.header.Get("X-Fs-Signals") == "" || v.Class != "bot" {
				t.Errorf("block: %d X-Fs-Verdict %q X-Fs-Score %q X-Fs-Signals %q; esperado 403 com os X-Fs-* do veredito bot (ADR 0058 itens 1 e 3)",
					r.status, r.header.Get("X-Fs-Verdict"), r.header.Get("X-Fs-Score"), r.header.Get("X-Fs-Signals"))
			}
		})

		t.Run("without-ja4h", func(t *testing.T) {
			id, o := newTraefixConn(t, key, a, used)
			r := botDo(t, http.MethodGet, "/auth", key, authHeaders(id, o, a, false), nil)
			v := decodeVerdict(t, "auth", r)
			t.Logf("primeira sem X-Fs-Ja4h: %d %s", r.status, v.String())
			if r.status != http.StatusOK || v.Class != "suspect" || v.has("ja4h_library") || !v.has("library_client") {
				t.Errorf("primeira requisição sem X-Fs-Ja4h: %d %s; esperado 200 suspect só com library_client", r.status, v.String())
			}
			ingest(t, key, traefixRequest(id, o, a, 0))
			r = botDo(t, http.MethodGet, "/auth", key, authHeaders(id, o, a, false), nil)
			v = decodeVerdict(t, "auth", r)
			t.Logf("segunda sem X-Fs-Ja4h, depois do ingest: %d %s", r.status, v.String())
			if r.status != http.StatusOK || v.Class != "bot" || !v.has("ja4h_library") {
				t.Errorf("segunda requisição depois do ingest: %d %s; esperado bot com o JA4H do ingest", r.status, v.String())
			}
		})
	})

	t.Run("errors", func(t *testing.T) {
		testBotErrors(t, key, apps, used)
	})

	t.Run("traefix-match", func(t *testing.T) {
		testTraefixMatch(t, key, feed, pub, used)
	})

	t.Run("forget", func(t *testing.T) {
		testForget(t, key, pub)
	})
}

// testTraefixMatch é a rodada de casamento: 100 conexões reais de um cliente Go ao traefik-app que grava o
// próprio ClientHello e o próprio prefixo h2; cada uma vira um lote do traefix com a origem pública vista pelo
// store, e o veredito pela origem tem de vir com view.tcp (≥ 99%) e JA4/Akamai iguais aos do espelho para o mesmo
// cliente (medido no probe).
func testTraefixMatch(t *testing.T, key *botKey, feed *f8Feed, pub string, used map[string]bool) {
	const rounds = 100
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// referência do espelho: o mesmo cliente no probe
	id := newID(t)
	if _, _, _, err := goH2Recorded(ctx, net.JoinHostPort(vps4, strconv.Itoa(portTLS)), probeHost(id), "/p/"+id+"/"); err != nil {
		t.Fatalf("go probe: %v", err)
	}
	ref := appFromProbe(t, "go", id)
	t.Logf("espelho (probe %s): ja4 %s akamai %s ja4h %s", id, ref.ja4, ref.akamai, ref.ja4h)
	matched, total := 0, 0
	var firstFeed sync.Once
	for i := range rounds {
		hello, prefix, port, err := goH2Recorded(ctx, net.JoinHostPort(vps4, strconv.Itoa(traefikPort)), vpsHost, "/")
		at := time.Now()
		if err != nil {
			t.Fatalf("conexão %d ao traefik-app: %v", i, err)
		}
		o := storeOrigin(t, pub, port, at.Add(-2*time.Second), used)
		a := ref
		a.client, a.hello, a.h2Prefix = "go", hello, prefix
		fid := ulid.Make().String()
		trigger := time.Now()
		ingest(t, key, traefixConn(fid, o, a), traefixRequest(fid, o, a, 0))
		r := verdictBySource(t, key, o, vpsHost)
		total++
		if r.status != http.StatusOK {
			t.Errorf("conexão %d (%s:%d): verdict %d %s", i, o.src.IP, o.src.Port, r.status, r.body)
			continue
		}
		v := decodeVerdict(t, "verdict", r)
		if v.View.TCP && deref(v.Subject.ConnID) == o.connID {
			matched++
		} else {
			t.Logf("conexão %d sem casamento: store %s %s:%d, veredito %s conn_id %q", i, o.connID, o.src.IP, o.src.Port, v.String(), deref(v.Subject.ConnID))
		}
		if v.View.ParseError {
			t.Errorf("conexão %d: parse_error nos bytes gravados", i)
		}
		checkMirror(t, a, v)
		if i == 0 {
			t.Logf("conexão 0: %s", v.String())
			checkClass(t, "go", v)
			firstFeed.Do(func() { checkFeed(t, feed, trigger, "go pelo ingest (rodada)", fsConn(fid)) })
		}
	}
	pct := 100 * float64(matched) / float64(total)
	t.Logf("casamento traefix ↔ store: %d de %d (%.1f%%)", matched, total, pct)
	if total < rounds || pct < 99 {
		t.Errorf("casamento %.1f%% em %d conexões, esperado ≥ 99%% em %d (spec 018 critérios de aceite)", pct, total, rounds)
	}
}

// goH2Recorded faz um GET h2 com crypto/tls e x/net/http2 gravando os bytes escritos: os do socket até o fim do
// handshake (ClientHello) e os decifrados (prefácio e frames). Devolve o ClientHello, o prefixo h2 e a porta local.
func goH2Recorded(ctx context.Context, addr, host, path string) (hello, prefix []byte, localPort int, err error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, nil, 0, err
	}
	defer c.Close() //nolint:errcheck // fim da conexão
	localPort = c.LocalAddr().(*net.TCPAddr).Port
	raw := &recConn{Conn: c, max: 16 << 10}
	tc := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, nil, localPort, err
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != "h2" {
		return nil, nil, localPort, fmt.Errorf("ALPN %q", p)
	}
	hello = clientHelloOf(raw.bytes())
	plain := &recConn{Conn: tc, max: 16 << 10}
	cc, err := (&http2.Transport{}).NewClientConn(plain) //nolint:staticcheck // o de net/http disca sozinho; aqui a conexão decifrada é envolvida para gravar o prefixo h2
	if err != nil {
		return nil, nil, localPort, err
	}
	defer cc.Close() //nolint:errcheck // fim da conexão
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, nil, localPort, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	prefix = h2PrefixOf(plain.bytes())
	if hello == nil || prefix == nil {
		return nil, nil, localPort, errors.New("ClientHello ou prefixo h2 incompleto na gravação")
	}
	return hello, prefix, localPort, nil
}

// recConn grava os primeiros max bytes escritos.
type recConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
	max int
}

func (c *recConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if n := c.max - len(c.buf); n > 0 {
		c.buf = append(c.buf, b[:min(len(b), n)]...)
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.buf)
}

// testBotErrors é o item 3: nenhum erro traz X-Fs-Verdict; 401, 404 indistinguível, 429 e os 400 da auth.
func testBotErrors(t *testing.T, key *botKey, apps map[string]f8App, used map[string]bool) {
	a, ok := apps["curl"]
	if !ok {
		t.Skip("sem a visão do curl (traefix-sim/curl não rodou)")
	}
	id, o := newTraefixConn(t, key, a, used)
	ingest(t, key, traefixRequest(id, o, a, 0))
	hdr := authHeaders(id, o, a, true)

	t.Run("401", func(t *testing.T) {
		checkNoVerdict(t, "auth sem chave", botDo(t, http.MethodGet, "/auth", nil, hdr, nil), http.StatusUnauthorized, "invalid_key")
		bogus := &botKey{secret: "fsk_" + strings.Repeat("a", 52)}
		checkNoVerdict(t, "auth com chave desconhecida", botDo(t, http.MethodGet, "/auth", bogus, hdr, nil), http.StatusUnauthorized, "invalid_key")
		checkNoVerdict(t, "verdict sem chave", verdictBySource(t, nil, o, vpsHost), http.StatusUnauthorized, "invalid_key")
	})

	t.Run("400", func(t *testing.T) {
		checkNoVerdict(t, "auth sem X-Fs-*", botDo(t, http.MethodGet, "/auth", key, map[string]string{
			"X-Forwarded-Host": vpsHost, "X-Forwarded-Uri": "/", "X-Forwarded-Method": "GET", "User-Agent": a.ua,
		}, nil), http.StatusBadRequest, "missing_fork_headers")
		other := maps(hdr)
		other["X-Forwarded-Host"] = f8Other
		checkNoVerdict(t, "auth com site fora da chave", botDo(t, http.MethodGet, "/auth", key, other, nil), http.StatusBadRequest, "bad_request")
	})

	t.Run("404", func(t *testing.T) {
		// domínio fora da chave × recurso inexistente: mesmo status, mesmo corpo, mesmos cabeçalhos (spec 020 RF-03)
		outside := verdictBySource(t, key, o, f8Other)
		missing := botDo(t, http.MethodGet, "/verdict?src_ip=192.0.2.1&src_port=1&site="+vpsHost+"&wait=0", key, nil, nil)
		sameNotFound(t, "verdict por origem", outside, missing)
		other := newBotKeyDomains(t, f8Other)
		sameNotFound(t, "verdict por fs_conn_id",
			botDo(t, http.MethodGet, "/verdict/conn/"+id, other, nil, nil),
			botDo(t, http.MethodGet, "/verdict/conn/"+ulid.Make().String(), other, nil, nil))
	})

	t.Run("429", func(t *testing.T) {
		slow := newBotKey(t, "--rate", "1", "--burst", "1")
		var last botResp
		for range 5 {
			if last = botDo(t, http.MethodGet, "/auth", slow, hdr, nil); last.status == http.StatusTooManyRequests {
				break
			}
		}
		checkNoVerdict(t, "auth acima do balde", last, http.StatusTooManyRequests, "rate_limited")
		if n, err := strconv.Atoi(last.header.Get("Retry-After")); err != nil || n < 1 {
			t.Errorf("Retry-After %q, esperado inteiro ≥ 1", last.header.Get("Retry-After"))
		}
	})
}

// newBotKeyDomains cria uma chave só com os domínios dados.
func newBotKeyDomains(t *testing.T, domains string) *botKey {
	t.Helper()
	sweepKeys.Do(func() { sweepBotKeys(t) })
	name := fmt.Sprintf("%s-%d", f8KeyName, time.Now().UnixNano())
	out, err := exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, //nolint:gosec // destino do teste
		botCLI+" key create --name "+name+" --domains "+domains).CombinedOutput()
	k := &botKey{}
	for l := range strings.Lines(string(out)) {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "id: "); ok {
			k.id = v
		}
		if v, ok := strings.CutPrefix(l, "key: "); ok {
			k.secret = v
		}
	}
	if k.id != "" {
		t.Cleanup(func() { revokeBotKey(t, k.id) })
	}
	if err != nil || !strings.HasPrefix(k.secret, "fsk_") {
		t.Fatalf("key create %s: %v", name, err)
	}
	time.Sleep(3 * time.Second)
	return k
}

func maps(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sameNotFound confere que duas respostas 404 são indistinguíveis (status, corpo e nomes de cabeçalho sem Date).
func sameNotFound(t *testing.T, what string, a, b botResp) {
	t.Helper()
	checkNoVerdict(t, what+" (fora da chave)", a, http.StatusNotFound, "not_found")
	checkNoVerdict(t, what+" (inexistente)", b, http.StatusNotFound, "not_found")
	names := func(h http.Header) []string {
		var out []string
		for n, v := range h {
			if n != "Date" {
				out = append(out, n+": "+strings.Join(v, ","))
			}
		}
		sort.Strings(out)
		return out
	}
	if !bytes.Equal(a.body, b.body) || !slices.Equal(names(a.header), names(b.header)) {
		t.Errorf("%s: 404 distinguível:\nfora da chave %v %s\ninexistente   %v %s", what, names(a.header), a.body, names(b.header), b.body)
	}
}

// testForget é o item 5: os agregados do IP do gerador aparecem em GET /bot/v1/ip/{ip} (flush a cada 5 s) e somem
// depois do forget pela CLI.
func testForget(t *testing.T, key *botKey, pub string) {
	type ipRep struct {
		Days []struct {
			Site     string `json:"site"`
			Requests int    `json:"requests"`
		} `json:"days"`
	}
	read := func() ipRep {
		r := botDo(t, http.MethodGet, "/ip/"+pub, key, nil, nil)
		if r.status != http.StatusOK {
			t.Fatalf("ip %s: %d %s", pub, r.status, r.body)
		}
		var rep ipRep
		if err := json.Unmarshal(r.body, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	deadline := time.Now().Add(20 * time.Second)
	rep := read()
	for len(rep.Days) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Second)
		rep = read()
	}
	if len(rep.Days) == 0 {
		t.Fatalf("ip %s sem agregados depois dos vereditos do traefix simulado (flush de 5 s)", pub)
	}
	t.Logf("antes do forget: %+v", rep.Days)
	out := remote(t, botCLI+" forget "+pub)
	t.Logf("forget: %s", out)
	if !strings.Contains(out, "service memory: reached") {
		t.Errorf("forget não chegou à memória do serviço: %s", out)
	}
	if rep = read(); len(rep.Days) != 0 {
		t.Errorf("ip %s ainda com agregados depois do forget: %+v", pub, rep.Days)
	}
}
