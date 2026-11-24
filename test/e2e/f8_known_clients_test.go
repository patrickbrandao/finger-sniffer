//go:build e2e

package e2e

// Medida da base própria (task 270, spec 018 "Base própria", ADR 0050 item 1): roda os clientes do
// TestF5Fingerprints (as mesmas funções de execução, com as mesmas opções) mais python-requests e o Chrome
// headless sem opções de protocolo além do QUIC desligado, e monta uma entrada de
// internal/bot/lists/known_clients.json por cliente com o registro do espelho. A conferência do registro com
// ja4/tshark/p0f fica no TestF5Fingerprints; aqui só se mede. Com FS_E2E_UPDATE=1 o arquivo é regravado
// (recordKnownClients); sem isso o conteúdo vai só para o log, com aviso quando a base não tem a medida.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// pythonBin é o Python do macOS, o que traz requests e urllib3 no site-packages do usuário.
var pythonBin = env("FS_E2E_PYTHON", "/usr/bin/python3")

// kcConn é o registro da conexão só com o que a base própria usa.
type kcConn struct {
	ConnID string   `json:"conn_id"`
	Dst    endpoint `json:"dst"`
	IP     *struct {
		TTLInitial int `json:"ttl_initial"`
	} `json:"ip"`
	TCP *struct {
		JA4T    *string `json:"ja4t"`
		OSGuess *string `json:"os_guess"`
	} `json:"tcp"`
	TLS  *kcTLS `json:"tls"`
	HTTP []struct {
		JA4H *string `json:"ja4h"`
	} `json:"http"`
	HTTP2 *struct {
		Akamai  string `json:"akamai"`
		Streams []struct {
			JA4H *string `json:"ja4h"`
		} `json:"streams"`
	} `json:"http2"`
	HTTP3 *struct {
		ClientHello *kcTLS `json:"client_hello"`
		Requests    []struct {
			JA4H *string `json:"ja4h"`
		} `json:"requests"`
	} `json:"http3"`
}

type kcTLS struct {
	JA4  string   `json:"ja4"`
	JA4R string   `json:"ja4_r"`
	ALPN []string `json:"alpn"`
}

// kcClient é um cliente medido: a família da spec 018 RF-06 e a versão (vazia = cliente ausente, pula).
type kcClient struct {
	f5Client
	family  string
	version func() string
}

var (
	chromeVersion  = sync.OnceValue(func() string { return numVersion(cmdLine(chromeBin, "--version"), 1) })
	firefoxVersion = sync.OnceValue(func() string { return numVersion(cmdLine(firefoxBin, "--version"), 1) })
	goVersion      = func() string { return numVersion(strings.TrimPrefix(runtime.Version(), "go"), 2) }
	// requests.__version__ (o User-Agent do python-requests leva essa versão)
	requestsVersion = sync.OnceValue(func() string {
		out, err := exec.Command(pythonBin, "-W", "ignore", "-c", "import requests; print(requests.__version__)").Output()
		if err != nil {
			return ""
		}
		return numVersion(string(out), 2)
	})
)

func curlVersion(bin string) func() string {
	return sync.OnceValue(func() string { return numVersion(strings.TrimPrefix(cmdLine(bin, "-V"), "curl "), 2) })
}

// pythonRequestsRun faz um GET com python-requests (urllib3, ssl do Python do macOS) por IPv4, como os curl.
// O ssl com LibreSSL não grava SSLKEYLOGFILE; requests só fala HTTP/1.1.
func pythonRequestsRun(ctx context.Context, url, _ string) error {
	const script = `import socket, sys, warnings
warnings.filterwarnings("ignore")
import urllib3.util.connection as c
c.allowed_gai_family = lambda: socket.AF_INET
import requests
r = requests.get(sys.argv[1], timeout=20)
r.raise_for_status()
if "conn_id: " not in r.text:
    sys.exit("página sem conn_id")
`
	out, err := exec.CommandContext(ctx, pythonBin, "-c", script, url).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %.500s", err, out)
	}
	return nil
}

// kcClients são os clientes do TestF5Fingerprints com a família e a versão, mais os da F8.
func kcClients(t *testing.T) []kcClient {
	t.Helper()
	fam := map[string]struct {
		family  string
		version func() string
	}{
		"curl-openssl h2":  {"curl", curlVersion(curlOpenSSL)},
		"curl-openssl h1":  {"curl", curlVersion(curlOpenSSL)},
		"curl-libressl h2": {"curl", curlVersion(curlLibreSSL)},
		"go h2":            {"go", goVersion},
		"go h1":            {"go", goVersion},
		"chrome h2":        {"chrome", chromeVersion},
		"chrome h1":        {"chrome", chromeVersion},
		"firefox h2":       {"firefox", firefoxVersion},
		"firefox h1":       {"firefox", firefoxVersion},
		"quic-go h3":       {"go", goVersion},
		"chrome h3":        {"chrome", chromeVersion},
		"firefox h3":       {"firefox", firefoxVersion},
	}
	if c := curlHTTP3(); c != "" {
		fam["curl h3"] = struct {
			family  string
			version func() string
		}{"curl", curlVersion(c)}
	}
	var cs []kcClient
	for _, cl := range f5Clients() {
		f, ok := fam[cl.name]
		if !ok {
			t.Logf("AVISO: cliente %q do TestF5Fingerprints sem família na base própria; fora da medida", cl.name)
			continue
		}
		cs = append(cs, kcClient{f5Client: cl, family: f.family, version: f.version})
	}
	return append(cs,
		kcClient{
			f5Client: f5Client{order: 90, name: "python-requests h1", needs: pythonBin, run: pythonRequestsRun},
			family:   "python", version: requestsVersion,
		},
		kcClient{
			// mesmo Chrome dos casos "chrome", com o User-Agent HeadlessChrome de quem o usa como robô
			f5Client: f5Client{order: 91, name: "headless h2", h2: true, keys: true, needs: chromeBin, run: chromeArgsRun("--disable-quic")},
			family:   "headless", version: chromeVersion,
		},
	)
}

// TestF8KnownClients mede a base própria de fingerprints (task 270).
func TestF8KnownClients(t *testing.T) {
	var (
		mu  sync.Mutex
		got []knownClient
	)
	t.Cleanup(func() {
		if len(got) == 0 {
			return
		}
		var health struct {
			Services map[string]struct {
				Commit string `json:"commit"`
			} `json:"services"`
		}
		get(t, "/health", &health)
		commit := health.Services["web"].Commit
		for i := range got {
			got[i].Commit = commit
		}
		path := knownClientsPath()
		old, err := readKnownClients(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range got {
			if !containsFP(old.Measured, k) {
				t.Logf("AVISO: base própria sem %s %s %s %s (regrave com FS_E2E_UPDATE=1)", k.Client, k.ClientVersion, k.Proto, k.JA4)
			}
		}
		b, wrote, err := recordKnownClients(path, got)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("base própria (%d medidas nesta execução, gravada=%v):\n%s", len(got), wrote, b)
		if errs := validateKnownClients(b); len(errs) > 0 {
			t.Errorf("base própria inválida: %v", errs)
		}
	})
	for _, cl := range kcClients(t) {
		t.Run(strings.ReplaceAll(cl.name, " ", "-"), func(t *testing.T) {
			t.Parallel()
			if cl.needs != "" {
				if _, err := os.Stat(cl.needs); err != nil {
					t.Skipf("%s não está instalado nesta máquina", cl.needs)
				}
			}
			ver := cl.version()
			if ver == "" {
				t.Skipf("%s: versão não encontrada (cliente ausente)", cl.name)
			}
			id := newID(t)
			url := "https://" + probeHost(id) + onTLS + "/p/" + id + "/"
			keylog := filepath.Join(t.TempDir(), "keys")
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			measuredAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
			if err := cl.run(ctx, url, keylog); err != nil {
				t.Fatalf("%s: %v", cl.name, err)
			}
			var c kcConn
			if cl.quic {
				get(t, "/connections/"+waitF5QUIC(t, id).ConnID, &c)
			} else {
				p := waitProbe(t, id, func(p *probeResp) bool {
					for _, c := range p.conns(portTLS) {
						if c.TLS != nil && len(c.HTTP)+h2Streams(c) > 0 {
							return true
						}
					}
					return false
				})
				// a primeira conexão com dados de aplicação (o preconnect do Chrome fica de fora)
				for _, pc := range p.conns(portTLS) {
					if pc.TLS != nil && len(pc.HTTP)+h2Streams(pc) > 0 {
						get(t, "/connections/"+pc.ConnID, &c)
						break
					}
				}
			}
			k, err := knownFrom(cl, ver, c)
			if err != nil {
				t.Fatalf("%s %s: %v", cl.name, c.ConnID, err)
			}
			k.MeasuredAt = measuredAt
			t.Logf("%s %s: ja4=%s ja4h_ab=%s ja4t=%s p0f_os=%s", cl.name, c.ConnID, k.JA4, k.JA4HAB, nullStr(k.JA4T), nullStr(k.P0FOS))
			mu.Lock()
			got = append(got, k)
			mu.Unlock()
		})
	}
}

// knownFrom monta a medida a partir do registro da conexão.
func knownFrom(cl kcClient, ver string, c kcConn) (knownClient, error) {
	k := knownClient{Client: cl.family, ClientVersion: ver, OS: "macos"} // todos os clientes rodam neste Mac
	var ja4h *string
	switch {
	case cl.quic:
		if c.HTTP3 == nil || c.HTTP3.ClientHello == nil || len(c.HTTP3.Requests) == 0 {
			return k, fmt.Errorf("sem http3.client_hello ou requisição")
		}
		k.Proto = "h3"
		k.JA4, k.JA4R, k.ALPN = c.HTTP3.ClientHello.JA4, c.HTTP3.ClientHello.JA4R, c.HTTP3.ClientHello.ALPN
		ja4h = c.HTTP3.Requests[0].JA4H
	default:
		if c.TLS == nil || c.TCP == nil {
			return k, fmt.Errorf("sem tls ou tcp")
		}
		k.JA4, k.JA4R, k.ALPN = c.TLS.JA4, c.TLS.JA4R, c.TLS.ALPN
		k.JA4T, k.P0FOS = c.TCP.JA4T, c.TCP.OSGuess
		if k.P0FOS != nil && *k.P0FOS == "" {
			k.P0FOS = nil
		}
		switch {
		case c.HTTP2 != nil && len(c.HTTP2.Streams) > 0:
			k.Proto = "h2"
			ak := c.HTTP2.Akamai
			k.Akamai = &ak
			ja4h = c.HTTP2.Streams[0].JA4H
		case len(c.HTTP) > 0:
			k.Proto = "h1"
			ja4h = c.HTTP[0].JA4H
		default:
			return k, fmt.Errorf("sem requisição h1 nem h2")
		}
		if cl.h2 != (k.Proto == "h2") {
			return k, fmt.Errorf("cliente %s negociou %s", cl.name, k.Proto)
		}
	}
	if k.ALPN == nil {
		k.ALPN = []string{}
	}
	if c.IP == nil {
		return k, fmt.Errorf("sem ip")
	}
	k.TTLInitial = c.IP.TTLInitial
	if ja4h == nil {
		return k, fmt.Errorf("sem ja4h")
	}
	p := strings.Split(*ja4h, "_")
	if len(p) < 2 {
		return k, fmt.Errorf("ja4h %q", *ja4h)
	}
	k.JA4HAB = p[0] + "_" + p[1]
	return k, nil
}

// containsFP diz se a base já tem a medida com as mesmas impressões.
func containsFP(ks []knownClient, k knownClient) bool {
	for _, o := range ks {
		if o.key() == k.key() && o.sameFingerprint(k) {
			return true
		}
	}
	return false
}
