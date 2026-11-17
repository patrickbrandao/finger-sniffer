//go:build e2e

package e2e

// Casos do traefix real da F8 (spec 017 RF-17, spec 019 "Critérios de aceite", ADR 0058; task 284 item 6). Rodam
// contra o router de teste do traefix no finger-01, que só existe depois da task 273: sem FS_E2E_TRAEFIX_URL todos
// pulam com aviso. O router de teste tem o espelho (web) como backend, então a página /p/<id>/ devolve o conn_id da
// conexão traefix → web e o registro dela no store mostra os campos que o backend recebeu (X-Fs-* inclusive).
//   - FS_E2E_TRAEFIX_URL: router com forwardAuth fingerSniffer em observe (failOpen, sem chave ou com chave observe);
//   - FS_E2E_TRAEFIX_BLOCK_URL: router com forwardAuth fingerSniffer e apiKey de uma chave em modo block;
//   - FS_E2E_TRAEFIX_REVOKED_URL: router com forwardAuth fingerSniffer, failOpen e apiKey de uma chave revogada;
//   - FS_E2E_TRAEFIX_STOP_BOT=1: autoriza parar o finger-sniffer-bot por alguns segundos (fail-open com o bot parado).

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	traefixURL        = os.Getenv("FS_E2E_TRAEFIX_URL")
	traefixBlockURL   = os.Getenv("FS_E2E_TRAEFIX_BLOCK_URL")
	traefixRevokedURL = os.Getenv("FS_E2E_TRAEFIX_REVOKED_URL")
)

// requireTraefix pula o caso enquanto o router de teste do traefix não existir (task 273).
func requireTraefix(t *testing.T, u string, name string) {
	t.Helper()
	if u == "" {
		t.Skipf("AVISO: traefix real ainda não está no finger-01 (task 273): defina %s para rodar este caso", name)
	}
}

var connIDLine = regexp.MustCompile(`(?m)^conn_id: ([0-9A-HJKMNP-TV-Z]{26})$`)

// traefixGet faz um GET de curl ao router e devolve o status, os cabeçalhos da resposta e os campos que o backend
// (o espelho) recebeu, pelo registro da conexão traefix → web no store.
func traefixGet(t *testing.T, base string, extra ...string) (int, http.Header, map[string]string) {
	t.Helper()
	id := newID(t)
	u := strings.TrimSuffix(base, "/") + "/p/" + id + "/"
	args := append([]string{"-4", "-sS", "-i", "--http2", "--max-time", "20"}, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, curlOpenSSL, append(args, u)...).CombinedOutput() //nolint:gosec // cliente local
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
	m := connIDLine.FindStringSubmatch(body)
	if m == nil {
		return status, h, nil
	}
	var rec struct {
		HTTP []struct {
			Fields [][4]string `json:"fields"`
		} `json:"http"`
		HTTP2 *struct {
			Streams []struct {
				Fields []struct{ Name, Value string } `json:"fields"`
			} `json:"streams"`
		} `json:"http2"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(api + "/connections/" + m[1]) //nolint:gosec,noctx // URL do teste
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("store sem a conexão do backend %s", m[1])
		}
		time.Sleep(500 * time.Millisecond)
	}
	get(t, "/connections/"+m[1], &rec)
	fields := map[string]string{}
	for _, r := range rec.HTTP {
		for _, f := range r.Fields {
			fields[strings.ToLower(f[0])] = f[2]
		}
	}
	if rec.HTTP2 != nil {
		for _, s := range rec.HTTP2.Streams {
			for _, f := range s.Fields {
				fields[strings.ToLower(f.Name)] = f.Value
			}
		}
	}
	return status, h, fields
}

// TestF8TraefixReal são os casos do traefix real (pulam até a task 273).
func TestF8TraefixReal(t *testing.T) {
	t.Run("observe", func(t *testing.T) {
		requireTraefix(t, traefixURL, "FS_E2E_TRAEFIX_URL")
		pub := macIPv4(t)
		status, _, f := traefixGet(t, traefixURL)
		if status != http.StatusOK || f == nil {
			t.Fatalf("router de teste: %d, campos do backend %v", status, f)
		}
		if f["x-fs-src-ip"] != pub || f["x-fs-conn-id"] == "" || f["x-fs-ja4h"] == "" {
			t.Errorf("backend sem os X-Fs-* da conexão: %v (IP do gerador %s)", f, pub)
		}
		if f["x-fs-verdict"] != "bot" {
			t.Errorf("curl pelo router em observe: X-Fs-Verdict %q, esperado bot (forwardAuth com X-Fs-Ja4h, ADR 0058)", f["x-fs-verdict"])
		}
		k := newBotKey(t)
		r := botDo(t, http.MethodGet, "/verdict/conn/"+f["x-fs-conn-id"]+"?wait=1000", k, nil, nil)
		v := decodeVerdict(t, "verdict/conn", r)
		if r.status != http.StatusOK || !v.View.TCP {
			t.Errorf("consulta pela conexão do traefix: %d %s; esperado view.tcp (casamento)", r.status, v.String())
		}
	})

	t.Run("forged-headers", func(t *testing.T) {
		requireTraefix(t, traefixURL, "FS_E2E_TRAEFIX_URL")
		pub := macIPv4(t)
		const forgedJA4H = "ge11cr99enus_000000000000_000000000000_000000000000"
		_, _, f := traefixGet(t, traefixURL, "-H", "X-Fs-Src-Ip: 203.0.113.7", "-H", "x-fs-ja4h: "+forgedJA4H,
			"-H", "X-Fs-Verdict: human", "-H", "X-FS-Conn-Id: 01ARZ3NDEKTSV4RRFFQ69G5FAV")
		if f == nil {
			t.Fatal("sem os campos do backend")
		}
		if f["x-fs-src-ip"] != pub || f["x-fs-ja4h"] == forgedJA4H || f["x-fs-verdict"] == "human" ||
			f["x-fs-conn-id"] == "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
			t.Errorf("X-Fs-* forjado chegou ao backend: %v (spec 019 RF-06)", f)
		}
	})

	t.Run("block-first-request", func(t *testing.T) {
		requireTraefix(t, traefixBlockURL, "FS_E2E_TRAEFIX_BLOCK_URL")
		status, h, _ := traefixGet(t, traefixBlockURL)
		if status != http.StatusForbidden || h.Get("X-Fs-Verdict") != "bot" {
			t.Errorf("curl na primeira requisição em block: %d X-Fs-Verdict %q, esperado 403 bot (ADR 0058 item 1)", status, h.Get("X-Fs-Verdict"))
		}
	})

	t.Run("fail-open-revoked-key", func(t *testing.T) {
		requireTraefix(t, traefixRevokedURL, "FS_E2E_TRAEFIX_REVOKED_URL")
		status, _, f := traefixGet(t, traefixRevokedURL)
		if status != http.StatusOK || f["x-fs-verdict"] != "unavailable" {
			t.Errorf("chave revogada no forwardAuth: %d X-Fs-Verdict %q, esperado 200 unavailable (401 sem X-Fs-Verdict é fail-open, ADR 0058 item 2)",
				status, f["x-fs-verdict"])
		}
	})

	t.Run("fail-open-bot-stopped", func(t *testing.T) {
		requireTraefix(t, traefixURL, "FS_E2E_TRAEFIX_URL")
		if os.Getenv("FS_E2E_TRAEFIX_STOP_BOT") != "1" {
			t.Skip("AVISO: defina FS_E2E_TRAEFIX_STOP_BOT=1 para parar o bot no finger-01 durante o caso")
		}
		remote(t, "systemctl stop finger-sniffer-bot")
		t.Cleanup(func() { remote(t, "systemctl start finger-sniffer-bot") })
		status, _, f := traefixGet(t, traefixURL)
		if status != http.StatusOK || f["x-fs-verdict"] != "unavailable" {
			t.Errorf("bot parado: %d X-Fs-Verdict %q, esperado 200 unavailable (fail-open, spec 019 RF-07)", status, f["x-fs-verdict"])
		}
	})
}
