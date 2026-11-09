//go:build e2e

package e2e

// Contrato das respostas de erro contra a vps602 (task 089): a mesma tabela do internal/store
// TestAPIErrorContract (que confere a tabela contra o openapi.yaml e cobre 500/503 com falhas provocadas), aqui
// só os casos sem falha, nas duas portas da API (9001 HTTP e 9000 HTTPS).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type apiErrorCase struct {
	Name    string            `json:"name"`
	Op      string            `json:"op"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Want    int               `json:"want"`
	Fault   string            `json:"fault"`
	Issue   string            `json:"issue"`
}

func loadAPIErrorCases(t *testing.T) []apiErrorCase {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "internal", "store", "testdata", "api-error-cases.json")) //nolint:gosec // repositório
	if err != nil {
		t.Fatal(err)
	}
	var tab struct {
		Cases []apiErrorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &tab); err != nil {
		t.Fatal(err)
	}
	return tab.Cases
}

// doAPIError faz a requisição; erro de transporte (store reiniciando por deploy em paralelo) é repetido por até
// ~45 s.
func doAPIError(t *testing.T, client *http.Client, base string, c apiErrorCase) (code int, ctype string, body []byte) {
	t.Helper()
	var last error
	for attempt := 0; attempt < 15; attempt++ {
		if attempt > 0 {
			time.Sleep(3 * time.Second)
		}
		req, err := http.NewRequest(c.Method, base+c.Path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "EOF") {
				last = err
				continue
			}
			t.Fatal(err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Content-Type"), b
	}
	t.Fatalf("%s %s%s: store não respondeu: %v", c.Method, base, c.Path, last)
	return 0, "", nil
}

// TestAPIErrorContractLive confere código e corpo das respostas de erro reais contra a regra do contrato
// (openapi 0.3.3, spec 004 "Erros da API"): 204 sem corpo no OPTIONS; nos demais, application/json com
// {"error": string}.
func TestAPIErrorContractLive(t *testing.T) {
	cases := loadAPIErrorCases(t)
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	https := strings.Replace(strings.Replace(api, "http://", "https://", 1), ":9001", ":9000", 1)
	for _, base := range []string{api, https} {
		root := strings.TrimSuffix(base, "/api/v1")
		for _, c := range cases {
			if c.Fault != "" {
				continue // só no teste unitário
			}
			t.Run(fmt.Sprintf("%s/%s", strings.SplitN(root, "://", 2)[0], c.Name), func(t *testing.T) {
				code, ctype, body := doAPIError(t, client, root, c)
				var bad []string
				if code != c.Want {
					bad = append(bad, fmt.Sprintf("código %d, esperava %d", code, c.Want))
				}
				if c.Want == http.StatusNoContent {
					if len(body) != 0 {
						bad = append(bad, fmt.Sprintf("204 com corpo de %d bytes", len(body)))
					}
				} else {
					if !strings.HasPrefix(ctype, "application/json") {
						bad = append(bad, fmt.Sprintf("Content-Type %q", ctype))
					}
					var v struct {
						Error *string `json:"error"`
					}
					if err := json.Unmarshal(body, &v); err != nil || v.Error == nil || *v.Error == "" {
						bad = append(bad, fmt.Sprintf("corpo fora de Error: %q", truncateBody(body)))
					}
				}
				if len(bad) == 0 {
					return
				}
				msg := fmt.Sprintf("%s %s%s: %s", c.Method, root, c.Path, strings.Join(bad, "; "))
				if c.Issue != "" {
					t.Skipf("desvio conhecido (%s): %s", c.Issue, msg)
				}
				t.Error(msg)
			})
		}
	}
}

func truncateBody(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}
