package bot

import (
	"net/http"
	"testing"
)

// TestStreamSiteOutsideKey: o filtro site do feed fora dos domínios da chave dá 404 not_found, como nas outras
// rotas (spec 020 RF-03, task 409); site de um domínio da chave abre o SSE; na 9003 sem chave nada muda.
func TestStreamSiteOutsideKey(t *testing.T) {
	f := newFixture(t)
	_, secret := f.createKey(KeyOptions{Name: "site", Domains: []string{"example.com"}})
	open := func(base string, key, site string) (int, string, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), "GET", base+"/bot/v1/stream?site="+site, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := f.public.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b := make([]byte, 512)
			n, _ := resp.Body.Read(b)
			return resp.StatusCode, resp.Header.Get("Content-Type"), b[:n]
		}
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil
	}
	for _, base := range []string{f.public.URL, f.internal.URL} {
		code, _, body := open(base, secret, "example.net")
		if code != http.StatusNotFound || errorCode(t, body) != "not_found" {
			t.Fatalf("%s site fora da chave: %d %s", base, code, body)
		}
		if code, ct, _ := open(base, secret, "example.com"); code != http.StatusOK || ct != "text/event-stream" {
			t.Fatalf("%s site da chave: %d %s", base, code, ct)
		}
	}
	if code, ct, _ := open(f.internal.URL, "", "example.net"); code != http.StatusOK || ct != "text/event-stream" {
		t.Fatalf("9003 sem chave: %d %s", code, ct)
	}
}
