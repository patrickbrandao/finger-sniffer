//go:build load

package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Os modelos são os goldens de veredito do bot (internal/bot/testdata/verdicts, task 276): ClientHello e prefixo
// h2 reais de Chrome e curl, com o registro de requisição de cada um.
//
//go:embed testdata/chrome.json testdata/curl.json
var templatesFS embed.FS

// template é um cliente simulado: os dois registros do golden (connection e request) como mapas, para trocar só os
// campos da conexão simulada.
type template struct {
	name string
	conn map[string]any
	req  map[string]any
	ua   string
	lang string
	ja4h string
}

func loadTemplates() ([]*template, error) {
	var out []*template
	for _, n := range []string{"chrome", "curl"} {
		b, err := templatesFS.ReadFile("testdata/" + n + ".json")
		if err != nil {
			return nil, err
		}
		var g struct {
			Batch struct {
				Records []map[string]any `json:"records"`
			} `json:"batch"`
		}
		if err := json.Unmarshal(b, &g); err != nil {
			return nil, fmt.Errorf("modelo %s: %w", n, err)
		}
		t := &template{name: n}
		for _, r := range g.Batch.Records {
			switch r["type"] {
			case "connection":
				t.conn = r
			case "request":
				t.req = r
			}
		}
		if t.conn == nil || t.req == nil {
			return nil, fmt.Errorf("modelo %s sem os registros connection e request", n)
		}
		fields, _ := t.req["fields"].(map[string]any)
		t.ua, _ = fields["user-agent"].(string)
		t.lang, _ = fields["accept-language"].(string)
		t.ja4h, _ = t.req["ja4h"].(string)
		out = append(out, t)
	}
	return out, nil
}

// clone copia um registro (raso nos valores, que não são alterados) para trocar campos.
func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ---------------------------------------------------------------- amostras

// sample é uma medida: início (ns, relógio do finger-01), tipo, latência (µs), status HTTP e um valor extra (view.tcp
// no auth, registros no ingest).
type sample struct {
	t      int64
	kind   string
	latUS  int64
	status int
	flag   int
}

// samplesHeader é o cabeçalho do samples.csv.
const samplesHeader = "t_ns,kind,lat_us,status,flag"

func (s sample) csv() string {
	return fmt.Sprintf("%d,%s,%d,%d,%d", s.t, s.kind, s.latUS, s.status, s.flag)
}

// recorder grava as amostras num CSV por um canal (quem mede não espera o disco).
type recorder struct {
	ch   chan sample
	done chan struct{}
	lost int64
	mu   sync.Mutex
}

func newRecorder(path string) (*recorder, error) {
	f, err := os.Create(path) //nolint:gosec // pasta do operador
	if err != nil {
		return nil, err
	}
	r := &recorder{ch: make(chan sample, 1<<16), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		defer f.Close() //nolint:errcheck // fim da gravação
		w := bufio.NewWriterSize(f, 1<<16)
		_, _ = fmt.Fprintln(w, samplesHeader)
		for s := range r.ch {
			_, _ = fmt.Fprintln(w, s.csv())
		}
		_ = w.Flush()
	}()
	return r, nil
}

func (r *recorder) add(s sample) {
	select {
	case r.ch <- s:
	default:
		r.mu.Lock()
		r.lost++
		r.mu.Unlock()
	}
}

func (r *recorder) close() int64 {
	close(r.ch)
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lost
}

// ---------------------------------------------------------------- HTTP

func newClient(conns int) *http.Client {
	tr := &http.Transport{
		MaxIdleConns: conns, MaxIdleConnsPerHost: conns, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// postIngest manda um lote ao POST /bot/v1/ingest/traefik e devolve status, aceitos e recusados.
func postIngest(ctx context.Context, c *http.Client, base, key string, body []byte) (status, accepted, rejected int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/ingest/traefik", bytes.NewReader(body))
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	var r struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
	}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &r)
	return resp.StatusCode, r.Accepted, r.Rejected, nil
}

// batchBody serializa um TraefikIngestBatch.
func batchBody(records []map[string]any) ([]byte, error) {
	return json.Marshal(map[string]any{"sender": "botload-task285", "records": records})
}

// ---------------------------------------------------------------- SSE

// readSSE lê um fluxo SSE e chama fn com o data de cada evento até ctx acabar; reconecta em erro.
func readSSE(ctx context.Context, c *http.Client, url, key string, fn func(data []byte), logf func(string, ...any)) {
	for ctx.Err() == nil {
		err := func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			if key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
			req.Header.Set("Accept", "text/event-stream")
			resp, err := c.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close() //nolint:errcheck // leitura
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			sc := bufio.NewScanner(resp.Body)
			sc.Buffer(make([]byte, 1<<16), 1<<22)
			for sc.Scan() {
				if d, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
					fn([]byte(strings.TrimSpace(d)))
				}
			}
			return sc.Err()
		}()
		if ctx.Err() != nil {
			return
		}
		// a URL do feed não leva a chave (vai no cabeçalho)
		logf("feed %s: %v; reconectando", url, err)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// sseClient é o cliente sem prazo total (o fluxo fica aberto).
func sseClient() *http.Client {
	return &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 10 * time.Second}}
}
