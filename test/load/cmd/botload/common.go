//go:build load

package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/akamai"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Os modelos são os goldens de veredito do bot (internal/bot/testdata/verdicts, task 276): ClientHello e prefixo
// h2 reais de Chrome e curl, com o registro de requisição de cada um. Os goldens estão no formato anterior
// (TraefikIngestBatch); loadTemplates os converte para o traefix.fingerprint/v1 (ADR 0062, task 304) e calcula as
// fingerprints prontas com os mesmos pacotes do espelho, como o traefix as manda no lote e nos X-Traefix-*.
//
//go:embed testdata/chrome.json testdata/curl.json
var templatesFS embed.FS

// Esquema e remetente dos lotes do traefix simulado (spec 019 RF-06: sender começa por traefix/).
const (
	schemaV1 = "traefix.fingerprint/v1"
	senderV1 = "traefix/fork-point-0-gb0710ad"
)

// template é um cliente simulado: os dois registros (connection e request) em traefix.fingerprint/v1 como mapas,
// para trocar só os campos da conexão simulada, e o que vai nos X-Traefix-* do forwardAuth.
type template struct {
	name   string
	conn   map[string]any
	req    map[string]any
	proto  string
	ua     string
	lang   string
	ja4h   string
	ja4    string
	ja3    string
	akamai string
	alpn   []string
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
		var oldConn, oldReq map[string]any
		for _, r := range g.Batch.Records {
			switch r["type"] {
			case "connection":
				oldConn = r
			case "request":
				oldReq = r
			}
		}
		if oldConn == nil || oldReq == nil {
			return nil, fmt.Errorf("modelo %s sem os registros connection e request", n)
		}
		if err := t.fromLegacy(oldConn, oldReq); err != nil {
			return nil, fmt.Errorf("modelo %s: %w", n, err)
		}
		out = append(out, t)
	}
	return out, nil
}

// fromLegacy converte os registros do formato anterior para o traefix.fingerprint/v1 (a correspondência da ADR
// 0062 item 2) e acrescenta as fingerprints prontas calculadas dos bytes crus (rawBytes ligado: vão as duas).
func (t *template) fromLegacy(c, r map[string]any) error {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	hello, err := base64.StdEncoding.DecodeString(str(c, "client_hello"))
	if err != nil {
		return fmt.Errorf("client_hello: %w", err)
	}
	ch, err := tlsparse.Parse(hello)
	if err != nil {
		return fmt.Errorf("client_hello: %w", err)
	}
	j3, j4 := ja3.Compute(ch), ja4.Compute(ch, ja4.TCP)
	t.ja4, t.ja3, t.alpn = j4.JA4, j3.JA3MD5, ch.ALPN
	t.proto = str(r, "proto")
	version := str(c, "tls_version")
	if !strings.HasPrefix(version, "TLS") {
		version = "TLS " + version
	}
	tls := map[string]any{
		"sni": str(c, "sni"), "alpnOffered": c["alpn_offered"], "alpn": str(c, "alpn"), "version": version,
		"cipher": str(c, "cipher"), "ja3": j3.JA3MD5, "ja3String": j3.JA3, "ja3n": j3.JA3NMD5, "ja3nString": j3.JA3N,
		"ja4": j4.JA4, "ja4r": j4.JA4R, "ja4o": j4.JA4O, "clientHello": str(c, "client_hello"), "clientHelloTruncated": false,
	}
	t.conn = map[string]any{
		"type": "connection", "connId": str(c, "fs_conn_id"), "time": str(c, "ts"), "entryPoint": str(c, "entry_point"),
		"src": c["src"], "dst": c["dst"], "proto": t.proto, "tls": tls,
	}
	if p := str(c, "h2_prefix"); p != "" {
		raw, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return fmt.Errorf("h2_prefix: %w", err)
		}
		hp := h2passive.NewParser(h2passive.Options{Dir: h2passive.DirIn, SkipPreface: true})
		hp.Feed(0, raw)
		if hp.Err() != nil {
			return fmt.Errorf("h2_prefix: %w", hp.Err())
		}
		t.akamai = akamai.FromInfo(hp.Info())
		t.conn["http2"] = map[string]any{"akamai": t.akamai, "prefix": p, "prefixTruncated": false}
	}
	// fields vira lista {name, value} na ordem de field_names (o traefix manda na ordem recebida)
	oldFields, _ := r["fields"].(map[string]any)
	names, _ := r["field_names"].([]any)
	fields := []map[string]any{}
	for _, n := range names {
		name, _ := n.(string)
		if v, ok := oldFields[name].(string); ok {
			fields = append(fields, map[string]any{"name": name, "value": v})
		}
	}
	t.ua, _ = oldFields["user-agent"].(string)
	t.lang, _ = oldFields["accept-language"].(string)
	t.ja4h = str(r, "ja4h")
	t.req = map[string]any{
		"type": "request", "connId": str(r, "fs_conn_id"), "start": str(r, "ts"), "end": str(r, "ended"),
		"entryPoint": str(c, "entry_point"), "proto": t.proto, "method": str(r, "method"), "authority": str(r, "authority"),
		"path": str(r, "path"), "httpVersion": str(r, "http_version"), "fieldNames": r["field_names"], "fields": fields,
		"cookieNames": r["cookie_names"], "ja4h": t.ja4h, "headersTruncated": false, "status": r["status"],
		"router": r["router"], "service": r["service"],
	}
	return nil
}

// clone copia um registro (raso nos valores, que não são alterados) para trocar campos.
func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// withTLS copia o registro de conexão com uma cópia do objeto tls (para trocar o SNI e o resto sem mexer no modelo).
func withTLS(conn map[string]any) (map[string]any, map[string]any) {
	c := clone(conn)
	tls, _ := conn["tls"].(map[string]any)
	t := clone(tls)
	c["tls"] = t
	return c, t
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

// batchBody serializa um lote traefix.fingerprint/v1 (spec 019 RF-06).
func batchBody(records []map[string]any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"schema": schemaV1, "sender": senderV1, "entryPoint": "websecure", "sentAt": ts(time.Now()), "records": records,
	})
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
