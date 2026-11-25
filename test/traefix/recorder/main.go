// Comando recorder: gravador dos lotes do traefix de teste (task 406; spec 019 RF-03, tasks 273 e 313). Roda no
// finger-01, ao lado do container fs-traefix-test, em 127.0.0.1:18090: o export.url do traefix aponta para ele, e
// ele guarda cada lote (corpo exato e metadados) e o repassa ao ingest do bot sem mudar os bytes nem os cabeçalhos
// fim a fim (os salto a salto, como Connection, ficam),
// devolvendo ao traefix a resposta do bot como veio. Só stdlib.
//
//	recorder -listen 127.0.0.1:18090 -upstream http://10.249.255.254:9003 -dir /finger-sniffer/var/traefix-test/batches
//
// Para cada lote grava, em -dir, NNNNNN.body (o corpo recebido, byte a byte) e NNNNNN.json (método, caminho,
// cabeçalhos, status e corpo da resposta do bot, tempo). Authorization não é gravado (só "[redacted]").
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// maxBody é o teto do corpo de um lote: o queueMaxBytes padrão do traefix (16 MiB) com folga.
const maxBody = 64 << 20

// meta são os metadados de um lote gravado ao lado do corpo.
type meta struct {
	Seq          uint64              `json:"seq"`
	Received     time.Time           `json:"received"`
	Method       string              `json:"method"`
	Path         string              `json:"path"`
	Header       map[string][]string `json:"header"`
	BodyBytes    int                 `json:"body_bytes"`
	Status       int                 `json:"status"`
	Response     string              `json:"response,omitempty"`
	Error        string              `json:"error,omitempty"`
	ElapsedMicro int64               `json:"elapsed_us"`
}

// recorder guarda e repassa os lotes.
type recorder struct {
	upstream *url.URL
	dir      string
	client   *http.Client
	seq      atomic.Uint64
}

func newRecorder(upstream, dir string) (*recorder, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("upstream inválido %q", upstream)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &recorder{
		upstream: u,
		dir:      dir,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// DisableCompression: o transporte não acrescenta Accept-Encoding nem descomprime a resposta
			Transport: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second},
			// redirecionamento volta ao traefix como veio
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	m := meta{Seq: rc.seq.Add(1), Received: start.UTC(), Method: r.Method, Path: r.URL.RequestURI(), Header: redact(r.Header)}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err == nil && len(body) > maxBody {
		err = errors.New("corpo acima do teto do gravador")
	}
	m.BodyBytes = len(body)
	defer func() {
		m.ElapsedMicro = time.Since(start).Microseconds()
		rc.save(m, body)
	}()
	if err != nil {
		m.Status, m.Error = http.StatusBadGateway, err.Error()
		http.Error(w, m.Error, m.Status)
		return
	}

	target := *rc.upstream
	target.Path = r.URL.Path
	target.RawPath = r.URL.RawPath
	target.RawQuery = r.URL.RawQuery
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		m.Status, m.Error = http.StatusBadGateway, err.Error()
		http.Error(w, m.Error, m.Status)
		return
	}
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)
	// sem User-Agent na entrada, o cliente Go poria o dele: a chave vazia impede
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header["User-Agent"] = []string{""}
	}
	out.ContentLength = int64(len(body))

	resp, err := rc.client.Do(out) //nolint:gosec // host fixo (-upstream); da entrada só vêm caminho e consulta
	if err != nil {
		m.Status, m.Error = http.StatusBadGateway, err.Error()
		http.Error(w, m.Error, m.Status)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		m.Error = "resposta do bot: " + err.Error()
	}
	m.Status, m.Response = resp.StatusCode, string(rb)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rb)
}

// save grava o corpo e os metadados do lote; erro de disco só vai ao log (o repasse já aconteceu).
func (rc *recorder) save(m meta, body []byte) {
	base := filepath.Join(rc.dir, fmt.Sprintf("%06d", m.Seq))
	if err := os.WriteFile(base+".body", body, 0o600); err != nil {
		log.Printf("gravar %s.body: %v", base, err)
	}
	j, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(base+".json", append(j, '\n'), 0o600); err != nil {
		log.Printf("gravar %s.json: %v", base, err)
	}
	log.Printf("lote %d %s %d B → %d %s", m.Seq, m.Path, m.BodyBytes, m.Status, strings.TrimSpace(m.Error))
}

// hopByHop são os cabeçalhos salto a salto (RFC 9110 7.6.1): valem só entre o traefix e o gravador e não seguem
// ao bot; todos os outros seguem como vieram.
var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for f := range strings.SplitSeq(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// redact copia os cabeçalhos sem o valor de Authorization (a chave de teste não vai ao disco).
func redact(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") {
			out[k] = []string{"[redacted]"}
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18090", "endereço de escuta (o export.url do traefix de teste)")
	upstream := flag.String("upstream", "http://10.249.255.254:9003", "base do ingest do bot")
	dir := flag.String("dir", "batches", "pasta dos lotes gravados")
	flag.Parse()
	rc, err := newRecorder(*upstream, *dir)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: rc, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("gravador em %s → %s, lotes em %s", *listen, *upstream, *dir)
	log.Fatal(srv.ListenAndServe())
}
