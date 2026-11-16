package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// fakeClock é um relógio controlado pelo teste.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testDB abre um banco do bot novo num diretório temporário.
func testDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bot.db")
	db, err := OpenDB(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

// testConfig é a configuração padrão dos testes.
func testConfig(dbPath string) Config {
	return Config{
		PublicPort: 9002, InternalPort: 9003, DBPath: dbPath, MaxBytes: 2 << 30, FlushInterval: time.Second,
		AggRetention: MaxAggRetention, ConnTTL: 10 * time.Minute, MaxConns: 1000, ViewWait: 50 * time.Millisecond,
		RateHigh: 120, InternalAllow: []netip.Prefix{netip.MustParsePrefix("10.249.0.0/16")},
	}
}

// openapiBytes lê o contrato do bot.
func openapiBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(openapiFile)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixture é um serviço bot com banco temporário e as duas portas em httptest.
type fixture struct {
	t        *testing.T
	db       *sql.DB
	srv      *Server
	clock    *fakeClock
	metrics  *service.Metrics
	public   *httptest.Server
	internal *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, path := testDB(t)
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	m := service.NewMetrics()
	srv := New(testConfig(path), Deps{DB: db, OpenAPI: openapiBytes(t), Version: "test", Metrics: m, Now: clock.Now})
	if err := srv.Keys().Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, db: db, srv: srv, clock: clock, metrics: m}
	f.public = httptest.NewServer(srv.Handler(false))
	f.internal = httptest.NewServer(srv.Handler(true))
	t.Cleanup(f.public.Close)
	t.Cleanup(f.internal.Close)
	return f
}

// createKey emite uma chave e recarrega o cache.
func (f *fixture) createKey(o KeyOptions) (Key, string) {
	f.t.Helper()
	k, secret, _, err := CreateKey(context.Background(), f.db, o, f.clock.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.srv.Keys().Reload(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	return k, secret
}

// do faz a requisição e devolve status, cabeçalhos e corpo.
func (f *fixture) do(base *httptest.Server, method, path, key string, hdr map[string]string, body string) (int, http.Header, []byte) {
	f.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := base.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// errorCode lê o campo error de um corpo Error.
func errorCode(t *testing.T, b []byte) string {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("corpo não é Error: %s", b)
	}
	return e.Error
}
