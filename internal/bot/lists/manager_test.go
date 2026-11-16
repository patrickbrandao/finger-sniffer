package lists

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	botmigrations "github.com/patrickbrandao/finger-sniffer/database/sqlite/bot"
)

// upstream é o publicador falso das listas: um httptest TLS para onde o cliente do teste disca qualquer host,
// então nenhuma requisição sai da máquina. Cada URL do catálogo responde com a amostra de testdata.
type upstream struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	bodies   map[string][]byte                                   // host+path → corpo
	override map[string]func(http.ResponseWriter, *http.Request) // host+path → handler
	requests map[string]int
	headers  map[string]http.Header
}

var fixtureByFormat = map[string]string{
	FormatGoogle: "google.json", FormatAWS: "aws.json", FormatAzure: "azure_page.html", FormatOracle: "oracle.json",
	FormatCSV: "digitalocean.csv", FormatCloudflare: "cloudflare.json",
}

func hostPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u.Host + u.Path
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{
		t: t, bodies: map[string][]byte{}, override: map[string]func(http.ResponseWriter, *http.Request){},
		requests: map[string]int{}, headers: map[string]http.Header{},
	}
	for _, s := range Catalog {
		u.bodies[hostPath(s.URL)] = readTestdata(t, fixtureByFormat[s.Format])
	}
	u.bodies[hostPath("https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20261109.json")] = readTestdata(t, "azure.json")
	u.bodies[hostPath(JA4DBDefaultURL)] = readTestdata(t, "ja4db.json")
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Host + r.URL.Path
		u.mu.Lock()
		u.requests[key]++
		u.headers[key] = r.Header.Clone()
		h := u.override[key]
		body, ok := u.bodies[key]
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, len(body)))
		if r.Header.Get("If-None-Match") == w.Header().Get("ETag") {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// client disca o upstream para qualquer host (sem rede de verdade).
func (u *upstream) client() *http.Client {
	addr := u.srv.Listener.Addr().String()
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // upstream falso do teste
	}}
}

func (u *upstream) set(raw string, body []byte) {
	u.mu.Lock()
	u.bodies[hostPath(raw)] = body
	u.mu.Unlock()
}

func (u *upstream) handle(raw string, h func(http.ResponseWriter, *http.Request)) {
	u.mu.Lock()
	u.override[hostPath(raw)] = h
	u.mu.Unlock()
}

func (u *upstream) count(raw string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[hostPath(raw)]
}

func (u *upstream) header(raw string) http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.headers[hostPath(raw)]
}

func testListsDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "bot.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	prov, err := goose.NewProvider(goose.DialectSQLite3, db, botmigrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

type env struct {
	up    *upstream
	db    *sql.DB
	dir   string
	clock *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{
		up: newUpstream(t), db: testListsDB(t), dir: filepath.Join(t.TempDir(), "lists"),
		clock: &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)},
	}
}

func (e *env) manager(t *testing.T, mod func(*Options)) *Manager {
	t.Helper()
	o := Options{
		Dir: e.dir, RefreshAt: 4 * time.Hour, Version: "test", DB: e.db, Client: e.up.client(), Now: e.clock.Now,
		Resolver: newResolver(), Jitter: func(time.Duration) time.Duration { return 0 },
	}
	if mod != nil {
		mod(&o)
	}
	m, err := NewManager(o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func source(name string) Source {
	for _, s := range Catalog {
		if s.Name == name {
			return s
		}
	}
	panic(name)
}

type row struct {
	sha      []byte
	entries  sql.NullInt64
	fetched  sql.NullInt64
	ok       sql.NullInt64
	errorMsg sql.NullString
}

func readRow(t *testing.T, db *sql.DB, name string) row {
	t.Helper()
	var r row
	err := db.QueryRow(`SELECT sha256, entries, fetched_at, ok_at, error FROM lists WHERE name = ?`, name).
		Scan(&r.sha, &r.entries, &r.fetched, &r.ok, &r.errorMsg)
	if err != nil {
		t.Fatalf("linha %s: %v", name, err)
	}
	return r
}

// Atualização completa: todas as listas do catálogo baixadas, gravadas em disco e na tabela, com User-Agent,
// árvore montada e lists_version mudando.
func TestRefreshAll(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, nil)
	before := m.Version()
	for name, err := range m.RefreshAll(context.Background()) {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if m.Version() == before || len(m.Version()) != 16 {
		t.Errorf("lists_version %q → %q", before, m.Version())
	}
	for _, s := range Catalog {
		if _, err := os.Stat(m.dataPath(s)); err != nil {
			t.Errorf("%s: cópia ausente: %v", s.Name, err)
		}
		r := readRow(t, e.db, s.Name)
		if len(r.sha) != 32 || r.entries.Int64 == 0 || !r.ok.Valid || !r.fetched.Valid || r.errorMsg.Valid {
			t.Errorf("%s: linha %+v", s.Name, r)
		}
	}
	if ua := e.up.header(source("aws").URL).Get("User-Agent"); ua != "finger-sniffer-bot/test" {
		t.Errorf("User-Agent %q", ua)
	}
	// A Azure segue o link da página para o JSON semanal.
	got := m.Lookup(netip.MustParseAddr("198.18.1.1"))
	if !slices.ContainsFunc(got, func(x Match) bool { return x.List == "azure" && x.Kind == KindCloud }) {
		t.Errorf("azure: %+v", got)
	}
	// O IP da amostra google está em todas as listas de formato google, com o robô de cada uma.
	got = m.Lookup(netip.MustParseAddr("::ffff:192.0.2.1"))
	if !slices.ContainsFunc(got, func(x Match) bool { return x.List == "googlebot" && x.Robot == "googlebot" && x.Kind == KindGoodBot }) {
		t.Errorf("googlebot: %+v", got)
	}
	if !slices.ContainsFunc(got, func(x Match) bool { return x.List == "gcp" && x.Kind == KindCloud }) {
		t.Errorf("gcp: %+v", got)
	}
	if got := m.Lookup(netip.MustParseAddr("2001:db8:aa00::1")); len(got) != 1 || got[0].List != "aws" {
		t.Errorf("aws v6: %+v", got)
	}
	if m.JA4DB("t13d1516h2_8daaf6152771_02713d6af862") != nil {
		t.Error("ja4db desligada devolveu rótulo")
	}
	if e.up.count(JA4DBDefaultURL) != 0 {
		t.Error("ja4db desligada foi baixada")
	}
}

// Lista nova inválida (vazia, queda > 50%, formato errado, > 64 MiB, HTTP de erro) não substitui a anterior.
func TestRefreshRejectsInvalid(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, nil)
	m.maxBytes = 4096
	ctx := context.Background()
	src := source("googlebot")
	if err := m.Refresh(ctx, src.Name); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(m.dataPath(src))
	if err != nil {
		t.Fatal(err)
	}
	version := m.Version()
	big := `{"prefixes":[` + strings.Repeat(`{"ipv4Prefix":"10.0.0.0/8"},`, 200) + `{"ipv4Prefix":"10.0.0.0/8"}]}`
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"vazia": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"prefixes":[]}`)) },
		"queda": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/27"}]}`))
		},
		"formato": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>oops</html>`)) },
		"grande":  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(big)) },
		"grande sem tamanho": func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush() // corpo chunked, sem Content-Length
			_, _ = w.Write([]byte(big))
		},
		"http 500": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
		"redirect http": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.com/x.json", http.StatusFound)
		},
	}
	for name, h := range cases {
		e.up.handle(src.URL, h)
		if err := m.Refresh(ctx, src.Name); err == nil {
			t.Errorf("%s: aceita", name)
		}
		now, err := os.ReadFile(m.dataPath(src))
		if err != nil || string(now) != string(good) {
			t.Errorf("%s: cópia em disco trocada", name)
		}
		if m.Version() != version {
			t.Errorf("%s: lists_version mudou", name)
		}
		if got := m.Lookup(netip.MustParseAddr("198.51.100.65")); !slices.ContainsFunc(got, func(x Match) bool { return x.List == "googlebot" }) {
			t.Errorf("%s: lista anterior perdida", name)
		}
		r := readRow(t, e.db, src.Name)
		if !r.errorMsg.Valid || r.entries.Int64 != 3 {
			t.Errorf("%s: linha %+v", name, r)
		}
	}
	if err := m.Refresh(ctx, "nao-existe"); err == nil {
		t.Error("lista desconhecida aceita")
	}
}

// Download condicional: ETag guardado e 304 conta como atualização; queda até 50% é aceita.
func TestRefreshConditional(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, nil)
	ctx := context.Background()
	src := source("bingbot")
	if err := m.Refresh(ctx, src.Name); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour)
	if err := m.Refresh(ctx, src.Name); err != nil {
		t.Fatal(err)
	}
	if e.up.header(src.URL).Get("If-None-Match") == "" {
		t.Error("sem If-None-Match")
	}
	r := readRow(t, e.db, src.Name)
	if r.ok.Int64 != e.clock.Now().Unix() || r.fetched.Int64 == r.ok.Int64 {
		t.Errorf("304: ok_at %d fetched_at %d", r.ok.Int64, r.fetched.Int64)
	}
	// Metade das entradas (3 → 2) ainda é aceita.
	e.up.set(src.URL, []byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/27"},{"ipv6Prefix":"2001:db8::/32"}]}`))
	if err := m.Refresh(ctx, src.Name); err != nil {
		t.Fatalf("queda de 1/3 rejeitada: %v", err)
	}
}

// Partida sem rede usa a cópia em disco; partida com cópia nova não baixa; cópia velha baixa.
func TestLoadFromDisk(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := e.manager(t, nil)
	m.RefreshAll(ctx)
	version := m.Version()

	offline := e.manager(t, func(o *Options) {
		o.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("sem rede")
		})}
	})
	offline.Load(ctx)
	if offline.Version() != version {
		t.Errorf("lists_version da cópia %q, quer %q", offline.Version(), version)
	}
	if got := offline.Lookup(netip.MustParseAddr("203.0.113.9")); len(got) != 1 || got[0].List != "aws" {
		t.Errorf("lookup da cópia: %+v", got)
	}
	for _, st := range offline.Status(e.clock.Now()) {
		if st.Entries == 0 || st.Stale {
			t.Errorf("status %+v", st)
		}
	}

	// Run na partida: cópia com menos de 24 h não baixa de novo.
	before := e.up.count(source("aws").URL)
	runFor(t, e.manager(t, nil))
	if e.up.count(source("aws").URL) != before {
		t.Error("cópia nova baixada de novo na partida")
	}
	// Mais de 24 h: baixa.
	e.clock.Advance(25 * time.Hour)
	runFor(t, e.manager(t, nil))
	if e.up.count(source("aws").URL) != before+1 {
		t.Errorf("cópia velha não baixada: %d", e.up.count(source("aws").URL)-before)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// runFor carrega e roda a atualização da partida; depois confere que Run para com o contexto cancelado.
func runFor(t *testing.T, m *Manager) {
	t.Helper()
	m.Load(context.Background())
	m.startup(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Run(ctx)
}

// Lista vencida (> 72 h) deixa o motivo `list <nome> stale`; a ja4db desligada nunca aparece.
func TestStale(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, nil)
	ctx := context.Background()
	m.RefreshAll(ctx)
	if r := m.StaleReasons(e.clock.Now()); len(r) != 0 {
		t.Fatalf("motivos com tudo novo: %v", r)
	}
	e.clock.Advance(71 * time.Hour)
	_ = m.Refresh(ctx, "aws")
	e.clock.Advance(2 * time.Hour)
	r := m.StaleReasons(e.clock.Now())
	if !slices.Contains(r, "list googlebot stale") || slices.Contains(r, "list aws stale") {
		t.Errorf("motivos %v", r)
	}
	for _, reason := range r {
		if strings.Contains(reason, JA4DBName) {
			t.Errorf("ja4db desligada no health: %v", r)
		}
	}
	for _, st := range m.Status(e.clock.Now()) {
		if st.Name == JA4DBName {
			t.Error("ja4db desligada no status")
		}
		if st.Name == "googlebot" && !st.Stale {
			t.Error("googlebot não vencida")
		}
		if st.Name == KnownClientsName && (st.Stale || st.Entries == 0) {
			t.Errorf("base própria %+v", st)
		}
	}
	// Sem atualização nenhuma desde a partida: vence 72 h depois da partida.
	fresh := e.manager(t, func(o *Options) { o.Dir = filepath.Join(t.TempDir(), "vazio") })
	if len(fresh.StaleReasons(e.clock.Now())) != 0 {
		t.Error("vencida logo na partida")
	}
	if len(fresh.StaleReasons(e.clock.Now().Add(73*time.Hour))) != len(Catalog) {
		t.Error("nunca atualizada e não vencida")
	}
}

// Métricas por lista com rótulo; a ja4db desligada fica fora.
func TestUpdateMetrics(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, nil)
	m.RefreshAll(context.Background())
	e.clock.Advance(90 * time.Second)
	got := map[string]float64{}
	m.UpdateMetrics(e.clock.Now(), func(name string, v float64) { got[name] = v })
	if got[`bot_list_entries{list="aws"}`] != 3 || got[`bot_list_age_seconds{list="aws"}`] != 90 {
		t.Errorf("aws: %v", got)
	}
	if got[`bot_list_entries{list="known_clients"}`] == 0 {
		t.Error("base própria sem entries")
	}
	for k := range got {
		if strings.Contains(k, JA4DBName) {
			t.Errorf("ja4db desligada nas métricas: %s", k)
		}
	}
	if len(got) != 1+2*len(Catalog) {
		t.Errorf("%d métricas", len(got))
	}
}

// ja4db ligada: baixada da URL configurada, rótulos por JA4, no lists_version, nas métricas e no health.
func TestJA4DBEnabled(t *testing.T) {
	e := newEnv(t)
	off := e.manager(t, nil)
	m := e.manager(t, func(o *Options) { o.JA4DBEnable = true })
	if err := m.Refresh(context.Background(), JA4DBName); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "ja4db.json")); err != nil {
		t.Fatal(err)
	}
	ls := m.JA4DB("t13d1812h1_85036bcba153_375ca2c5e164")
	if len(ls) != 1 || ls[0].Kind != "library" || ls[0].Library != "python-requests" {
		t.Errorf("rótulos %+v", ls)
	}
	if m.Version() == off.Version() {
		t.Error("ja4db fora do lists_version")
	}
	got := map[string]float64{}
	m.UpdateMetrics(e.clock.Now(), func(name string, v float64) { got[name] = v })
	if got[`bot_list_entries{list="ja4db"}`] != 4 {
		t.Errorf("métrica ja4db %v", got[`bot_list_entries{list="ja4db"}`])
	}
	if len(m.StaleReasons(e.clock.Now().Add(80*time.Hour))) != len(Catalog)+1 {
		t.Error("ja4db ligada fora do stale")
	}
	// A URL é trocável.
	alt := e.manager(t, func(o *Options) { o.JA4DBEnable, o.JA4DBURL = true, "https://mirror.example/ja4db.json" })
	e.up.set("https://mirror.example/ja4db.json", readTestdata(t, "ja4db.json"))
	if err := alt.Refresh(context.Background(), JA4DBName); err != nil {
		t.Fatal(err)
	}
}

// URL trocada por FS_BOT_LIST_<NOME>_URL e só HTTPS.
func TestURLOverride(t *testing.T) {
	e := newEnv(t)
	m := e.manager(t, func(o *Options) { o.URLs = map[string]string{"cloudflare": "https://mirror.example/cf.json"} })
	e.up.set("https://mirror.example/cf.json", readTestdata(t, "cloudflare.json"))
	if err := m.Refresh(context.Background(), "cloudflare"); err != nil {
		t.Fatal(err)
	}
	if e.up.count("https://mirror.example/cf.json") != 1 || e.up.count(source("cloudflare").URL) != 0 {
		t.Error("URL trocada não usada")
	}
	_, err := NewManager(Options{Dir: e.dir, URLs: map[string]string{"aws": "http://insecure.example/x.json"}})
	if err == nil {
		t.Error("URL http aceita")
	}
	_, err = NewManager(Options{Dir: e.dir, JA4DBEnable: true, JA4DBURL: "ftp://x/"})
	if err == nil {
		t.Error("ja4db não https aceita")
	}
}

// Sem pasta (testes do serviço): nada é baixado; só a base própria.
func TestNoDir(t *testing.T) {
	m, err := NewManager(Options{JA4DBEnable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources()) != 0 || len(m.Status(time.Now())) != 1 || m.Version() == "" {
		t.Errorf("sources %d status %d", len(m.Sources()), len(m.Status(time.Now())))
	}
	m.Run(context.Background()) // volta na hora
	if len(m.StaleReasons(time.Now().Add(1000*time.Hour))) != 0 {
		t.Error("stale sem listas")
	}
}

// Horário da atualização diária: na primeira hora depois de FS_BOT_LIST_REFRESH_AT.
func TestNextRefresh(t *testing.T) {
	at := 4 * time.Hour
	cases := []struct {
		now    string
		jitter time.Duration
		want   string
	}{
		{"2026-11-16T03:00:00Z", 0, "2026-11-16T04:00:00Z"},
		{"2026-11-16T03:00:00Z", 59 * time.Minute, "2026-11-16T04:59:00Z"},
		{"2026-11-16T04:30:00Z", 10 * time.Minute, "2026-11-17T04:10:00Z"},
		{"2026-11-16T23:59:00Z", 0, "2026-11-17T04:00:00Z"},
	}
	for _, c := range cases {
		now, _ := time.Parse(time.RFC3339, c.now)
		if got := NextRefresh(now, at, c.jitter).Format(time.RFC3339); got != c.want {
			t.Errorf("%s +%s: %s, quer %s", c.now, c.jitter, got, c.want)
		}
	}
}
