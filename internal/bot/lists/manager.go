package lists

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limites do download (ADR 0050 itens 3 e 5).
const (
	FetchTimeout = 30 * time.Second
	MaxListBytes = 64 << 20
	// StaleAfter é o prazo sem atualizar para o health ficar degraded (spec 018 RF-11).
	StaleAfter = 72 * time.Hour
	// refreshAge é a idade da cópia em disco que pede download na partida.
	refreshAge = 24 * time.Hour
	// refreshWindow é a janela aleatória depois de FS_BOT_LIST_REFRESH_AT.
	refreshWindow = time.Hour
)

// Métricas por lista (spec 018 RF-12, rótulos da ADR 0056 item 4).
const (
	metricListAge     = "bot_list_age_seconds"
	metricListEntries = "bot_list_entries"
)

// ErrUnknownList é devolvido por Refresh para um nome fora das listas ativas.
var ErrUnknownList = errors.New("lists: unknown list")

// Options configura o Manager.
type Options struct {
	// Dir é a pasta das cópias (var/bot/lists); vazio desliga os downloads (só a base própria).
	Dir string
	// URLs troca a URL padrão do catálogo por nome (FS_BOT_LIST_<NOME>_URL).
	URLs        map[string]string
	JA4DBEnable bool
	JA4DBURL    string
	RefreshAt   time.Duration // deslocamento desde 00:00 UTC
	Version     string        // versão do binário, no User-Agent
	DB          *sql.DB       // tabela lists (opcional)
	Client      *http.Client  // nil = cliente próprio com o prazo de 30 s
	Resolver    Resolver      // nil = net.DefaultResolver
	Now         func() time.Time
	// Jitter sorteia o atraso dentro da janela de atualização (nil = aleatório).
	Jitter func(window time.Duration) time.Duration
	Log    *slog.Logger
}

// listState é o estado de uma lista baixada.
type listState struct {
	src       Source
	data      *parsed
	sha       []byte
	fetchedAt time.Time // último conteúdo aceito
	okAt      time.Time // última atualização bem-sucedida (200 aceito ou 304)
	err       string
	meta      fileMeta
}

// fileMeta acompanha a cópia em disco para o download condicional.
type fileMeta struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Match é uma lista de IP que contém o IP consultado.
type Match struct {
	List  string `json:"list"`
	Kind  string `json:"kind"`
	Robot string `json:"robot,omitempty"`
}

// ListStatus é o estado de uma lista para o health.
type ListStatus struct {
	Name      string
	Entries   int
	FetchedAt time.Time // zero = nunca baixada (ou base própria)
	Stale     bool
}

// Manager mantém as listas ativas, a árvore de prefixos e a verificação de robô.
type Manager struct {
	opts     Options
	maxBytes int64 // MaxListBytes (menor nos testes)
	known    *KnownClients
	verifier *Verifier
	started  time.Time
	sources  []Source
	bySource map[string]Source

	refreshMu sync.Mutex // um download por vez
	mu        sync.Mutex
	state     map[string]*listState

	tree    atomic.Pointer[Tree]
	ja4db   atomic.Pointer[map[string][]JA4DBLabel]
	version atomic.Value // string
}

// NewManager valida a base própria e monta o catálogo ativo (ja4db só com JA4DBEnable).
func NewManager(o Options) (*Manager, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Jitter == nil {
		o.Jitter = func(window time.Duration) time.Duration {
			return time.Duration(rand.Int64N(int64(window))) //nolint:gosec // só espalha o horário do download
		}
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: FetchTimeout}
	}
	if o.JA4DBURL == "" {
		o.JA4DBURL = JA4DBDefaultURL
	}
	known, err := LoadKnownClients()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		opts: o, maxBytes: MaxListBytes, known: known, verifier: NewVerifier(o.Resolver, o.Now), started: o.Now(),
		bySource: map[string]Source{}, state: map[string]*listState{},
	}
	if o.Dir != "" {
		for _, s := range Catalog {
			if u := o.URLs[s.Name]; u != "" {
				s.URL = u
			}
			m.sources = append(m.sources, s)
		}
		if o.JA4DBEnable {
			m.sources = append(m.sources, Source{Name: JA4DBName, URL: o.JA4DBURL, Format: FormatJA4DB, Kind: KindJA4DB})
		}
	}
	for _, s := range m.sources {
		if err := checkURL(s.URL); err != nil {
			return nil, fmt.Errorf("lists: %s: %w", s.Name, err)
		}
		m.bySource[s.Name] = s
		m.state[s.Name] = &listState{src: s}
	}
	m.rebuild()
	return m, nil
}

// checkURL exige HTTPS (ADR 0050 item 5).
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("url must be https: %q", raw)
	}
	return nil
}

// Known é a base própria.
func (m *Manager) Known() *KnownClients { return m.known }

// Verifier é a verificação de robô por DNS.
func (m *Manager) Verifier() *Verifier { return m.verifier }

// Sources são as listas baixadas ativas.
func (m *Manager) Sources() []Source { return slices.Clone(m.sources) }

// Lookup diz em quais listas de IP o IP está.
func (m *Manager) Lookup(ip netip.Addr) []Match {
	names := m.tree.Load().Lookup(ip)
	out := make([]Match, 0, len(names))
	for _, n := range names {
		s := m.bySource[n]
		out = append(out, Match{List: n, Kind: s.Kind, Robot: s.Robot})
	}
	return out
}

// JA4DB devolve os rótulos da ja4db para um JA4 (nil com a ja4db desligada ou sem o JA4).
func (m *Manager) JA4DB(ja4 string) []JA4DBLabel {
	p := m.ja4db.Load()
	if p == nil {
		return nil
	}
	return (*p)[ja4]
}

// Version é o lists_version: hash dos hashes das listas ativas com conteúdo.
func (m *Manager) Version() string {
	v, _ := m.version.Load().(string)
	return v
}

// Load lê as cópias em disco e o estado da tabela lists (partida sem rede usa a cópia em disco).
func (m *Manager) Load(ctx context.Context) {
	rows := m.readRows(ctx)
	for _, s := range m.sources {
		st := m.state[s.Name]
		b, err := os.ReadFile(m.dataPath(s))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				m.opts.Log.Warn("bot: list copy unreadable", "list", s.Name, "err", err)
			}
			continue
		}
		p, err := parse(s.Format, b)
		if err != nil || p.entries == 0 {
			m.opts.Log.Warn("bot: list copy invalid", "list", s.Name, "err", err)
			continue
		}
		sum := sha256.Sum256(b)
		meta := m.readMeta(s)
		m.mu.Lock()
		st.data, st.sha = &p, sum[:]
		if meta.URL == s.URL {
			st.meta = meta
		}
		if r, ok := rows[s.Name]; ok {
			st.fetchedAt, st.okAt, st.err = r.fetchedAt, r.okAt, r.err
		}
		if st.okAt.IsZero() {
			if fi, err := os.Stat(m.dataPath(s)); err == nil {
				st.okAt, st.fetchedAt = fi.ModTime(), fi.ModTime()
			}
		}
		m.mu.Unlock()
	}
	m.rebuild()
}

// Run atualiza na partida as listas sem cópia ou com mais de 24 h e depois uma vez por dia, em horário
// aleatório na primeira hora depois de RefreshAt, até ctx acabar.
func (m *Manager) Run(ctx context.Context) {
	if len(m.sources) == 0 {
		return
	}
	m.startup(ctx)
	for {
		next := NextRefresh(m.opts.Now(), m.opts.RefreshAt, m.opts.Jitter(refreshWindow))
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		for _, s := range m.sources {
			if ctx.Err() != nil {
				return
			}
			m.refreshLogged(ctx, s.Name)
		}
	}
}

// startup baixa as listas sem cópia em disco ou com a cópia de mais de 24 h.
func (m *Manager) startup(ctx context.Context) {
	now := m.opts.Now()
	for _, s := range m.sources {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		st := m.state[s.Name]
		need := st.data == nil || st.okAt.IsZero() || now.Sub(st.okAt) > refreshAge
		m.mu.Unlock()
		if need {
			m.refreshLogged(ctx, s.Name)
		}
	}
}

func (m *Manager) refreshLogged(ctx context.Context, name string) {
	if err := m.Refresh(ctx, name); err != nil && ctx.Err() == nil {
		m.opts.Log.Warn("bot: list refresh", "list", name, "err", err)
	}
}

// NextRefresh é o próximo horário de atualização: hoje (UTC) em at+jitter, ou amanhã se já passou.
func NextRefresh(now time.Time, at, jitter time.Duration) time.Time {
	day := now.UTC().Truncate(24 * time.Hour)
	next := day.Add(at + jitter)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// RefreshAll atualiza todas as listas ativas e devolve o erro de cada uma (nil = ok).
func (m *Manager) RefreshAll(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, s := range m.sources {
		out[s.Name] = m.Refresh(ctx, s.Name)
	}
	return out
}

// Refresh baixa uma lista, valida e troca a cópia (lists refresh da CLI, task 283). Conteúdo inválido (formato,
// vazio, queda a menos da metade, > 64 MiB) não substitui a anterior. Queda: nas listas de IP, o espaço coberto de
// alguma família presente na anterior (ADR 0077 item 3); na ja4db, a contagem de entradas.
func (m *Manager) Refresh(ctx context.Context, name string) error {
	return m.refreshNamed(ctx, name, false)
}

// RefreshForced é o lists refresh --force <nome> (ADR 0077 item 3): valida o formato e a lista não vazia, sem a
// regra da queda, e registra warn com o espaço anterior e o novo por família.
func (m *Manager) RefreshForced(ctx context.Context, name string) error {
	return m.refreshNamed(ctx, name, true)
}

func (m *Manager) refreshNamed(ctx context.Context, name string, force bool) error {
	s, ok := m.bySource[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownList, name)
	}
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	err := m.refresh(ctx, s, force)
	now := m.opts.Now()
	m.mu.Lock()
	st := m.state[name]
	if err != nil {
		st.err = err.Error()
	} else {
		st.err, st.okAt = "", now
	}
	row := listRow{sha: st.sha, fetchedAt: st.fetchedAt, okAt: st.okAt, err: st.err}
	if st.data != nil {
		row.entries = st.data.entries
	}
	m.mu.Unlock()
	m.writeRow(ctx, s, row)
	return err
}

func (m *Manager) refresh(ctx context.Context, s Source, force bool) error {
	m.mu.Lock()
	st := m.state[s.Name]
	meta := st.meta
	prev := st.data // trocado inteiro, nunca alterado: ler fora da trava é seguro
	if prev == nil {
		meta = fileMeta{}
	}
	m.mu.Unlock()

	body, newMeta, notModified, err := m.fetch(ctx, s.URL, meta)
	if err != nil {
		return err
	}
	if notModified {
		return nil
	}
	if s.Format == FormatAzure {
		if link, ok := azureLink(body); ok {
			if body, _, _, err = m.fetch(ctx, link, fileMeta{}); err != nil {
				return err
			}
		}
	}
	p, err := parse(s.Format, body)
	if err != nil {
		return err
	}
	if p.entries == 0 {
		return errors.New("lists: empty list rejected")
	}
	if prev != nil {
		if force {
			m.opts.Log.Warn("bot: list refresh forced", "list", s.Name,
				"prev_ipv4", prev.space[0], "new_ipv4", p.space[0], "prev_ipv6", prev.space[1], "new_ipv6", p.space[1],
				"prev_entries", prev.entries, "new_entries", p.entries)
		} else if err := checkDrop(s, prev, &p); err != nil {
			return err
		}
	}
	if err := m.writeFiles(s, body, newMeta); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	m.mu.Lock()
	st.data, st.sha, st.meta, st.fetchedAt = &p, sum[:], newMeta, m.opts.Now()
	m.mu.Unlock()
	m.rebuild()
	return nil
}

// checkDrop recusa a queda a menos da metade (ADR 0077 item 3): nas listas de IP, por família presente na anterior,
// pelo espaço coberto (a família que some inteira conta como queda); na ja4db, pela contagem de entradas.
func checkDrop(s Source, prev, p *parsed) error {
	if s.Kind == KindJA4DB {
		if p.entries*2 < prev.entries {
			return fmt.Errorf("lists: drop from %d to %d entries rejected", prev.entries, p.entries)
		}
		return nil
	}
	for fam, name := range [2]string{"ipv4", "ipv6"} {
		if prev.space[fam] > 0 && p.space[fam]*2 < prev.space[fam] {
			return fmt.Errorf("lists: %s covered space drop from %g to %g addresses rejected", name, prev.space[fam], p.space[fam])
		}
	}
	return nil
}

// fetch faz o GET com o download condicional; notModified com 304.
func (m *Manager) fetch(ctx context.Context, raw string, meta fileMeta) ([]byte, fileMeta, bool, error) {
	if err := checkURL(raw); err != nil {
		return nil, meta, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, meta, false, err
	}
	req.Header.Set("User-Agent", "finger-sniffer-bot/"+m.opts.Version)
	if meta.URL == raw {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	client := *m.opts.Client
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" {
			return errors.New("lists: redirect to non-https refused")
		}
		if len(via) >= 5 {
			return errors.New("lists: too many redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, meta, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, meta, true, nil
	case http.StatusOK:
	default:
		return nil, meta, false, fmt.Errorf("lists: http %d", resp.StatusCode)
	}
	if resp.ContentLength > m.maxBytes {
		return nil, meta, false, fmt.Errorf("lists: body over %d bytes", m.maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, m.maxBytes+1))
	if err != nil {
		return nil, meta, false, err
	}
	if int64(len(b)) > m.maxBytes {
		return nil, meta, false, fmt.Errorf("lists: body over %d bytes", m.maxBytes)
	}
	return b, fileMeta{URL: raw, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, false, nil
}

func (m *Manager) dataPath(s Source) string {
	ext := ".json"
	if s.Format == FormatCSV {
		ext = ".csv"
	}
	return filepath.Join(m.opts.Dir, s.Name+ext)
}

func (m *Manager) metaPath(s Source) string { return filepath.Join(m.opts.Dir, s.Name+".meta.json") }

func (m *Manager) readMeta(s Source) fileMeta {
	var meta fileMeta
	if b, err := os.ReadFile(m.metaPath(s)); err == nil {
		_ = json.Unmarshal(b, &meta)
	}
	return meta
}

// writeFiles troca a cópia e o meta de forma atômica (arquivo temporário + rename).
func (m *Manager) writeFiles(s Source, body []byte, meta fileMeta) error {
	if err := os.MkdirAll(m.opts.Dir, 0o750); err != nil {
		return err
	}
	if err := writeAtomic(m.dataPath(s), body); err != nil {
		return err
	}
	mb, _ := json.Marshal(meta)
	return writeAtomic(m.metaPath(s), mb)
}

func writeAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// rebuild remonta a árvore, o mapa da ja4db e o lists_version a partir do estado.
func (m *Manager) rebuild() {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := NewTreeBuilder()
	var ja4 map[string][]JA4DBLabel
	hashes := []string{KnownClientsName + ":" + m.known.Version}
	for _, s := range m.sources {
		st := m.state[s.Name]
		if st.data == nil {
			continue
		}
		hashes = append(hashes, s.Name+":"+hex.EncodeToString(st.sha))
		if s.Kind == KindJA4DB {
			ja4 = st.data.ja4
			continue
		}
		b.Add(s.Name, st.data.prefixes)
	}
	m.tree.Store(b.Build())
	if ja4 != nil {
		m.ja4db.Store(&ja4)
	}
	sort.Strings(hashes)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "\n")))
	m.version.Store(hex.EncodeToString(sum[:8]))
}

// Status devolve o estado de cada lista ativa (a base própria primeiro).
func (m *Manager) Status(now time.Time) []ListStatus {
	out := []ListStatus{{Name: KnownClientsName, Entries: m.known.Entries()}}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sources {
		st := m.state[s.Name]
		ls := ListStatus{Name: s.Name, FetchedAt: st.fetchedAt, Stale: m.staleLocked(st, now)}
		if st.data != nil {
			ls.Entries = st.data.entries
		}
		out = append(out, ls)
	}
	return out
}

// staleLocked: sem atualização bem-sucedida há mais de 72 h (desde a partida, se nunca atualizou).
func (m *Manager) staleLocked(st *listState, now time.Time) bool {
	ref := st.okAt
	if ref.IsZero() {
		ref = m.started
	}
	return now.Sub(ref) > StaleAfter
}

// StaleReasons são os motivos de degraded (`list <nome> stale`, spec 018 RF-11).
func (m *Manager) StaleReasons(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, s := range m.sources {
		if m.staleLocked(m.state[s.Name], now) {
			out = append(out, "list "+s.Name+" stale")
		}
	}
	return out
}

// UpdateMetrics publica bot_list_age_seconds{list} e bot_list_entries{list} das listas ativas.
func (m *Manager) UpdateMetrics(now time.Time, set func(name string, v float64)) {
	set(labeled(metricListEntries, KnownClientsName), float64(m.known.Entries()))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sources {
		st := m.state[s.Name]
		entries := 0
		if st.data != nil {
			entries = st.data.entries
		}
		set(labeled(metricListEntries, s.Name), float64(entries))
		ref := st.okAt
		if ref.IsZero() {
			ref = m.started
		}
		set(labeled(metricListAge, s.Name), now.Sub(ref).Seconds())
	}
}

func labeled(metric, list string) string { return metric + `{list="` + list + `"}` }

// listRow é a linha da tabela lists.
type listRow struct {
	sha       []byte
	entries   int
	fetchedAt time.Time
	okAt      time.Time
	err       string
}

func (m *Manager) readRows(ctx context.Context) map[string]listRow {
	out := map[string]listRow{}
	if m.opts.DB == nil {
		return out
	}
	rows, err := m.opts.DB.QueryContext(ctx, `SELECT name, fetched_at, ok_at, error FROM lists`)
	if err != nil {
		m.opts.Log.Warn("bot: lists table", "err", err)
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		var fetched, ok sql.NullInt64
		var e sql.NullString
		if err := rows.Scan(&name, &fetched, &ok, &e); err != nil {
			return out
		}
		out[name] = listRow{fetchedAt: unix(fetched), okAt: unix(ok), err: e.String}
	}
	return out
}

func unix(v sql.NullInt64) time.Time {
	if !v.Valid || v.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}

func nullUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func (m *Manager) writeRow(ctx context.Context, s Source, r listRow) {
	if m.opts.DB == nil {
		return
	}
	var e, sha any
	if r.err != "" {
		e = r.err
	}
	if r.sha != nil {
		sha = r.sha
	}
	_, err := m.opts.DB.ExecContext(ctx, `INSERT INTO lists (name, url, sha256, entries, fetched_at, ok_at, error)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET url = excluded.url, sha256 = excluded.sha256, entries = excluded.entries,
			fetched_at = excluded.fetched_at, ok_at = excluded.ok_at, error = excluded.error`,
		s.Name, s.URL, sha, r.entries, nullUnix(r.fetchedAt), nullUnix(r.okAt), e)
	if err != nil && ctx.Err() == nil {
		m.opts.Log.Warn("bot: lists row", "list", s.Name, "err", err)
	}
}
