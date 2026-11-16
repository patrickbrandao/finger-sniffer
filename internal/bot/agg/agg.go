// Package agg acumula em memória os agregados do bot por IP + site + hora (ip_hourly) e por fingerprint + dia +
// família de UA (fp_daily), grava-os no banco a cada flush e mantém o cache de comportamento da última hora e das
// horas gravadas até 24 h (spec 018 RF-08 e RF-09, ADR 0052).
//
// Minimização (ADR 0052 item 2): o caminho da requisição só entra como SHA-256 truncado com o sal do dia, que é
// descartado quando o dia muda; nem o caminho nem a query ficam na memória ou no banco. O IP das fingerprints entra
// só como hash com o mesmo sal, para a contagem aproximada de `ips`.
package agg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/bits"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Classes do veredito (mesmos valores do pacote bot, ADR 0049 item 3).
const (
	ClassHuman   = "human"
	ClassBot     = "bot"
	ClassSuspect = "suspect"
	ClassGoodBot = "good_bot"
	ClassUnknown = "unknown"
)

// Constantes dos acumuladores.
const (
	// DefaultMaxEntries é o teto padrão de entradas em memória (comportamento por IP + site, horas abertas e
	// fingerprints do dia); cheio, a observação é descartada e contada em bot_agg_dropped_total.
	DefaultMaxEntries = 200_000
	// BehaviorHours é a janela do cache de comportamento (spec 018 RF-09): a hora corrente e as 23 anteriores.
	BehaviorHours = 24
	// maxPathsPerHour limita os hashes de caminho por IP + site + hora; acima disso a contagem satura.
	maxPathsPerHour = 4096
	// kmvK é o tamanho do esboço KMV que estima os IPs distintos de uma fingerprint no dia.
	kmvK = 256
	// maxSiteLen e maxValueLen limitam o que entra como chave.
	maxSiteLen  = 253
	maxValueLen = 512
)

// Fingerprint é uma fingerprint vista na requisição.
type Fingerprint struct {
	Kind  string // ja4 | akamai | ja4h | ja4t
	Value string
}

// Request é o resumo de uma requisição já com a classe do veredito (a task 282 chama Observe).
type Request struct {
	Time time.Time
	IP   netip.Addr
	Site string // host do site
	// Path é o caminho da requisição; a query é cortada e o caminho só vira hash, nunca é guardado.
	Path string
	// Reused diz que a requisição veio numa conexão que já tinha requisições (reuso de conexão).
	Reused       bool
	Class        string
	UAFamily     string
	Fingerprints []Fingerprint
}

// Intervals são n, soma e soma dos quadrados dos intervalos (s) entre requisições do IP no site.
type Intervals struct {
	N     int64
	Sum   float64
	SqSum float64
}

// Mean é a média dos intervalos (0 sem intervalos).
func (iv Intervals) Mean() float64 {
	if iv.N == 0 {
		return 0
	}
	return iv.Sum / float64(iv.N)
}

// StdDev é o desvio padrão populacional dos intervalos (0 com menos de dois).
func (iv Intervals) StdDev() float64 {
	if iv.N < 2 {
		return 0
	}
	m := iv.Mean()
	return math.Sqrt(math.Max(0, iv.SqSum/float64(iv.N)-m*m))
}

// Stats é o comportamento de um IP num site (spec 018 RF-09). "Hour" é a hora corrente (epoch/3600); "Day" soma a
// hora corrente e as 23 anteriores. Os caminhos de Day são a soma dos distintos de cada hora (aproximado).
type Stats struct {
	Known          bool
	RequestsPerMin float64 // janela deslizante de 60 s
	HourRequests   int64
	HourConns      int64
	HourReused     int64
	HourPaths      int64
	HourStatics    int64
	HourIntervals  Intervals
	DayRequests    int64
	DayConns       int64
	DayPaths       int64
	DayStatics     int64
	DayIntervals   Intervals
	Hours          int // horas com dados na janela
}

// Config configura o acumulador.
type Config struct {
	// MaxEntries é o teto de entradas em memória (DefaultMaxEntries se ≤ 0).
	MaxEntries int
	// MaxAge é a idade máxima de uma hora ainda não gravada (falha persistente do flush); passada, é descartada.
	// Padrão 7 dias (ADR 0052 item 1).
	MaxAge time.Duration
}

// counters são os contadores de uma hora de ip_hourly.
type counters struct {
	requests, conns, reused, paths, statics int64
	iv                                      Intervals
	class                                   [5]int64 // human, bot, suspect, good_bot, unknown
}

func (c *counters) add(o counters) {
	c.requests += o.requests
	c.conns += o.conns
	c.reused += o.reused
	c.paths += o.paths
	c.statics += o.statics
	c.iv.N += o.iv.N
	c.iv.Sum += o.iv.Sum
	c.iv.SqSum += o.iv.SqSum
	for i := range c.class {
		c.class[i] += o.class[i]
	}
}

func (c counters) sub(o counters) counters {
	d := counters{
		requests: c.requests - o.requests, conns: c.conns - o.conns, reused: c.reused - o.reused,
		paths: c.paths - o.paths, statics: c.statics - o.statics,
		iv: Intervals{N: c.iv.N - o.iv.N, Sum: c.iv.Sum - o.iv.Sum, SqSum: c.iv.SqSum - o.iv.SqSum},
	}
	for i := range d.class {
		d.class[i] = c.class[i] - o.class[i]
	}
	return d
}

// hourAcc é uma hora ainda aberta: total acumulado, o que já foi gravado e os hashes dos caminhos.
type hourAcc struct {
	cur, flushed counters
	paths        map[uint64]struct{}
}

// hourStats é uma hora fechada e gravada (cache de comportamento).
type hourStats struct {
	hour int64
	c    counters
}

// behavior é o estado de um IP num site.
type behavior struct {
	last    time.Time
	minute  int64 // epoch/60 de curMin
	curMin  int64
	prevMin int64
	open    map[int64]*hourAcc
	past    []hourStats // ordenado por hora
}

type siteKey struct {
	ip   [16]byte
	site string
}

type fpKey struct {
	kind, value string
	day         int64
	ua          string
}

// fpAcc é o acumulador de uma fingerprint no dia.
type fpAcc struct {
	requests, bot, human                      int64
	flushedRequests, flushedBot, flushedHuman int64
	flushedIPs                                int64
	ips                                       kmv
}

// Aggregator é o acumulador dos agregados e o cache de comportamento. Seguro para uso concorrente.
type Aggregator struct {
	maxEntries int
	maxAge     time.Duration
	flushMu    sync.Mutex // serializa os flushes

	mu      sync.Mutex
	entries int // comportamentos + horas abertas + fingerprints
	saltDay int64
	salt    [32]byte
	sites   map[siteKey]*behavior
	fps     map[fpKey]*fpAcc

	dropped atomic.Uint64
}

// New cria o acumulador.
func New(cfg Config) *Aggregator {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 7 * 24 * time.Hour
	}
	return &Aggregator{
		maxEntries: cfg.MaxEntries, maxAge: cfg.MaxAge, saltDay: math.MinInt64,
		sites: map[siteKey]*behavior{}, fps: map[fpKey]*fpAcc{},
	}
}

// Dropped devolve quantas observações foram descartadas pelo teto de entradas ou por idade sem flush
// (bot_agg_dropped_total).
func (a *Aggregator) Dropped() uint64 { return a.dropped.Load() }

// Entries devolve quantas entradas há em memória.
func (a *Aggregator) Entries() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.entries
}

// Observe acumula uma requisição.
func (a *Aggregator) Observe(r Request) {
	if !r.IP.IsValid() || r.Time.IsZero() {
		return
	}
	site := normSite(r.Site)
	if site == "" {
		return
	}
	k := siteKey{ip: ipKey(r.IP), site: site}
	unix := r.Time.Unix()
	hour, day := floorDiv(unix, 3600), floorDiv(unix, 86400)

	a.mu.Lock()
	defer a.mu.Unlock()
	salt := a.saltFor(day)
	b := a.sites[k]
	if b == nil {
		if a.entries+2 > a.maxEntries {
			a.dropped.Add(1)
			return
		}
		b = &behavior{open: map[int64]*hourAcc{}}
		a.sites[k] = b
		a.entries++
	}
	h := b.open[hour]
	if h == nil {
		if a.entries+1 > a.maxEntries {
			a.dropped.Add(1)
			return
		}
		h = &hourAcc{paths: map[uint64]struct{}{}}
		b.open[hour] = h
		a.entries++
	}
	c := &h.cur
	c.requests++
	if r.Reused {
		c.reused++
	} else {
		c.conns++
	}
	p := cleanPath(r.Path)
	if isStatic(p) {
		c.statics++
	}
	if len(h.paths) < maxPathsPerHour {
		h.paths[pathHash(salt, site, p)] = struct{}{}
		c.paths = int64(len(h.paths))
	}
	if !b.last.IsZero() {
		if iv := r.Time.Sub(b.last).Seconds(); iv >= 0 {
			c.iv.N++
			c.iv.Sum += iv
			c.iv.SqSum += iv * iv
		}
	}
	if r.Time.After(b.last) {
		b.last = r.Time
	}
	b.countMinute(floorDiv(unix, 60))
	c.class[classIndex(r.Class)]++

	if len(r.Fingerprints) == 0 {
		return
	}
	ipHash := ipHash(salt, k.ip)
	ua := r.UAFamily
	if ua == "" || len(ua) > 64 {
		ua = "other"
	}
	for _, f := range r.Fingerprints {
		if !validKind(f.Kind) || f.Value == "" || len(f.Value) > maxValueLen {
			continue
		}
		fk := fpKey{kind: f.Kind, value: f.Value, day: day, ua: ua}
		acc := a.fps[fk]
		if acc == nil {
			if a.entries+1 > a.maxEntries {
				a.dropped.Add(1)
				continue
			}
			acc = &fpAcc{}
			a.fps[fk] = acc
			a.entries++
		}
		acc.requests++
		switch r.Class {
		case ClassBot:
			acc.bot++
		case ClassHuman:
			acc.human++
		}
		acc.ips.add(ipHash)
	}
}

// countMinute mantém os dois baldes de minuto da taxa deslizante.
func (b *behavior) countMinute(m int64) {
	switch {
	case m == b.minute:
		b.curMin++
	case m == b.minute+1:
		b.prevMin, b.curMin, b.minute = b.curMin, 1, m
	case m > b.minute+1:
		b.prevMin, b.curMin, b.minute = 0, 1, m
	}
}

// Query devolve o comportamento do IP no site, sem disco e com a trava só pelo tempo de somar no máximo 24 horas.
func (a *Aggregator) Query(ip netip.Addr, site string, now time.Time) Stats {
	if !ip.IsValid() {
		return Stats{}
	}
	k := siteKey{ip: ipKey(ip), site: normSite(site)}
	unix := now.Unix()
	cur := floorDiv(unix, 3600)
	first := cur - BehaviorHours + 1

	a.mu.Lock()
	defer a.mu.Unlock()
	b := a.sites[k]
	if b == nil {
		return Stats{}
	}
	var hourC, dayC counters
	var hours uint32 // bit i = hora first+i com dados
	for _, p := range b.past {
		if p.hour < first || p.hour > cur {
			continue
		}
		dayC.add(p.c)
		hours |= 1 << (p.hour - first)
		if p.hour == cur {
			hourC.add(p.c)
		}
	}
	for hr, h := range b.open {
		if hr < first || hr > cur {
			continue
		}
		dayC.add(h.cur)
		hours |= 1 << (hr - first)
		if hr == cur {
			hourC.add(h.cur)
		}
	}
	st := Stats{
		Known: hours != 0, HourRequests: hourC.requests, HourConns: hourC.conns, HourReused: hourC.reused,
		HourPaths: hourC.paths, HourStatics: hourC.statics, HourIntervals: hourC.iv,
		DayRequests: dayC.requests, DayConns: dayC.conns, DayPaths: dayC.paths, DayStatics: dayC.statics,
		DayIntervals: dayC.iv, Hours: bits.OnesCount32(hours),
	}
	nowMin := floorDiv(unix, 60)
	frac := float64(unix-nowMin*60) / 60
	switch nowMin {
	case b.minute:
		st.RequestsPerMin = float64(b.prevMin)*(1-frac) + float64(b.curMin)
	case b.minute + 1:
		st.RequestsPerMin = float64(b.curMin) * (1 - frac)
	}
	return st
}

// Forget apaga da memória tudo do prefixo (acumuladores ainda não gravados, hashes de caminhos e cache de
// comportamento) e devolve quantos pares IP + site saíram (ADR 0052 item 5, ADR 0056 item 2).
func (a *Aggregator) Forget(p netip.Prefix) int {
	p = p.Masked()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, b := range a.sites {
		if p.Contains(netip.AddrFrom16(k.ip).Unmap()) {
			a.entries -= 1 + len(b.open)
			delete(a.sites, k)
			n++
		}
	}
	return n
}

// maintain fecha as horas passadas já gravadas (vão ao cache de comportamento), descarta horas abertas mais velhas
// que maxAge, corta o cache em 24 h, apaga fingerprints de dias passados já gravadas e troca o sal no dia novo.
// Chamada com a.mu.
func (a *Aggregator) maintain(now time.Time) {
	unix := now.Unix()
	cur, day := floorDiv(unix, 3600), floorDiv(unix, 86400)
	first := cur - BehaviorHours + 1
	oldest := floorDiv(now.Add(-a.maxAge).Unix(), 3600)
	for k, b := range a.sites {
		for hr, h := range b.open {
			switch {
			case hr >= cur:
				continue
			case h.cur == h.flushed:
				if hr >= first {
					b.addPast(hourStats{hour: hr, c: h.cur})
				}
			case hr < oldest:
				a.dropped.Add(uint64(max(0, h.cur.requests-h.flushed.requests))) //nolint:gosec // não negativo
			default:
				continue
			}
			delete(b.open, hr)
			a.entries--
		}
		b.past = slices.DeleteFunc(b.past, func(p hourStats) bool { return p.hour < first })
		if len(b.open) == 0 && len(b.past) == 0 {
			delete(a.sites, k)
			a.entries--
		}
	}
	oldestDay := floorDiv(now.Add(-a.maxAge).Unix(), 86400)
	for k, f := range a.fps {
		if k.day >= day {
			continue
		}
		if f.flushedRequests == f.requests && f.flushedBot == f.bot && f.flushedHuman == f.human {
			delete(a.fps, k)
			a.entries--
		} else if k.day < oldestDay {
			a.dropped.Add(uint64(max(0, f.requests-f.flushedRequests))) //nolint:gosec // não negativo
			delete(a.fps, k)
			a.entries--
		}
	}
	a.saltFor(day)
}

// addPast junta uma hora gravada ao cache (somando se a hora já veio do banco no início).
func (b *behavior) addPast(s hourStats) {
	i, found := slices.BinarySearchFunc(b.past, s.hour, func(p hourStats, h int64) int {
		switch {
		case p.hour < h:
			return -1
		case p.hour > h:
			return 1
		}
		return 0
	})
	if found {
		b.past[i].c.add(s.c)
		return
	}
	b.past = slices.Insert(b.past, i, s)
}

// saltFor devolve o sal do dia; num dia novo, sorteia outro e descarta o anterior (ADR 0052 item 2). Um dia mais
// velho que o atual usa o sal atual (aproximação; o sal antigo já foi descartado). Chamada com a.mu.
func (a *Aggregator) saltFor(day int64) [32]byte {
	if day > a.saltDay {
		a.saltDay = day
		_, _ = rand.Read(a.salt[:])
	}
	return a.salt
}

// pathHash é o SHA-256 do caminho com o sal do dia e o site, truncado em 64 bits.
func pathHash(salt [32]byte, site, p string) uint64 {
	h := sha256.New()
	h.Write(salt[:])
	h.Write([]byte(site))
	h.Write([]byte{0})
	h.Write([]byte(p))
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint64(h.Sum(sum[:0]))
}

// ipHash é o SHA-256 do IP com o sal do dia, truncado em 64 bits (contagem aproximada de ips de fp_daily).
func ipHash(salt [32]byte, ip [16]byte) uint64 {
	h := sha256.New()
	h.Write(salt[:])
	h.Write([]byte{1})
	h.Write(ip[:])
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint64(h.Sum(sum[:0]))
}

// cleanPath corta query e fragmento.
func cleanPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	return p
}

// staticExt são as extensões de recursos estáticos.
var staticExt = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".webp": true, ".avif": true, ".bmp": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".webm": true, ".mp3": true, ".ogg": true, ".wav": true,
}

// isStatic diz se o caminho é de recurso estático pela extensão.
func isStatic(p string) bool {
	return staticExt[strings.ToLower(path.Ext(p))]
}

func validKind(k string) bool {
	switch k {
	case "ja4", "akamai", "ja4h", "ja4t":
		return true
	}
	return false
}

func classIndex(c string) int {
	switch c {
	case ClassHuman:
		return 0
	case ClassBot:
		return 1
	case ClassSuspect:
		return 2
	case ClassGoodBot:
		return 3
	}
	return 4
}

func normSite(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) > maxSiteLen {
		return ""
	}
	return s
}

// ipKey é o IP em 16 bytes (IPv4 mapeado em IPv6), a forma do banco.
func ipKey(a netip.Addr) [16]byte {
	return a.Unmap().WithZone("").As16()
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && a < 0 {
		q--
	}
	return q
}

// kmv é o esboço "k minimum values": guarda os k menores hashes distintos e estima a cardinalidade.
type kmv struct {
	vals     []uint64
	overflow bool // algum hash ficou de fora: a contagem deixa de ser exata
}

func (s *kmv) add(h uint64) {
	i, found := slices.BinarySearch(s.vals, h)
	if found {
		return
	}
	if len(s.vals) < kmvK {
		s.vals = slices.Insert(s.vals, i, h)
		return
	}
	s.overflow = true
	if i >= kmvK {
		return
	}
	s.vals = slices.Insert(s.vals, i, h)[:kmvK]
}

// estimate devolve a cardinalidade exata até k e a estimativa (k-1)/v_k acima disso.
func (s *kmv) estimate() int64 {
	if !s.overflow {
		return int64(len(s.vals))
	}
	v := float64(s.vals[kmvK-1]) / float64(math.MaxUint64)
	if v <= 0 {
		return int64(len(s.vals))
	}
	return int64(math.Round(float64(kmvK-1) / v))
}
