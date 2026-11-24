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
	// fingerprints do dia); cheio, despeja os comportamentos menos recentes já gravados e, sem nenhum, descarta a
	// observação e conta em bot_agg_dropped_total (ADR 0073 item 7.4).
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
	// MaxSitesPerOrigin é o teto de entradas de hora (IP + site) que uma origem (IPv4; IPv6 por /64) cria numa hora;
	// MaxFingerprintsPerOrigin, o de fingerprints novas no dia (ADR 0073 item 7).
	MaxSitesPerOrigin        = 32
	MaxFingerprintsPerOrigin = 256
	// evictFraction é a fração do teto despejada por passo com o teto global cheio (1%); emptyScanBackoff é o
	// intervalo entre varreduras quando nada era despejável (tudo por gravar).
	evictFraction    = 100
	emptyScanBackoff = time.Second
)

// Motivos de bot_agg_limited_total.
const (
	LimitIPSites        = "ip_sites"
	LimitIPFingerprints = "ip_fingerprints"
	// LimitKey é a parte por chave da 9002 (ADR 0073 item 3.2).
	LimitKey = "key"
)

// Partes das entradas para as chaves da 9002 (ADR 0073 item 3.2): cada chave até 1/keyShareDiv (10%) e todas juntas
// até 1/keyedShareDiv (50%) do teto.
const (
	keyShareDiv   = 10
	keyedShareDiv = 2
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
	// Owner é a chave da 9002 que mandou a requisição (id da chave); "" = interna (9003, com ou sem chave).
	Owner string
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
	// Now é o relógio da marca de teto cheio (FullSince; time.Now se nil).
	Now func() time.Time
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
	owner        string // chave da 9002 que criou a entrada ("" = interna)
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
	owner   string      // chave da 9002 que criou a entrada ("" = interna)
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
	owner                                     string // chave da 9002 que criou a entrada ("" = interna)
}

// originCount conta o que uma origem criou na hora (entradas de hora) e no dia (fingerprints novas).
type originCount struct {
	hour, sites int64
	day, fps    int64
}

// Aggregator é o acumulador dos agregados e o cache de comportamento. Seguro para uso concorrente.
type Aggregator struct {
	maxEntries int
	maxAge     time.Duration
	now        func() time.Time
	flushMu    sync.Mutex // serializa os flushes

	mu      sync.Mutex
	entries int // comportamentos + horas abertas + fingerprints
	saltDay int64
	salt    [32]byte
	sites   map[siteKey]*behavior
	fps     map[fpKey]*fpAcc
	origins map[[16]byte]*originCount
	// byOwner e keyed são as entradas de cada chave da 9002 e de todas juntas (parte por chave).
	byOwner map[string]int
	keyed   int

	dropped      atomic.Uint64
	evicted      atomic.Uint64
	limitedSites atomic.Uint64
	limitedFPs   atomic.Uint64
	limitedKey   atomic.Uint64
	fullAt       atomic.Int64 // UnixNano do último despejo ou descarte pelo teto global
	emptyScanAt  time.Time    // última varredura de despejo que não achou nada despejável
}

// New cria o acumulador.
func New(cfg Config) *Aggregator {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 7 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Aggregator{
		maxEntries: cfg.MaxEntries, maxAge: cfg.MaxAge, now: cfg.Now, saltDay: math.MinInt64,
		sites: map[siteKey]*behavior{}, fps: map[fpKey]*fpAcc{}, origins: map[[16]byte]*originCount{},
		byOwner: map[string]int{},
	}
}

// Evicted devolve quantos comportamentos já gravados saíram da memória pelo teto global (bot_agg_evicted_total).
func (a *Aggregator) Evicted() uint64 { return a.evicted.Load() }

// Limited devolve quantas observações (ou fingerprints) foram cortadas pelo teto por origem do motivo dado
// (bot_agg_limited_total{reason}).
func (a *Aggregator) Limited(reason string) uint64 {
	switch reason {
	case LimitIPSites:
		return a.limitedSites.Load()
	case LimitIPFingerprints:
		return a.limitedFPs.Load()
	case LimitKey:
		return a.limitedKey.Load()
	}
	return 0
}

// FullSince diz se houve despejo ou descarte pelo teto global nos últimos d (health agg full).
func (a *Aggregator) FullSince(now time.Time, d time.Duration) bool {
	t := a.fullAt.Load()
	return t != 0 && now.Sub(time.Unix(0, t)) < d
}

// originKey é a origem do teto por origem: o IPv4 ou o /64 do IPv6, em 16 bytes.
func originKey(ip [16]byte) [16]byte {
	a := netip.AddrFrom16(ip).Unmap()
	if a.Is4() {
		return ip
	}
	for i := 8; i < 16; i++ {
		ip[i] = 0
	}
	return ip
}

// origin devolve os contadores da origem já trazidos para a hora e o dia dados (uma hora ou dia mais novo zera;
// mais velho conta no corrente). Chamada com a.mu.
func (a *Aggregator) origin(ip [16]byte, hour, day int64) *originCount {
	o := a.origins[originKey(ip)]
	if o == nil {
		o = &originCount{hour: hour, day: day}
		a.origins[originKey(ip)] = o
	}
	if hour > o.hour {
		o.hour, o.sites = hour, 0
	}
	if day > o.day {
		o.day, o.fps = day, 0
	}
	return o
}

// ownerRoom diz se o dono pode criar n entradas dentro da parte dele (sempre para as internas). Chamada com a.mu.
func (a *Aggregator) ownerRoom(owner string, n int) bool {
	if owner == "" {
		return true
	}
	return a.byOwner[owner]+n <= max(1, a.maxEntries/keyShareDiv) && a.keyed+n <= max(1, a.maxEntries/keyedShareDiv)
}

// charge soma (n > 0) ou tira (n < 0) entradas do dono. Chamada com a.mu.
func (a *Aggregator) charge(owner string, n int) {
	if owner == "" {
		return
	}
	a.keyed += n
	if a.byOwner[owner] += n; a.byOwner[owner] <= 0 {
		delete(a.byOwner, owner)
	}
}

// removeBehavior tira o comportamento e as horas abertas dele da memória e das contas. Chamada com a.mu.
func (a *Aggregator) removeBehavior(k siteKey, b *behavior) {
	a.entries -= 1 + len(b.open)
	a.charge(b.owner, -1)
	for _, h := range b.open {
		a.charge(h.owner, -1)
	}
	delete(a.sites, k)
}

// room garante espaço para n entradas novas: com o teto cheio, despeja os comportamentos menos recentes já gravados
// (1% do teto por passo, sem tocar em skip); sem nada despejável, conta o descarte. Chamada com a.mu.
func (a *Aggregator) room(n int, skip siteKey) bool {
	if a.entries+n <= a.maxEntries {
		return true
	}
	a.fullAt.Store(a.now().UnixNano())
	if now := a.now(); now.Sub(a.emptyScanAt) >= emptyScanBackoff || now.Before(a.emptyScanAt) {
		a.evictLocked(max(1, a.maxEntries/evictFraction), skip, now)
	}
	if a.entries+n <= a.maxEntries {
		return true
	}
	a.dropped.Add(1)
	return false
}

// evictLocked tira da memória até n comportamentos menos recentes com todas as horas gravadas (o histórico segue no
// banco). Sem nada despejável, a próxima varredura espera emptyScanBackoff. Chamada com a.mu.
func (a *Aggregator) evictLocked(n int, skip siteKey, now time.Time) {
	type cand struct {
		k    siteKey
		last time.Time
	}
	var cs []cand
	for k, b := range a.sites {
		if k == skip || !b.flushed() {
			continue
		}
		cs = append(cs, cand{k, b.last})
	}
	if len(cs) == 0 {
		a.emptyScanAt = now
		return
	}
	slices.SortFunc(cs, func(x, y cand) int { return x.last.Compare(y.last) })
	for _, c := range cs[:min(n, len(cs))] {
		a.removeBehavior(c.k, a.sites[c.k])
		a.evicted.Add(1)
	}
}

// flushed diz se todas as horas abertas do comportamento já foram gravadas.
func (b *behavior) flushed() bool {
	for _, h := range b.open {
		if h.cur != h.flushed {
			return false
		}
	}
	return true
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
	h := (*hourAcc)(nil)
	if b != nil {
		h = b.open[hour]
	}
	if h == nil {
		// entrada de hora nova (com ou sem comportamento novo): teto por origem na hora e depois o global
		o := a.origin(k.ip, hour, day)
		if o.sites >= MaxSitesPerOrigin {
			a.limitedSites.Add(1)
			return
		}
		need := 1
		if b == nil {
			need = 2
		}
		if !a.ownerRoom(r.Owner, need) {
			a.limitedKey.Add(1)
			return
		}
		if !a.room(need, k) {
			return
		}
		if b == nil {
			b = &behavior{open: map[int64]*hourAcc{}, owner: r.Owner}
			a.sites[k] = b
			a.entries++
		}
		h = &hourAcc{paths: map[uint64]struct{}{}, owner: r.Owner}
		b.open[hour] = h
		a.entries++
		a.charge(r.Owner, need)
		o.sites++
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
			o := a.origin(k.ip, hour, day)
			if o.fps >= MaxFingerprintsPerOrigin {
				a.limitedFPs.Add(1)
				continue
			}
			if !a.ownerRoom(r.Owner, 1) {
				a.limitedKey.Add(1)
				continue
			}
			if !a.room(1, k) {
				continue
			}
			acc = &fpAcc{owner: r.Owner}
			a.fps[fk] = acc
			a.entries++
			a.charge(r.Owner, 1)
			o.fps++
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
			a.removeBehavior(k, b)
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
				a.dropped.Add(uint64(max(0, h.cur.requests-h.flushed.requests)))
			default:
				continue
			}
			delete(b.open, hr)
			a.entries--
			a.charge(h.owner, -1)
		}
		b.past = slices.DeleteFunc(b.past, func(p hourStats) bool { return p.hour < first })
		if len(b.open) == 0 && len(b.past) == 0 {
			a.removeBehavior(k, b)
		}
	}
	// contadores por origem: só os da hora ou do dia correntes têm efeito
	for k, o := range a.origins {
		if o.hour < cur && o.day < day {
			delete(a.origins, k)
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
			a.charge(f.owner, -1)
		} else if k.day < oldestDay {
			a.dropped.Add(uint64(max(0, f.requests-f.flushedRequests)))
			delete(a.fps, k)
			a.entries--
			a.charge(f.owner, -1)
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
