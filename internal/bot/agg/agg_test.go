package agg

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	botmigrations "github.com/patrickbrandao/finger-sniffer/database/sqlite/bot"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// openDB abre um banco do bot migrado num diretório temporário (sem importar o pacote bot, que importa este).
func openDB(t testing.TB) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bot.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
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

func req(at time.Time, ip, site, path string, reused bool, class string) Request {
	return Request{
		Time: at, IP: netip.MustParseAddr(ip), Site: site, Path: path, Reused: reused, Class: class,
		UAFamily: "chrome", Fingerprints: []Fingerprint{{Kind: "ja4", Value: "t13d1516h2_8daaf6152771_02713d6af862"}},
	}
}

type hourRow struct {
	requests, conns, reused, paths, statics, ivN, human, bot, unknown int64
	ivSum, ivSq                                                       float64
}

func readHour(t *testing.T, db *sql.DB, ip, site string, at time.Time) hourRow {
	t.Helper()
	k := ipKey(netip.MustParseAddr(ip))
	var r hourRow
	err := db.QueryRow(`SELECT requests, conns, reused, paths, statics, iv_n, iv_sum, iv_sq_sum, class_human,
		class_bot, class_unknown FROM ip_hourly WHERE ip = ? AND site = ? AND hour = ?`, k[:], site, at.Unix()/3600).
		Scan(&r.requests, &r.conns, &r.reused, &r.paths, &r.statics, &r.ivN, &r.ivSum, &r.ivSq, &r.human, &r.bot,
			&r.unknown)
	if err != nil {
		t.Fatalf("ip_hourly %s %s: %v", ip, site, err)
	}
	return r
}

// TestObserveQuery: contagens da hora, caminhos distintos (query cortada), estáticos, reuso, intervalos e taxa.
func TestObserveQuery(t *testing.T) {
	a := New(Config{})
	ip := "192.0.2.10"
	paths := []string{"/", "/a?x=1", "/a?x=2", "/b", "/style.css", "/app.JS", "/img/logo.png#top"}
	for i, p := range paths {
		a.Observe(req(t0.Add(time.Duration(i)*2*time.Second), ip, "Example.com", p, i > 0, ClassHuman))
	}
	st := a.Query(netip.MustParseAddr("::ffff:"+ip), "example.com", t0.Add(13*time.Second))
	if !st.Known || st.HourRequests != 7 || st.HourConns != 1 || st.HourReused != 6 {
		t.Fatalf("contagens: %+v", st)
	}
	// "/", "/a", "/b", "/style.css", "/app.JS", "/img/logo.png" = 6 distintos; 3 estáticos.
	if st.HourPaths != 6 || st.HourStatics != 3 {
		t.Fatalf("caminhos %d estáticos %d", st.HourPaths, st.HourStatics)
	}
	if iv := st.HourIntervals; iv.N != 6 || iv.Sum != 12 || iv.SqSum != 24 || iv.Mean() != 2 || iv.StdDev() != 0 {
		t.Fatalf("intervalos %+v", iv)
	}
	if st.RequestsPerMin != 7 || st.DayRequests != 7 || st.Hours != 1 {
		t.Fatalf("taxa %v dia %d horas %d", st.RequestsPerMin, st.DayRequests, st.Hours)
	}
	// Outro site e outro IP não se misturam.
	if a.Query(netip.MustParseAddr(ip), "other.com", t0).Known || a.Query(netip.MustParseAddr("192.0.2.11"), "example.com", t0).Known {
		t.Fatal("vazou entre chaves")
	}
	// Taxa deslizante: um minuto e meio depois só sobra metade do balde anterior.
	if r := a.Query(netip.MustParseAddr(ip), "example.com", t0.Add(90*time.Second)).RequestsPerMin; r != 3.5 {
		t.Fatalf("taxa deslizante %v", r)
	}
	if r := a.Query(netip.MustParseAddr(ip), "example.com", t0.Add(3*time.Minute)).RequestsPerMin; r != 0 {
		t.Fatalf("taxa velha %v", r)
	}
}

// TestFlushUpsertAndFailure: o flush soma no banco; com falha, os acumuladores ficam e o próximo grava o delta
// inteiro; fp_daily conta requisições, classes e IPs distintos.
func TestFlushUpsertAndFailure(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := New(Config{})
	a.Observe(req(t0, "192.0.2.1", "s.com", "/x", false, ClassBot))
	a.Observe(req(t0.Add(time.Second), "192.0.2.1", "s.com", "/y", true, ClassBot))
	if err := a.Flush(ctx, db, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Banco fechado: o flush falha e nada se perde.
	bad := openDB(t)
	_ = bad.Close()
	a.Observe(req(t0.Add(2*time.Second), "192.0.2.1", "s.com", "/x", true, ClassHuman))
	a.Observe(req(t0.Add(3*time.Second), "192.0.2.2", "s.com", "/z.css", false, ClassUnknown))
	if err := a.Flush(ctx, bad, t0.Add(3*time.Second)); err == nil {
		t.Fatal("flush num banco fechado sem erro")
	}
	a.Observe(req(t0.Add(4*time.Second), "192.0.2.1", "s.com", "/w", true, ClassHuman))
	if err := a.Flush(ctx, db, t0.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Flush sem novidade não muda nada.
	if err := a.Flush(ctx, db, t0.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	r := readHour(t, db, "192.0.2.1", "s.com", t0)
	want := hourRow{requests: 4, conns: 1, reused: 3, paths: 3, ivN: 3, ivSum: 4, ivSq: 6, human: 2, bot: 2}
	if r != want {
		t.Fatalf("ip_hourly %+v, quer %+v", r, want)
	}
	r2 := readHour(t, db, "192.0.2.2", "s.com", t0)
	if r2.requests != 1 || r2.statics != 1 || r2.unknown != 1 || r2.ivN != 0 {
		t.Fatalf("segundo IP %+v", r2)
	}
	var reqs, ips, cb, ch int64
	if err := db.QueryRow(`SELECT requests, ips, class_bot, class_human FROM fp_daily WHERE kind = 'ja4' AND ua_family = 'chrome' AND day = ?`,
		t0.Unix()/86400).Scan(&reqs, &ips, &cb, &ch); err != nil {
		t.Fatal(err)
	}
	if reqs != 5 || ips != 2 || cb != 2 || ch != 2 {
		t.Fatalf("fp_daily requests %d ips %d bot %d human %d", reqs, ips, cb, ch)
	}
}

// TestMaxEntries: o teto de entradas descarta e conta, e a memória não cresce além dele com o flush falhando.
func TestMaxEntries(t *testing.T) {
	a := New(Config{MaxEntries: 10})
	for i := range 50 {
		a.Observe(Request{Time: t0, IP: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), Site: "s.com", Path: "/"})
	}
	if a.Entries() > 10 {
		t.Fatalf("%d entradas acima do teto", a.Entries())
	}
	if a.Dropped() != 45 { // 5 IPs couberam (comportamento + hora cada)
		t.Fatalf("descartes %d", a.Dropped())
	}
	bad := openDB(t)
	_ = bad.Close()
	for h := range 30 {
		at := t0.Add(time.Duration(h) * time.Hour)
		a.Observe(Request{Time: at, IP: netip.MustParseAddr("198.51.100.1"), Site: "s.com", Path: "/"})
		_ = a.Flush(context.Background(), bad, at)
		if a.Entries() > 10 {
			t.Fatalf("hora %d: %d entradas", h, a.Entries())
		}
	}
}

// TestCacheWithoutDisk: depois do flush, a leitura do cache de comportamento (hora corrente e horas gravadas) não
// precisa do banco, mesmo fechado.
func TestCacheWithoutDisk(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := New(Config{})
	ip := netip.MustParseAddr("2001:db8::7")
	for h := range 3 {
		for i := range 10 {
			a.Observe(req(t0.Add(time.Duration(h)*time.Hour+time.Duration(i)*time.Second), ip.String(), "s.com",
				fmt.Sprintf("/p%d", i), i > 0, ClassHuman))
		}
		if err := a.Flush(ctx, db, t0.Add(time.Duration(h)*time.Hour+time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Flush(ctx, db, t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st := a.Query(ip, "s.com", t0.Add(2*time.Hour+30*time.Minute))
	if st.Hours != 3 || st.DayRequests != 30 || st.DayPaths != 30 || st.HourRequests != 10 || st.DayConns != 3 {
		t.Fatalf("cache %+v", st)
	}
	// Intervalos atravessam as horas: 29 intervalos.
	if st.DayIntervals.N != 29 {
		t.Fatalf("intervalos %+v", st.DayIntervals)
	}
}

// TestLoad: no início, as horas gravadas das últimas 24 h voltam ao cache e somam com o que chegar depois.
func TestLoad(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := New(Config{})
	ip := "192.0.2.50"
	a.Observe(req(t0.Add(-30*time.Hour), ip, "s.com", "/old", false, ClassHuman)) // fora da janela de 24 h
	a.Observe(req(t0.Add(-2*time.Hour), ip, "s.com", "/a", false, ClassHuman))
	a.Observe(req(t0, ip, "s.com", "/b", false, ClassHuman))
	if err := a.Flush(ctx, db, t0); err != nil {
		t.Fatal(err)
	}
	b := New(Config{})
	if err := b.Load(ctx, db, t0); err != nil {
		t.Fatal(err)
	}
	b.Observe(req(t0.Add(time.Second), ip, "s.com", "/c", false, ClassHuman))
	st := b.Query(netip.MustParseAddr(ip), "s.com", t0.Add(time.Second))
	if st.DayRequests != 3 || st.HourRequests != 2 || st.Hours != 2 {
		t.Fatalf("depois do load %+v", st)
	}
	if err := b.Flush(ctx, db, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := b.Query(netip.MustParseAddr(ip), "s.com", t0.Add(time.Hour)); st.DayRequests != 3 {
		t.Fatalf("hora fechada duplicou: %+v", st)
	}
	if r := readHour(t, db, ip, "s.com", t0); r.requests != 2 {
		t.Fatalf("banco %+v", r)
	}
}

// TestMemoryRetention: relógio falso; nada com IP fica na memória além da janela de 24 h do cache (e nunca além de
// 7 dias e 1 hora), e uma hora que o flush nunca conseguiu gravar sai depois de MaxAge.
func TestMemoryRetention(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := New(Config{})
	a.Observe(req(t0, "192.0.2.1", "s.com", "/", false, ClassHuman))
	for h := 1; h <= 7*24+1; h++ {
		if err := a.Flush(ctx, db, t0.Add(time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if h >= BehaviorHours && a.Entries() != 0 {
			t.Fatalf("hora %d: %d entradas", h, a.Entries())
		}
	}
	// Sem banco: a hora não gravada expira em MaxAge e conta como descarte.
	b := New(Config{MaxAge: 7 * 24 * time.Hour})
	bad := openDB(t)
	_ = bad.Close()
	b.Observe(req(t0, "192.0.2.1", "s.com", "/", false, ClassHuman))
	_ = b.Flush(ctx, bad, t0.Add(7*24*time.Hour))
	if b.Entries() == 0 {
		t.Fatal("expirou cedo demais")
	}
	_ = b.Flush(ctx, bad, t0.Add(7*24*time.Hour+time.Hour))
	if n := b.Entries() - len(b.fps); n != 0 || b.Dropped() != 1 {
		t.Fatalf("entradas com IP %d descartes %d", n, b.Dropped())
	}
	// A fingerprint (sem IP) sai quando o dia inteiro passa de MaxAge.
	_ = b.Flush(ctx, bad, t0.Add(8*24*time.Hour))
	if b.Entries() != 0 || b.Dropped() != 2 {
		t.Fatalf("entradas %d descartes %d", b.Entries(), b.Dropped())
	}
}

// TestForget: apaga da memória o prefixo inteiro (v4 e v6) e nada além.
func TestForget(t *testing.T) {
	a := New(Config{})
	for _, ip := range []string{"192.0.2.1", "192.0.2.200", "192.0.3.1", "2001:db8::1", "2001:db8:1::1"} {
		a.Observe(req(t0, ip, "s.com", "/", false, ClassHuman))
		a.Observe(req(t0, ip, "t.com", "/", false, ClassHuman))
	}
	if n := a.Forget(netip.MustParsePrefix("192.0.2.0/24")); n != 4 {
		t.Fatalf("forget v4: %d", n)
	}
	if n := a.Forget(netip.MustParsePrefix("2001:db8::/48")); n != 2 {
		t.Fatalf("forget v6: %d", n)
	}
	if a.Query(netip.MustParseAddr("192.0.2.1"), "s.com", t0).Known || !a.Query(netip.MustParseAddr("192.0.3.1"), "s.com", t0).Known {
		t.Fatal("forget errado")
	}
	if !a.Query(netip.MustParseAddr("2001:db8:1::1"), "t.com", t0).Known {
		t.Fatal("forget v6 apagou demais")
	}
	// Só sobram as fingerprints do dia (sem IP) e as 2 chaves restantes (comportamento + hora).
	if got := a.Entries() - len(a.fps); got != 8 {
		t.Fatalf("entradas com IP %d", got)
	}
}

// TestNoPathInClear: o caminho e a query nunca ficam na memória nem no banco.
func TestNoPathInClear(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := New(Config{})
	const secret = "/private-path-7f3a/segredo.css"
	const query = "token=abc123xyz"
	a.Observe(req(t0, "192.0.2.9", "s.com", secret+"?"+query, false, ClassHuman))
	var found []string
	walk(reflect.ValueOf(a), func(s string) {
		if strings.Contains(s, "private-path") || strings.Contains(s, "abc123") {
			found = append(found, s)
		}
	})
	if len(found) > 0 {
		t.Fatalf("caminho em claro na memória: %q", found)
	}
	if err := a.Flush(ctx, db, t0); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"ip_hourly", "fp_daily"} {
		rows, err := db.Query("SELECT * FROM " + tbl)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for _, v := range vals {
				s := fmt.Sprint(v)
				if b, ok := v.([]byte); ok {
					s = string(b)
				}
				if strings.Contains(s, "private-path") || strings.Contains(s, "abc123") {
					t.Fatalf("caminho em claro em %s: %q", tbl, s)
				}
			}
		}
		_ = rows.Close()
	}
}

// walk percorre o valor (ponteiros, structs, mapas, slices, arrays) e entrega toda string e todo []byte.
func walk(v reflect.Value, f func(string)) {
	seen := map[uintptr]bool{}
	var rec func(v reflect.Value)
	rec = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			rec(v.Elem())
		case reflect.Interface:
			if !v.IsNil() {
				rec(v.Elem())
			}
		case reflect.Struct:
			for i := range v.NumField() {
				rec(v.Field(i))
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				rec(it.Key())
				rec(it.Value())
			}
		case reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				f(string(v.Bytes()))
				return
			}
			for i := range v.Len() {
				rec(v.Index(i))
			}
		case reflect.Array:
			for i := range v.Len() {
				rec(v.Index(i))
			}
		case reflect.String:
			f(v.String())
		}
	}
	rec(v)
}

// TestKMV: a estimativa de IPs distintos é exata até k e fica a ±15% acima disso.
func TestKMV(t *testing.T) {
	var salt [32]byte
	for _, n := range []int{1, 100, 256, 5000, 50000} {
		var s kmv
		for i := range n {
			var ip [16]byte
			ip[12], ip[13], ip[14], ip[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
			s.add(ipHash(salt, ip))
			s.add(ipHash(salt, ip)) // repetido não conta
		}
		est := float64(s.estimate())
		if n <= kmvK && est != float64(n) {
			t.Errorf("n=%d estimativa %v", n, est)
		}
		if math.Abs(est-float64(n))/float64(n) > 0.15 {
			t.Errorf("n=%d estimativa %v", n, est)
		}
	}
}

// populated cria um acumulador com n pares IP + site e 24 h de cache.
func populated(tb testing.TB, n int) (*Aggregator, []netip.Addr) {
	tb.Helper()
	a := New(Config{MaxEntries: 1 << 22})
	ips := make([]netip.Addr, n)
	for i := range n {
		ips[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	for h := range BehaviorHours {
		at := t0.Add(time.Duration(h) * time.Hour)
		for _, ip := range ips {
			a.Observe(Request{Time: at, IP: ip, Site: "s.com", Path: "/", Class: ClassHuman})
		}
		a.mu.Lock()
		for _, b := range a.sites {
			for _, hr := range b.open {
				hr.flushed = hr.cur // como depois de um flush bem-sucedido
			}
		}
		a.maintain(at.Add(time.Hour))
		a.mu.Unlock()
	}
	return a, ips
}

// TestQueryP99: p99 da consulta ao cache abaixo de 1 ms com 10 000 pares IP + site e 24 h de horas cada.
func TestQueryP99(t *testing.T) {
	a, ips := populated(t, 10000)
	now := t0.Add(BehaviorHours*time.Hour - time.Minute)
	lat := make([]time.Duration, 0, 20000)
	for i := range 20000 {
		start := time.Now()
		st := a.Query(ips[i%len(ips)], "s.com", now)
		lat = append(lat, time.Since(start))
		if st.DayRequests != BehaviorHours-1 && st.DayRequests != BehaviorHours {
			t.Fatalf("cache %+v", st)
		}
	}
	slices.Sort(lat)
	if p99 := lat[len(lat)*99/100]; p99 > time.Millisecond {
		t.Fatalf("p99 %s", p99)
	}
}

func BenchmarkQuery(b *testing.B) {
	a, ips := populated(b, 10000)
	now := t0.Add(BehaviorHours*time.Hour - time.Minute)
	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		start := time.Now()
		a.Query(ips[i%len(ips)], "s.com", now)
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	slices.Sort(lat)
	if len(lat) > 0 {
		b.ReportMetric(float64(lat[len(lat)*99/100].Nanoseconds()), "p99-ns")
	}
}

func BenchmarkObserve(b *testing.B) {
	a := New(Config{MaxEntries: 1 << 22})
	r := req(t0, "192.0.2.1", "s.com", "/a/b", true, ClassHuman)
	for i := 0; b.Loop(); i++ {
		r.IP = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		a.Observe(r)
	}
}

// TestOriginSitesLimit: 100 000 sites de um IP não impedem Query de outro IP de ter Known=true e a taxa certa; a
// origem fica com 32 entradas de hora e o resto conta em ip_sites, o que ela já tem segue acumulando, e outro IP do
// mesmo /64 IPv6 divide o teto (task 363, ADR 0073 item 7.1).
func TestOriginSitesLimit(t *testing.T) {
	a := New(Config{Now: func() time.Time { return t0 }})
	for i := range 100_000 {
		a.Observe(Request{Time: t0, IP: netip.MustParseAddr("203.0.113.9"), Site: fmt.Sprintf("r%06d.example", i), Path: "/"})
	}
	if got := a.Limited(LimitIPSites); got != 100_000-MaxSitesPerOrigin {
		t.Fatalf("ip_sites %d", got)
	}
	if a.Entries() != 2*MaxSitesPerOrigin || a.Dropped() != 0 {
		t.Fatalf("entradas %d descartes %d", a.Entries(), a.Dropped())
	}
	a.Observe(Request{Time: t0, IP: netip.MustParseAddr("203.0.113.9"), Site: "r000000.example", Path: "/"})
	if st := a.Query(netip.MustParseAddr("203.0.113.9"), "r000000.example", t0); st.HourRequests != 2 {
		t.Fatalf("site já da origem não acumulou: %+v", st)
	}
	for i := range 200 {
		a.Observe(Request{Time: t0.Add(time.Duration(i) * 100 * time.Millisecond), IP: netip.MustParseAddr("198.51.100.4"), Site: "site.example", Path: "/"})
	}
	st := a.Query(netip.MustParseAddr("198.51.100.4"), "site.example", t0.Add(20*time.Second))
	if !st.Known || st.HourRequests != 200 || st.RequestsPerMin != 200 {
		t.Fatalf("outro IP: %+v", st)
	}
	// IPv6: o /64 é a origem
	for i := range 40 {
		ip := netip.MustParseAddr(fmt.Sprintf("2001:db8:7:7::%x", i+1))
		a.Observe(Request{Time: t0, IP: ip, Site: "v6.example", Path: "/"})
	}
	if got := a.Limited(LimitIPSites); got != 100_000-MaxSitesPerOrigin+8 {
		t.Fatalf("ip_sites com o /64: %d", got)
	}
	// na hora seguinte a origem tem o teto de novo
	a.Observe(Request{Time: t0.Add(time.Hour), IP: netip.MustParseAddr("203.0.113.9"), Site: "nova.example", Path: "/"})
	if st := a.Query(netip.MustParseAddr("203.0.113.9"), "nova.example", t0.Add(time.Hour)); !st.Known {
		t.Fatal("teto da origem não zerou na hora nova")
	}
}

// TestOriginFingerprintsLimit: até 256 fingerprints novas por origem no dia; as existentes seguem contando; o dia
// novo zera (ADR 0073 item 7.2).
func TestOriginFingerprintsLimit(t *testing.T) {
	a := New(Config{})
	ip := netip.MustParseAddr("203.0.113.10")
	for i := range 300 {
		a.Observe(Request{Time: t0, IP: ip, Site: "s.example", Path: "/", Fingerprints: []Fingerprint{{Kind: "ja4", Value: fmt.Sprintf("v%d", i)}}})
	}
	if got := a.Limited(LimitIPFingerprints); got != 300-MaxFingerprintsPerOrigin || len(a.fps) != MaxFingerprintsPerOrigin {
		t.Fatalf("ip_fingerprints %d fps %d", got, len(a.fps))
	}
	a.Observe(Request{Time: t0, IP: ip, Site: "s.example", Path: "/", Fingerprints: []Fingerprint{{Kind: "ja4", Value: "v0"}}})
	if f := a.fps[fpKey{kind: "ja4", value: "v0", day: t0.Unix() / 86400, ua: "other"}]; f == nil || f.requests != 2 {
		t.Fatalf("existente não contou: %+v", f)
	}
	// outro IP cria a sua
	a.Observe(Request{Time: t0, IP: netip.MustParseAddr("198.51.100.5"), Site: "s.example", Path: "/", Fingerprints: []Fingerprint{{Kind: "ja4", Value: "w"}}})
	if len(a.fps) != MaxFingerprintsPerOrigin+1 {
		t.Fatalf("fps %d", len(a.fps))
	}
	a.Observe(Request{Time: t0.Add(24 * time.Hour), IP: ip, Site: "s.example", Path: "/", Fingerprints: []Fingerprint{{Kind: "ja4", Value: "z"}}})
	if got := a.Limited(LimitIPFingerprints); got != 300-MaxFingerprintsPerOrigin {
		t.Fatalf("dia novo ainda limitado: %d", got)
	}
}

// TestEvictWhenFull: com o teto global cheio, os comportamentos menos recentes já gravados saem da memória (1% do
// teto por passo, bot_agg_evicted_total) em vez de recusar o novo; sem nada gravado, o novo é descartado como antes.
// As duas situações marcam o health (agg full) por 60 s (ADR 0073 item 7.4).
func TestEvictWhenFull(t *testing.T) {
	now := t0
	a := New(Config{MaxEntries: 200, Now: func() time.Time { return now }})
	obs := func(i int, at time.Time) {
		a.Observe(Request{Time: at, IP: netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), Site: "s.example", Path: "/"})
	}
	for i := range 100 {
		obs(i, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if a.Entries() != 200 || a.FullSince(now, time.Minute) {
		t.Fatalf("entradas %d", a.Entries())
	}
	obs(100, t0) // nada gravado: descarte
	if a.Dropped() != 1 || a.Evicted() != 0 || !a.FullSince(now, time.Minute) {
		t.Fatalf("descartes %d despejos %d", a.Dropped(), a.Evicted())
	}
	if err := a.Flush(context.Background(), openDB(t), t0); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second) // passa a espera da varredura vazia
	obs(101, t0.Add(time.Second))
	// 1% de 200 = 2 comportamentos despejados (os 2 mais antigos), o novo entra
	if a.Evicted() != 2 || a.Dropped() != 1 || a.Entries() != 198 {
		t.Fatalf("despejos %d descartes %d entradas %d", a.Evicted(), a.Dropped(), a.Entries())
	}
	if a.Query(netip.AddrFrom4([4]byte{198, 18, 0, 0}), "s.example", t0).Known || !a.Query(netip.AddrFrom4([4]byte{198, 18, 0, 2}), "s.example", t0).Known {
		t.Fatal("despejou o comportamento errado")
	}
	if !a.Query(netip.AddrFrom4([4]byte{198, 18, 0, 101}), "s.example", t0.Add(time.Second)).Known {
		t.Fatal("o novo não entrou")
	}
	if a.FullSince(now.Add(time.Minute), time.Minute) {
		t.Fatal("marca de cheio não expirou")
	}
}
