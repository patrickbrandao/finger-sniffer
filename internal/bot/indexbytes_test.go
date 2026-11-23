package bot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// indexLoad monta conexões do store e do fork para medir o índice (task 277 e 290). `typical`: store com o TLSInfo
// do web (Chrome), IP/TCP com séries e 16 streams h2; fork com ClientHello/h2 do Chrome e 4 requisições.
// `hostile`: valores únicos — cada stream do store com UA de 512 bytes e um campo único; o fork com 16 requisições
// de caminho de 256 bytes, UA de 512 bytes e campos longos (nada se compartilha).
type indexLoad struct {
	hostile bool
	// long acrescenta ao fork hostil textos únicos acima dos tetos do ingest (método, router, service, entry point,
	// SNI, nomes de campo e de cookie, nome Sec-Fetch-*, valor de campo, JA4H), cortados no check (task 332).
	long     bool
	storeTpl string
	fork     string
	req      string
	forkReqs int
}

func newIndexLoad(tb testing.TB, hostile bool) *indexLoad {
	tb.Helper()
	// TLSInfo como o web publica (listas analisadas com nomes, extensões, ClientHello em base64) e IP/TCP com as
	// séries: o Record precisa ficar só com o que o veredito lê.
	ch, err := tlsparse.Parse(goldenBytes("tls/chrome.bin"))
	if err != nil {
		tb.Fatal(err)
	}
	tlsInfo := tlsparse.NewInfo(ch, goldenBytes("tls/chrome.bin"), tlsparse.DefaultInlineMax)
	ja3.Fill(tlsInfo, ch)
	ja4.Fill(tlsInfo, ch, ja4.TCP)
	series := make([][2]float64, 64)
	tcpInfo := map[string]any{
		"syn":     map[string]any{"window": 65535, "options": [][]any{{"mss", 1432}, {"nop"}, {"wscale", 6}, {"sack_perm"}}},
		"syn_mss": 1432, "mtu_implied": 1492, "mss_reduction": 8, "ja4t": "65535_2-1-3-1-1-8-4-0-0_1432_6",
		"p0f": "6:53+11:0:1432:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:ecn,flow:0", "window_series": series,
		"segments_in": series, "segments_out": series,
	}
	ipInfo := map[string]any{"ttl": 53, "ttl_initial": 64, "hops": 11, "packets": map[string]any{"syn": map[string]any{"ttl": 53}}}
	streams := make([]any, 0, 16)
	for i := 1; i <= 16; i++ {
		st := h2Stream(2*i - 1)
		if hostile {
			fields := st["fields"].([]map[string]any) //nolint:forcetypeassert // montado acima
			fields[4]["value"] = "UNIQ_UA_" + strings.Repeat("u", 500) + fmt.Sprintf("%02d", i)
			fields = append(fields, map[string]any{"name": fmt.Sprintf("x-uniq-%02d-UNIQF", i), "value": "1"})
			st["fields"] = fields
		}
		streams = append(streams, st)
	}
	l := &indexLoad{hostile: hostile, forkReqs: 4}
	if hostile {
		l.forkReqs = maxForkRequests
	}
	l.storeTpl = string(storeMessageWith(tb, "CONNIDCONNIDCONNIDCONNID00", "", 12345, map[string]any{
		"tls": tlsInfo, "tcp": tcpInfo, "ip": ipInfo,
		"http2": map[string]any{"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "streams": streams},
	}))
	l.fork = `{"type":"connection","fs_conn_id":"FSID","ts":"2026-11-16T12:00:00Z","src":{"ip":"198.51.100.7","port":12345},` +
		`"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure","sni":"www.example.com","alpn_offered":["h2","http/1.1"],` +
		`"client_hello":"` + base64.StdEncoding.EncodeToString(goldenBytes("tls/chrome.bin")) + `","h2_prefix":"` +
		base64.StdEncoding.EncodeToString(goldenBytes("h2/chrome.prefix")) + `"}`
	l.req = `{"type":"request","fs_conn_id":"FSID","ts":"2026-11-16T12:00:01Z","proto":"h2","method":"GET","authority":"www.example.com",` +
		`"path":"PATH","http_version":"2.0","field_names":["sec-ch-ua","user-agent","accept","accept-language","cookie"],` +
		`"fields":{"user-agent":"UA","accept":"ACCEPT"},` +
		`"cookie_names":["sid"],"ja4h":"ge20nn05ptbr_aaaaaaaaaaaa_000000000000_000000000000","status":200}`
	return l
}

// storeMsg é a mensagem fs.v1.store.connection da conexão i no estágio dado.
func (l *indexLoad) storeMsg(i int, stage string) []byte {
	id := fmt.Sprintf("01JC0X3K8V2T7Q9N%010d", i)
	msg := strings.Replace(strings.Replace(l.storeTpl, "CONNIDCONNIDCONNIDCONNID00", id, 1), "12345", strconv.Itoa(10000+i%50000), 1)
	if l.hostile {
		msg = strings.ReplaceAll(strings.ReplaceAll(msg, "UNIQ_UA_", id[16:]), "UNIQF", id[16:])
	}
	if stage != StageUpdated {
		before := msg
		msg = strings.Replace(msg, `"stage":"updated"`, `"stage":"`+stage+`"`, 1)
		if msg == before {
			panic("estágio não achado na mensagem")
		}
	}
	return []byte(msg)
}

// add põe no índice a conexão i nas duas visões.
func (l *indexLoad) add(tb testing.TB, ix *Index, i int, now time.Time) {
	tb.Helper()
	sc, err := ParseStoreConnection(l.storeMsg(i, StageOpened))
	if err != nil {
		tb.Fatal(err)
	}
	ix.PutStore(sc, now)
	fid := fmt.Sprintf("01JC0X3K8V2T7Q9F%010d", i)
	port := strconv.Itoa(10000 + i%50000)
	recs := []string{strings.Replace(strings.Replace(l.fork, "FSID", fid, 1), "12345", port, 1)}
	for j := range l.forkReqs {
		path, ua, accept := "/static/app.js", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36", "*/*"
		if l.hostile {
			path = fmt.Sprintf("/%s/%02d/%s", fid, j, strings.Repeat("p", 220))
			ua = fmt.Sprintf("%s-%02d-%s", fid, j, strings.Repeat("u", 480))
			accept = fmt.Sprintf("%s-%02d-%s", fid, j, strings.Repeat("a", 480))
		}
		recs = append(recs, strings.NewReplacer("FSID", fid, "PATH", path, `"UA"`, `"`+ua+`"`, `"ACCEPT"`, `"`+accept+`"`).Replace(l.req))
	}
	if l.long {
		for j := range recs {
			recs[j] = longTexts(recs[j], fmt.Sprintf("%s-%02d", fid, j))
		}
	}
	for j, raw := range recs {
		p, err := parseRecord(json.RawMessage(raw))
		if err != nil {
			tb.Fatal(j, err)
		}
		ix.UpdateFork(fid, now, p.apply)
	}
}

// internerSlack é o que o interner pode reter, na geração, dos textos já cortados de conexões despejadas (8192
// textos de até 255 bytes e as listas e mapas pequenos); sem os cortes e o teto de 1 KiB ele passa de 100 MiB.
const internerSlack = 8 << 20

// longTexts troca os textos do registro do formato anterior por textos únicos de 4 KiB (prefixo tag), todos acima
// dos tetos do ingest.
func longTexts(raw, tag string) string {
	long := func(c string) string { return tag + strings.Repeat(c, 4096) }
	return strings.NewReplacer(
		`"method":"GET"`, `"method":"`+long("m")+`"`,
		`"entry_point":"websecure"`, `"entry_point":"`+long("e")+`","tls_version":"`+long("v")+`","cipher":"`+long("c")+`"`,
		`"sni":"www.example.com"`, `"sni":"`+long("s")+`.example.com"`,
		`"alpn_offered":["h2","http/1.1"]`, `"alpn_offered":["h2","`+long("a")+`"]`,
		`"http_version":"2.0"`, `"http_version":"`+long("h")+`"`,
		`"cookie_names":["sid"]`, `"cookie_names":["`+long("k")+`"]`,
		`"field_names":["sec-ch-ua"`, `"field_names":["`+long("f")+`"`,
		`"fields":{`, `"fields":{"sec-fetch-`+long("x")+`":"1","accept-language":"`+long("l")+`",`,
		`"ja4h":"ge20nn05ptbr_aaaaaaaaaaaa_000000000000_000000000000"`, `"ja4h":"`+long("j")+`"`,
		`"status":200`, `"status":200,"router":"`+long("r")+`","service":"`+long("v")+`"`,
	).Replace(raw)
}

// TestIndexBytesLongIngestTexts: task 332 — com teto de bytes pequeno e textos longos do ingest (cortados nos tetos
// da ADR 0073 item 6), o heap do índice mais o interner fica no teto + 25% + internerSlack depois de despejar
// (antes, o interner segurava os textos de 4 KiB de cada registro despejado até encher a geração). A razão entre
// bot_index_bytes e o heap com esses textos fica no BenchmarkIndexFullMemory (`hostile_long`), que mede sozinho.
func TestIndexBytesLongIngestTexts(t *testing.T) {
	saved := shared
	t.Cleanup(func() { shared = saved })
	const maxBytes = 4 << 20
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	l := newIndexLoad(t, true)
	l.long = true
	shared = &interner{max: maxInterned}
	ix := NewIndex(10*time.Minute, 1000, maxBytes, nil)
	before := heapObjects()
	for i := range 1000 {
		l.add(t, ix, i, now)
	}
	used := heapObjects() - before
	if limit := 1.25*float64(maxBytes) + internerSlack; used > limit {
		t.Errorf("heap do índice e do interner %.0f acima do teto + 25%% + interner (%.0f)", used, limit)
	}
	runtime.KeepAlive(ix)
}

// TestIndexBytesCap: com teto pequeno, conexões hostis despejam as mais antigas por bytes (reason="bytes"), o
// total fica no teto e o health fica degraded com "index bytes" até 60 s depois do último despejo (task 290).
func TestIndexBytesCap(t *testing.T) {
	db, path := testDB(t)
	cfg := testConfig(path)
	cfg.IndexMaxBytes = 512 << 10
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	srv := New(cfg, Deps{DB: db, Now: clock.Now})
	m := srv.deps.Metrics
	l := newIndexLoad(t, true)
	if st, _ := srv.Status(); st != event.StatusOK {
		t.Fatalf("status inicial %s", st)
	}
	for i := range 40 {
		l.add(t, srv.index, i, clock.Now())
		clock.Advance(time.Millisecond)
		if b := srv.index.Bytes(clock.Now()); b > cfg.IndexMaxBytes {
			t.Fatalf("conexão %d: %d bytes acima do teto %d", i, b, cfg.IndexMaxBytes)
		}
	}
	evicted := m.Get(evictedMetric(evictBytes))
	store, fork := srv.index.Len()
	if evicted == 0 || m.Get(evictedMetric(evictCount)) != 0 || store+fork+int(evicted) != 80 {
		t.Fatalf("despejos bytes=%v count=%v, ficaram %d+%d", evicted, m.Get(evictedMetric(evictCount)), store, fork)
	}
	// Ficam as mais novas: a última conexão está nas duas visões, a primeira em nenhuma.
	now := clock.Now()
	if _, ok := srv.index.StoreByID(fmt.Sprintf("01JC0X3K8V2T7Q9N%010d", 39), now); !ok {
		t.Error("a conexão mais nova do store saiu")
	}
	if _, ok := srv.index.Fork(fmt.Sprintf("01JC0X3K8V2T7Q9F%010d", 39), now); !ok {
		t.Error("a conexão mais nova do fork saiu")
	}
	if _, ok := srv.index.StoreByID(fmt.Sprintf("01JC0X3K8V2T7Q9N%010d", 0), now); ok {
		t.Error("a conexão mais antiga ficou")
	}
	srv.updateMetrics()
	if g := m.Get(metricIndexBytes); g <= 0 || g > float64(cfg.IndexMaxBytes) {
		t.Errorf("bot_index_bytes %v", g)
	}
	if st, reasons := srv.Status(); st != event.StatusDegraded || !slices.Contains(reasons, "index bytes") {
		t.Fatalf("depois do despejo: %s %v", st, reasons)
	}
	clock.Advance(59 * time.Second)
	if _, reasons := srv.Status(); !slices.Contains(reasons, "index bytes") {
		t.Error("59 s depois já saiu do degraded")
	}
	clock.Advance(2 * time.Second)
	if st, reasons := srv.Status(); st != event.StatusOK {
		t.Errorf("61 s depois: %s %v", st, reasons)
	}
}

// TestIndexBytesRelease: substituição (updated/closed) não acumula, remoção (forget) e TTL descontam, e o índice
// vencido volta ao custo do índice vazio; o teto de conexões conta reason="count" (task 290).
func TestIndexBytesRelease(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, hostile := range []bool{false, true} {
		t.Run(fmt.Sprintf("hostile=%v", hostile), func(t *testing.T) {
			reasons := map[string]int{}
			ix := NewIndex(10*time.Minute, 3, 0, func(r string, n int) { reasons[r] += n })
			if b := ix.Bytes(now); b != indexEmptyBytes {
				t.Fatalf("vazio: %d, quer %d", b, indexEmptyBytes)
			}
			l := newIndexLoad(t, hostile)
			l.add(t, ix, 0, now)
			one := ix.Bytes(now)
			if one-indexEmptyBytes < 4<<10 {
				t.Fatalf("uma conexão custou só %d", one-indexEmptyBytes)
			}
			// O store republica a conexão (updated, closed, closed): o total não cresce.
			for _, stage := range []string{StageUpdated, StageClosed, StageClosed} {
				sc, err := ParseStoreConnection(l.storeMsg(0, stage))
				if err != nil {
					t.Fatal(err)
				}
				ix.PutStore(sc, now)
				if b := ix.Bytes(now); b < one-16 || b > one+16 { // só o texto do estágio muda
					t.Errorf("%s: %d, antes %d", stage, b, one)
				}
			}
			// Mais requisições no fork que o teto de 16: o total para de crescer quando corta as antigas.
			fid := fmt.Sprintf("01JC0X3K8V2T7Q9F%010d", 0)
			extra := func(j int) {
				raw := strings.NewReplacer("FSID", fid, "PATH", fmt.Sprintf("/x/%04d", j), `"UA"`, `"ua"`, `"ACCEPT"`, `"*/*"`).Replace(l.req)
				p, err := parseRecord(json.RawMessage(raw))
				if err != nil {
					t.Fatal(err)
				}
				ix.UpdateFork(fid, now, p.apply)
			}
			for j := range 2 * maxForkRequests {
				extra(j)
			}
			full := ix.Bytes(now)
			extra(1000)
			if b := ix.Bytes(now); b != full {
				t.Errorf("fork cheio cresceu: %d → %d", full, b)
			}
			l.add(t, ix, 1, now)
			l.add(t, ix, 2, now)
			l.add(t, ix, 3, now.Add(time.Second)) // teto 3 por visão: despeja a 0 nas duas
			if reasons[evictCount] != 2 || reasons[evictBytes] != 0 {
				t.Errorf("despejos %v", reasons)
			}
			if n := ix.Forget(netip.MustParsePrefix("198.51.100.0/24")); n != 3 {
				t.Errorf("forget do fork: %d", n)
			}
			if b := ix.Bytes(now.Add(time.Second)); b <= indexEmptyBytes {
				t.Errorf("depois do forget do fork: %d", b)
			}
			if b := ix.Bytes(now.Add(11 * time.Minute)); b != indexEmptyBytes {
				t.Errorf("depois do TTL: %d, quer %d", b, indexEmptyBytes)
			}
			if reasons[evictCount] != 2 || reasons[evictBytes] != 0 {
				t.Errorf("o TTL contou como despejo: %v", reasons)
			}
		})
	}
}

// TestIndexBytesShared: conexões iguais (navegador típico) compartilham os resumos e textos do interner; cada
// uma a mais custa menos que a primeira, que os criou (ADR 0057 item 2).
func TestIndexBytesShared(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	ix := NewIndex(10*time.Minute, 100, 0, nil)
	l := newIndexLoad(t, false)
	l.add(t, ix, 0, now)
	first := ix.Bytes(now) - indexEmptyBytes
	l.add(t, ix, 1, now)
	second := ix.Bytes(now) - indexEmptyBytes - first
	l.add(t, ix, 2, now)
	third := ix.Bytes(now) - indexEmptyBytes - first - second
	if second >= first || third != second {
		t.Errorf("custos %d, %d, %d", first, second, third)
	}
}

// TestLoadConfigIndexMaxBytes: padrão de 384 MiB, inteiro em bytes, abaixo de 16 MiB a configuração falha.
func TestLoadConfigIndexMaxBytes(t *testing.T) {
	for _, k := range []string{"FS_LISTEN_IPV4", "FS_LISTEN_IPV6", "FS_BOT_INTERNAL_LISTEN", "FS_BOT_INTERNAL_ALLOW", "FS_BOT_INDEX_MAX_BYTES"} {
		t.Setenv(k, "")
	}
	c, err := LoadConfig()
	if err != nil || c.IndexMaxBytes != 402653184 {
		t.Fatalf("padrão: %d %v", c.IndexMaxBytes, err)
	}
	t.Setenv("FS_BOT_INDEX_MAX_BYTES", "16777216")
	if c, err := LoadConfig(); err != nil || c.IndexMaxBytes != 16<<20 {
		t.Errorf("16 MiB: %d %v", c.IndexMaxBytes, err)
	}
	for _, v := range []string{"16777215", "0", "384MiB"} {
		t.Setenv("FS_BOT_INDEX_MAX_BYTES", v)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("%q aceito", v)
		}
	}
}

// heapObjects lê os bytes de objetos vivos no heap (runtime/metrics) depois de um GC completo.
func heapObjects() float64 {
	runtime.GC()
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return float64(s[0].Value.Uint64())
}

// BenchmarkIndexFullMemory: memória do índice cheio (tasks 277 e 290). `typical` com 100 000 conexões nas duas
// visões (FS_BOT_MAX_CONNS) e `hostile` com 10 000, sem teto de bytes: reporta bytes por conexão, o total para
// 100 000 e a razão entre o contabilizado (bot_index_bytes) e o heap medido, que tem de ficar em ±25%.
// `hostile_cap` põe 20 000 conexões hostis com o teto padrão (384 MiB): o heap do índice fica ≤ teto + 25%.
// `hostile_long` é o hostil com textos acima dos tetos do ingest (cortados, task 332), também em ±25%.
func BenchmarkIndexFullMemory(b *testing.B) {
	for _, tc := range []struct {
		name     string
		conns    int
		hostile  bool
		maxBytes int64
		long     bool
	}{
		{"typical", 100_000, false, 0, false},
		{"hostile", 10_000, true, 0, false},
		{"hostile_cap", 20_000, true, DefaultIndexMaxBytes, false},
		{"hostile_long", 2000, true, 0, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			l := newIndexLoad(b, tc.hostile)
			l.long = tc.long
			now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			for range b.N {
				shared = &interner{max: maxInterned} // geração nova: o interner não traz textos de outra rodada
				evicted := 0
				ix := NewIndex(10*time.Minute, tc.conns, tc.maxBytes, func(_ string, n int) { evicted += n })
				before := heapObjects()
				for i := range tc.conns {
					l.add(b, ix, i, now)
				}
				used := heapObjects() - before
				accounted := float64(ix.Bytes(now) - indexEmptyBytes)
				store, fork := ix.Len()
				b.ReportMetric(2*used/float64(store+fork), "B/conn") // as duas visões de uma conexão
				b.ReportMetric(used/(1<<20), "heap-MiB")
				b.ReportMetric(accounted/(1<<20), "accounted-MiB")
				b.ReportMetric(accounted/used, "accounted/heap")
				b.ReportMetric(float64(evicted), "evicted")
				if r := accounted / used; r < 0.75 || r > 1.25 {
					b.Errorf("contabilidade fora de ±25%%: %.0f contabilizados, %.0f no heap (%.2f)", accounted, used, r)
				}
				if tc.maxBytes > 0 && used > 1.25*float64(tc.maxBytes) {
					b.Errorf("heap do índice %.0f acima do teto + 25%% (%d)", used, tc.maxBytes)
				}
				runtime.KeepAlive(ix)
			}
		})
	}
}
