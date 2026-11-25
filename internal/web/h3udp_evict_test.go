package web

import (
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// rfcInitial é o Initial do cliente da RFC 9001 (apêndice A.2): ClientHello completo num datagrama.
func rfcInitial(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("../../pkg/quicparse/testdata/rfc9001-client-initial.hex")
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unknownVersion é um cabeçalho longo de versão desconhecida: a análise para no primeiro datagrama sem
// ClientHello, com versão legível (vira handshake_failed).
func unknownVersion(dcid byte) []byte {
	return []byte{0xc0, 0x0a, 0x0a, 0x0a, 0x0a, 1, dcid, 0, 0}
}

func checkTrackerInvariants(t *testing.T, tr *initTracker) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.n != len(trackerEntries(tr)) {
		t.Fatalf("contador %d, entradas %d", tr.n, len(trackerEntries(tr)))
	}
	if tr.n > initMaxEntries || tr.bytes < 0 || tr.bytes > initMaxBytes {
		t.Fatalf("tetos: %d entradas, %d bytes", len(tr.m), tr.bytes)
	}
	if n := tr.evictNoCH.Len() + tr.evictCH.Len(); n > tr.n {
		t.Fatalf("fila de despejo %d > tabela %d", n, tr.n)
	}
	sum := 0
	for _, e := range trackerEntries(tr) {
		sum += e.bytes
		if e.claimed && e.evict != nil {
			t.Fatal("reclamada na fila de despejo")
		}
	}
	if sum != tr.bytes {
		t.Fatalf("bytes %d, soma das entradas %d", tr.bytes, sum)
	}
}

// TestInitTrackerEvictsWhenFull: com a tabela cheia de Initials forjados sem ClientHello, o Initial
// legítimo de uma 5-tupla nova ainda é analisado, o contador sobe e a despejada com versão legível vira
// handshake_failed (task 143).
func TestInitTrackerEvictsWhenFull(t *testing.T) {
	tr := newTestTracker(t)
	var orphans []*initEntry
	tr.orphans = func(e *initEntry, _ *quicparse.Info) { orphans = append(orphans, e) }
	local := udpAddr(443)
	tr.observe(local, udpAddr(9999), []byte{0x80, 1, 2}) // ilegível: não abre entrada (task 350)
	if len(tr.m) != 0 {
		t.Fatal("cabeçalho ilegível abriu entrada")
	}
	for i := range initMaxEntries {
		tr.observe(local, udpAddr(10000+i), unknownVersion(byte(i)))
	}
	if len(tr.m) != initMaxEntries || tr.evictNoCH.Len() != initMaxEntries {
		t.Fatalf("%d entradas, %d na fila", len(tr.m), tr.evictNoCH.Len())
	}
	tr.observe(local, udpAddr(9), rfcInitial(t))
	e, info := tr.claim(udpAddr(9), time.Second)
	if e == nil || info == nil || info.ClientHello == nil || len(info.TransportParams) == 0 {
		t.Fatalf("Initial legítimo sem análise: %+v", info)
	}
	if got := tr.srv.metrics.Get(MetricH3InitTableFull); got != 1 {
		t.Fatalf("contador %v", got)
	}
	// a mais antiga (porta 10000, versão legível) saiu como handshake_failed
	if _, ok := tr.m[udpAddr(10000).String()]; ok || len(orphans) != 1 || orphans[0].key != udpAddr(10000).String() {
		t.Fatalf("despejo: mais antiga ficou ou %d órfãs", len(orphans))
	}
	tr.observe(local, udpAddr(8), rfcInitial(t))
	if _, ok := tr.m[udpAddr(10001).String()]; ok || len(orphans) != 2 {
		t.Fatalf("segunda mais antiga ficou ou %d órfãs", len(orphans))
	}
	checkTrackerInvariants(t, tr)
}

// TestInitTrackerEvictPrefersNoClientHello: sem candidatas sem ClientHello, despeja a com ClientHello
// encerrada mais antiga, publicando handshake_failed; reclamadas e em análise nunca saem.
func TestInitTrackerEvictPrefersNoClientHello(t *testing.T) {
	tr := newTestTracker(t)
	var orphans []*initEntry
	tr.orphans = func(e *initEntry, _ *quicparse.Info) { orphans = append(orphans, e) }
	local := udpAddr(443)
	ini := rfcInitial(t)
	// 2 com ClientHello (encerradas), uma sem ClientHello, o resto em análise (lixo decifrável não para)
	tr.observe(local, udpAddr(1), ini)
	tr.observe(local, udpAddr(2), ini)
	tr.observe(local, udpAddr(3), unknownVersion(3))
	for i := len(tr.m); i < initMaxEntries; i++ {
		tr.observe(local, udpAddr(20000+i), fakeInitial(1, 10))
	}
	if tr.evictCH.Len() != 2 || tr.evictNoCH.Len() != 1 {
		t.Fatalf("filas: %d com CH, %d sem", tr.evictCH.Len(), tr.evictNoCH.Len())
	}
	tr.observe(local, udpAddr(4), ini) // despeja a 3 (sem ClientHello)
	if _, ok := tr.m[udpAddr(3).String()]; ok || len(orphans) != 1 || orphans[0].key != udpAddr(3).String() {
		t.Fatalf("não despejou a sem ClientHello: %d órfãs", len(orphans))
	}
	// reclama a 1: a próxima despejada é a 2, e depois a 4
	if e, _ := tr.claim(udpAddr(1), 0); e == nil {
		t.Fatal("claim")
	}
	tr.observe(local, udpAddr(5), ini)
	if _, ok := tr.m[udpAddr(2).String()]; ok {
		t.Fatal("não despejou a 2")
	}
	if _, ok := tr.m[udpAddr(1).String()]; !ok {
		t.Fatal("despejou a reclamada")
	}
	tr.observe(local, udpAddr(6), ini)
	tr.observe(local, udpAddr(7), ini)
	tr.observe(local, udpAddr(8), ini)
	if _, ok := tr.m[udpAddr(1).String()]; !ok {
		t.Fatal("despejou a reclamada")
	}
	checkTrackerInvariants(t, tr)

	// tabela cheia só de reclamadas e em análise: a 5-tupla nova fica sem análise e o contador sobe
	tr.mu.Lock()
	for _, e := range trackerEntries(tr) {
		e.claimed = true
		tr.unevictLocked(e)
	}
	tr.mu.Unlock()
	before := tr.srv.metrics.Get(MetricH3InitTableFull)
	tr.observe(local, udpAddr(99), ini)
	if _, ok := tr.m[udpAddr(99).String()]; ok || len(tr.m) != initMaxEntries {
		t.Fatal("entrou com a tabela cheia de reclamadas")
	}
	if tr.srv.metrics.Get(MetricH3InitTableFull) != before+1 {
		t.Fatal("contador não subiu")
	}
	checkTrackerInvariants(t, tr)
}

// TestInitTrackerShortLife: a não reclamada sem ClientHello sai ao fim de initWindow (com handshake_failed
// se tem versão legível); com ClientHello fica até initOrphanAfter; reclamada só sai fechada.
func TestInitTrackerShortLife(t *testing.T) {
	tr := newTestTracker(t)
	now := time.Unix(1000, 0)
	tr.srv.now = func() time.Time { return now }
	var orphans []string
	tr.orphans = func(e *initEntry, _ *quicparse.Info) { orphans = append(orphans, e.key) }
	local := udpAddr(443)
	tr.observe(local, udpAddr(1), unknownVersion(1))  // sem CH, versão legível
	tr.observe(local, udpAddr(2), fakeInitial(2, 10)) // em análise, sem CH
	tr.observe(local, udpAddr(3), rfcInitial(t))      // com CH
	tr.observe(local, udpAddr(4), fakeInitial(4, 10)) // reclamada
	if e, _ := tr.claim(udpAddr(4), 0); e == nil {
		t.Fatal("claim")
	}
	now = now.Add(initWindow + time.Millisecond)
	tr.sweep()
	if len(tr.m) != 2 || tr.m[udpAddr(3).String()] == nil || tr.m[udpAddr(4).String()] == nil {
		t.Fatalf("depois de initWindow: %d entradas", len(tr.m))
	}
	if len(orphans) != 2 {
		t.Fatalf("órfãs %v", orphans)
	}
	now = now.Add(initOrphanAfter)
	tr.sweep()
	if len(tr.m) != 1 || tr.m[udpAddr(4).String()] == nil || len(orphans) != 3 {
		t.Fatalf("depois de initOrphanAfter: %d entradas, órfãs %v", len(tr.m), orphans)
	}
	checkTrackerInvariants(t, tr)
}

// TestH3InitTableFullStillAnalyzed: com a tabela de Initials cheia de lixo sem ClientHello, uma conexão h3
// real ganha entrada por despejo e o http3.connection dela sai com client_hello e transport params.
func TestH3InitTableFullStillAnalyzed(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	tr := h.srv.h3.tracker
	local := pc.LocalAddr()
	// versão desconhecida: encerrada sem ClientHello (a despejada sai como handshake_failed órfão)
	for i := range initMaxEntries {
		tr.observe(local, udpAddr(10000+i), unknownVersion(byte(i)))
	}
	cl := &http.Client{Transport: h3Client(t), Timeout: 5 * time.Second}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	resp, _ := h3Get(t, cl, "https://127.0.0.1:"+itoa(port)+"/p/"+testProbe+"/")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// o evento da conexão real é o que não veio de uma 5-tupla forjada (portas 10000+)
	var first map[string]any
	for deadline := time.Now().Add(5 * time.Second); first == nil; time.Sleep(10 * time.Millisecond) {
		for _, c := range h.events.find(t, event.SubjectWebHTTP3Connection, 0) {
			if c.Env.Flow != nil && (c.Env.Flow.SrcPort < 10000 || c.Env.Flow.SrcPort >= 10000+initMaxEntries) {
				first = c.Payload
				break
			}
		}
		if first == nil && time.Now().After(deadline) {
			t.Fatal("sem http3.connection da conexão real")
		}
	}
	tps, _ := first["transport_params"].([]any)
	if first["client_hello"] == nil || len(tps) == 0 {
		t.Fatalf("Initial sem análise com a tabela cheia: %v", first)
	}
	if h.srv.metrics.Get(MetricH3InitTableFull) < 1 {
		t.Fatal("contador da tabela cheia")
	}
}

// BenchmarkInitTrackerFlood: datagramas de 5-tuplas sempre novas com a tabela cheia (o despejo é O(1)).
func BenchmarkInitTrackerFlood(b *testing.B) {
	tr := newTestTracker(b)
	local := udpAddr(443)
	d := unknownVersion(1)
	for i := range initMaxEntries {
		tr.observe(local, udpAddr(10000+i), d)
	}
	i := 0
	for b.Loop() {
		i++
		tr.observe(local, udpAddr(20000+i%40000), d)
	}
}
