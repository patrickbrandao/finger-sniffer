package web

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// trackerEntries lista todas as entradas da tabela (chamar com tr.mu ou sem concorrência).
func trackerEntries(tr *initTracker) []*initEntry {
	var out []*initEntry
	for _, list := range tr.m {
		out = append(out, list...)
	}
	return out
}

// trackerEntry devolve a entrada mais nova da 5-tupla (nil sem nenhuma).
func trackerEntry(tr *initTracker, remote net.Addr) *initEntry {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	list := tr.m[remote.String()]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

// longPacket monta um cabeçalho longo v1 do tipo dado (0 Initial, 2 Handshake, 3 Retry) com DCID, SCID e n
// bytes de lixo (não decifra).
func longPacket(typ byte, dcid, scid []byte, n int) []byte {
	b := []byte{0xc0 | typ<<4, 0, 0, 0, 1, byte(len(dcid))}
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	if typ == 0 {
		b = append(b, 0) // token vazio
	}
	b = quicparse.AppendVarint(b, uint64(n))
	return append(b, make([]byte, n)...)
}

// sealedInitial monta um Initial v1 com DCID e SCID dados, cifrado com as chaves derivadas de keyDCID, com n
// bytes de PADDING: decifra quando keyDCID é o próprio DCID (primeiro Initial de uma conexão); com o DCID
// original e outro DCID no cabeçalho, é o Initial com o CID de NEW_CONNECTION_ID (task 430).
func sealedInitial(t testing.TB, keyDCID, dcid, scid []byte, n int) []byte {
	t.Helper()
	k, err := quicparse.NewInitialKeys(quicparse.Version1, keyDCID, false)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{0xc1, 0, 0, 0, 1, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0) // token vazio
	length := 2 + n + 16
	hdr = append(hdr, byte(length>>8)|0x40, byte(length))
	pnOff := len(hdr)
	hdr = append(hdr, 0, 0)
	return k.Seal(hdr, pnOff, 0, make([]byte, n))
}

// TestInitTrackerSplitsByDCID: com a conexão anterior viva (reclamada, sem release), o Initial de uma conexão
// nova na mesma 5-tupla (DCID e SCID novos) abre entrada própria, com DCID e conn_id próprios, e o claim da
// conexão nova pega essa entrada; a retransmissão do Initial da anterior continua na dela (task 425).
func TestInitTrackerSplitsByDCID(t *testing.T) {
	var reqs atomic.Int64
	srv := NewServer(testConfig(t.TempDir()), Deps{})
	srv.deps.ConnID = func(_ context.Context, f event.Flow, _ time.Time) (string, error) {
		reqs.Add(1)
		return "c-" + f.QUICDCIDHex, nil
	}
	tr := newInitTracker(context.Background(), srv)
	local, remote := udpAddr(443), udpAddr(1000)
	old := rfcInitial(t) // decifra: pede conn_id no primeiro datagrama
	tr.observe(local, remote, old)
	e1, _ := tr.claim(remote, 0)
	if e1 == nil || e1.connID == nil {
		t.Fatal("primeira conexão sem entrada")
	}

	// conexão nova na mesma porta de origem, a anterior ainda viva
	d9 := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	n := sealedInitial(t, d9, d9, []byte{7, 7, 7, 7}, 1200)
	tr.observe(local, remote, n)
	e2, _ := tr.claim(remote, 0)
	if e2 == nil || e2 == e1 {
		t.Fatal("a conexão nova herdou a entrada da anterior")
	}
	if e2.flow.QUICDCIDHex != "0909090909090909" || e1.flow.QUICDCIDHex == e2.flow.QUICDCIDHex {
		t.Fatalf("DCIDs %s e %s", e1.flow.QUICDCIDHex, e2.flow.QUICDCIDHex)
	}
	if e1.connID.get() != "c-"+e1.flow.QUICDCIDHex || e2.connID == nil || e2.connID.get() != "c-0909090909090909" ||
		reqs.Load() != 2 {
		t.Fatalf("conn_id: %d pedidos", reqs.Load())
	}

	// retransmissão do Initial da anterior: na entrada dela, sem entrada nova nem pedido novo
	b1, b2 := e1.bytes, e2.bytes
	tr.observe(local, remote, old)
	tr.mu.Lock()
	count := len(tr.m[remote.String()])
	tr.mu.Unlock()
	if count != 2 || e2.bytes != b2 || reqs.Load() != 2 {
		t.Fatalf("retransmissão: %d entradas, bytes %d→%d (anterior %d)", count, b2, e2.bytes, b1)
	}
	checkTrackerInvariants(t, tr)

	// release de uma não mexe na outra
	tr.release(e1)
	tr.observe(local, remote, n)
	if got := trackerEntry(tr, remote); got != e2 || tr.n != 1 {
		t.Fatalf("depois do release: %p (nova %p), %d entradas", got, e2, tr.n)
	}
	checkTrackerInvariants(t, tr)
}

// TestInitTrackerSameConnCIDs: retransmissões do Initial (mesmo DCID), o Initial depois da resposta do
// servidor (DCID = SCID do servidor, mesmo com SCID vazio do cliente) e o Initial depois do Retry (DCID = SCID
// do Retry) continuam na mesma entrada; um Initial com CIDs desconhecidos abre outra (task 425).
func TestInitTrackerSameConnCIDs(t *testing.T) {
	tr := newTestTracker(t)
	local, remote := udpAddr(443), udpAddr(2000)
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	count := func() int {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.m[remote.String()])
	}
	// cliente com SCID vazio: só o SCID do servidor liga os Initials seguintes à entrada
	tr.observe(local, remote, longPacket(0, odcid, nil, 1200))
	tr.observe(local, remote, longPacket(0, odcid, nil, 1200)) // retransmissão
	e := trackerEntry(tr, remote)
	if e == nil || count() != 1 {
		t.Fatalf("retransmissão abriu entrada: %d", count())
	}
	srvCID := []byte{0xa, 0xb, 0xc, 0xd}
	tr.sent(remote, []byte{0x40, 1, 2, 3})                      // cabeçalho curto: ignorado
	tr.sent(remote, longPacket(0, nil, srvCID, 100))            // Initial do servidor
	tr.observe(local, remote, longPacket(0, srvCID, nil, 1200)) // ACK do cliente no Initial
	tr.observe(local, remote, longPacket(2, srvCID, nil, 100))  // Handshake
	if count() != 1 || trackerEntry(tr, remote) != e {
		t.Fatalf("Initial com o SCID do servidor abriu entrada: %d", count())
	}

	// Retry: o cliente refaz o Initial com o DCID do Retry e o mesmo SCID dele
	remote2 := udpAddr(2001)
	cscid := []byte{5, 5, 5, 5}
	tr.observe(local, remote2, longPacket(0, odcid, cscid, 1200))
	e2 := trackerEntry(tr, remote2)
	retry := []byte{0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe, 0xe}
	tr.sent(remote2, longPacket(3, cscid, retry, 40))
	if len(e2.cids) != 1 || e2.cids[0] != string(retry) {
		t.Fatalf("SCID do Retry não guardado: %x", e2.cids)
	}
	tr.observe(local, remote2, longPacket(0, retry, cscid, 1200))
	if trackerEntry(tr, remote2) != e2 {
		t.Fatal("Initial depois do Retry abriu entrada")
	}

	// CIDs desconhecidos, Initial que não decifra com as chaves do próprio DCID: fica na mais nova (task 430)
	d6 := []byte{6, 6, 6, 6, 6, 6, 6, 6}
	tr.observe(local, remote, longPacket(0, d6, nil, 1200))
	if count() != 1 || trackerEntry(tr, remote) != e {
		t.Fatalf("Initial que não decifra abriu entrada: %d", count())
	}
	// CIDs desconhecidos e decifra com as chaves do próprio DCID: conexão nova na mesma 5-tupla
	tr.observe(local, remote, sealedInitial(t, d6, d6, nil, 1200))
	if count() != 2 || trackerEntry(tr, remote) == e {
		t.Fatalf("Initial novo sem entrada própria: %d", count())
	}
	// cabeçalho curto vai à mais nova, sem entrada nova
	tr.observe(local, remote, []byte{0x40, 1, 2, 3})
	if count() != 2 {
		t.Fatal("cabeçalho curto abriu entrada")
	}
	checkTrackerInvariants(t, tr)
}

// TestInitTrackerClaimPrefersAccepted: com duas entradas não reclamadas na 5-tupla (a anterior com handshake
// recusado, ainda não limpa), o claim pega a do DCID original aceito pelo quic-go; sem accepted, a mais antiga.
func TestInitTrackerClaimPrefersAccepted(t *testing.T) {
	tr := newTestTracker(t)
	local, remote := udpAddr(443), udpAddr(3000)
	d1, d2 := []byte{1, 1, 1, 1, 1, 1, 1, 1}, []byte{2, 2, 2, 2, 2, 2, 2, 2}
	tr.observe(local, remote, sealedInitial(t, d1, d1, []byte{1}, 1200))
	tr.observe(local, remote, sealedInitial(t, d2, d2, []byte{2}, 1200))
	tr.accepted(remote, nil)                   // sem DCID original: nada
	tr.accepted(remote, []byte{3, 3, 3, 3, 3}) // DCID que não está na tabela: nada
	tr.accepted(remote, d2)
	e, _ := tr.claim(remote, 0)
	if e == nil || e.dcid != string(d2) {
		t.Fatalf("claim pegou %+v", e)
	}
	e, _ = tr.claim(remote, 0)
	if e == nil || e.dcid != string(d1) {
		t.Fatalf("segundo claim pegou %+v", e)
	}
	if e, _ := tr.claim(remote, 0); e != nil {
		t.Fatal("claim de entrada já reclamada")
	}
}

// TestInitTrackerNewConnectionIDInitial: o cliente (quic-go) passa, ainda no Initial, a um CID que o espelho
// emitiu em NEW_CONNECTION_ID, mas cifra com as chaves do DCID original. Esse Initial fica na entrada da
// conexão (sem entrada nova nem pedido de conn_id) e a varredura não publica órfã; uma conexão nova de verdade
// na mesma 5-tupla continua com entrada própria (task 430).
func TestInitTrackerNewConnectionIDInitial(t *testing.T) {
	var reqs atomic.Int64
	srv := NewServer(testConfig(t.TempDir()), Deps{})
	srv.deps.ConnID = func(_ context.Context, f event.Flow, _ time.Time) (string, error) {
		reqs.Add(1)
		return "c-" + f.QUICDCIDHex, nil
	}
	now := time.Now() // o prazo do pedido de conn_id sai deste relógio
	srv.now = func() time.Time { return now }
	tr := newInitTracker(context.Background(), srv)
	var orphans []*initEntry
	tr.orphans = func(e *initEntry, _ *quicparse.Info) { orphans = append(orphans, e) }
	local, remote := udpAddr(443), udpAddr(4000)
	count := func() int {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.m[remote.String()])
	}
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ncid := []byte{0xc, 0xc, 0xc, 0xc}
	tr.observe(local, remote, sealedInitial(t, odcid, odcid, nil, 1200))
	e, _ := tr.claim(remote, 0)
	if e == nil || e.connID == nil || e.connID.get() != "c-0102030405060708" || reqs.Load() != 1 {
		t.Fatalf("primeira conexão: %+v, %d pedidos", e, reqs.Load())
	}
	tr.observe(local, remote, sealedInitial(t, odcid, ncid, nil, 1200))
	if count() != 1 || trackerEntry(tr, remote) != e || reqs.Load() != 1 {
		t.Fatalf("Initial com o CID de NEW_CONNECTION_ID: %d entradas, %d pedidos", count(), reqs.Load())
	}
	now = now.Add(initOrphanAfter + time.Second)
	tr.sweep()
	if len(orphans) != 0 {
		t.Fatalf("%d órfãs (DCID %s)", len(orphans), orphans[0].flow.QUICDCIDHex)
	}

	// conexão nova de verdade na mesma 5-tupla: entrada e conn_id próprios
	d2 := []byte{2, 2, 2, 2, 2, 2, 2, 2}
	tr.observe(local, remote, sealedInitial(t, d2, d2, nil, 1200))
	if e2 := trackerEntry(tr, remote); count() != 2 || e2 == e || e2.connID == nil ||
		e2.connID.get() != "c-0202020202020202" || reqs.Load() != 2 {
		t.Fatalf("conexão nova: %d entradas, %d pedidos", count(), reqs.Load())
	}
	checkTrackerInvariants(t, tr)
}

// TestInitTrackerUndecryptedNoOrphan: entrada de versão conhecida que nada decifrou não sai como
// handshake_failed na varredura; a de versão desconhecida continua saindo (spec 011, task 430).
func TestInitTrackerUndecryptedNoOrphan(t *testing.T) {
	tr := newTestTracker(t)
	now := time.Unix(1000, 0)
	tr.srv.now = func() time.Time { return now }
	var orphans []string
	tr.orphans = func(e *initEntry, _ *quicparse.Info) { orphans = append(orphans, e.key) }
	local := udpAddr(443)
	tr.observe(local, udpAddr(1), longPacket(0, []byte{1, 1, 1, 1, 1, 1, 1, 1}, nil, 1200))
	tr.observe(local, udpAddr(2), unknownVersion(2))
	now = now.Add(initOrphanAfter + time.Second)
	tr.sweep()
	if len(tr.m) != 0 || len(orphans) != 1 || orphans[0] != udpAddr(2).String() {
		t.Fatalf("%d entradas, órfãs %v", len(tr.m), orphans)
	}
}

// TestH3SamePortNewConn: duas conexões QUIC do mesmo socket do cliente (mesma 5-tupla), a primeira viva, com
// probes diferentes no SNI: cada uma sai com DCID, ClientHello, probe e conn_id próprios (task 425).
func TestH3SamePortNewConn(t *testing.T) {
	h := newHarness(t, harnessOpts{deps: func(d *Deps) {
		d.ConnID = func(_ context.Context, f event.Flow, _ time.Time) (string, error) {
			return "c-" + f.QUICDCIDHex, nil
		}
	}})
	pc := startH3(t, h)
	srvAddr := pc.LocalAddr().(*net.UDPAddr)
	cpc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	qtr := &quic.Transport{Conn: cpc}
	defer func() { _ = qtr.Close() }()
	client := func(sni string) (*http.Client, *http3.Transport) {
		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{ServerName: sni, InsecureSkipVerify: true},
			QUICConfig:      &quic.Config{MaxIdleTimeout: 5 * time.Second},
			Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return qtr.DialEarly(ctx, srvAddr, tc, qc)
			},
		}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}, tr
	}
	const probe2 = "zyxwvuts"
	base := "https://127.0.0.1:" + itoa(srvAddr.Port)
	cl1, tr1 := client(testSNI)
	defer func() { _ = tr1.Close() }()
	cl2, tr2 := client(probe2 + ".finger-west-01.badblock.net.br")
	defer func() { _ = tr2.Close() }()

	_, body1 := h3Get(t, cl1, base+"/p/"+testProbe+"/")
	_, body2 := h3Get(t, cl2, base+"/p/"+probe2+"/") // a primeira continua aberta (tr1 não fechou)
	connOf := func(body string) string {
		for l := range strings.SplitSeq(body, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "conn_id: "); ok {
				return v
			}
		}
		return ""
	}
	c1, c2 := connOf(body1), connOf(body2)
	if !strings.HasPrefix(c1, "c-") || !strings.HasPrefix(c2, "c-") || c1 == c2 {
		t.Fatalf("conn_id %q e %q\n%s\n%s", c1, c2, body1, body2)
	}

	port := cpc.LocalAddr().(*net.UDPAddr).Port
	// o accept marcou cada entrada pelo DCID original vindo do Tracer do quic-go
	tr := h.srv.h3.tracker
	tr.mu.Lock()
	list := slices.Clone(tr.m[cpc.LocalAddr().String()])
	tr.mu.Unlock()
	if len(list) != 2 || !list[0].accepted || !list[1].accepted || list[0].dcid == list[1].dcid {
		t.Fatalf("entradas da 5-tupla: %d", len(list))
	}
	byDCID := map[string]decoded{}
	deadline := time.Now().Add(5 * time.Second)
	for len(byDCID) < 2 && time.Now().Before(deadline) {
		for _, ev := range h.events.find(t, event.SubjectWebHTTP3Connection, port) {
			if _, ok := byDCID[ev.Env.Flow.QUICDCIDHex]; !ok {
				byDCID[ev.Env.Flow.QUICDCIDHex] = ev // o primeiro evento de cada conexão
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(byDCID) != 2 {
		t.Fatalf("%d DCIDs nos http3.connection: %v", len(byDCID), byDCID)
	}
	want := map[string]string{testProbe: testSNI, probe2: probe2 + ".finger-west-01.badblock.net.br"}
	seen := map[string]bool{}
	for dcid, ev := range byDCID {
		if _, err := hex.DecodeString(dcid); err != nil || ev.Env.ProbeID == nil {
			t.Fatalf("evento %s sem probe: %+v", dcid, ev.Env)
		}
		p := *ev.Env.ProbeID
		ch, _ := ev.Payload["client_hello"].(map[string]any)
		if ch == nil || ch["sni"] != want[p] {
			t.Fatalf("conexão %s: probe %s, ClientHello %v", dcid, p, ch)
		}
		if "c-"+dcid != c1 && "c-"+dcid != c2 {
			t.Fatalf("DCID %s fora dos conn_id %s %s", dcid, c1, c2)
		}
		seen[p] = true
	}
	if !seen[testProbe] || !seen[probe2] {
		t.Fatalf("probes %v", seen)
	}
}
