package web

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

func newTestTracker(t testing.TB) *initTracker {
	t.Helper()
	srv := NewServer(testConfig(t.TempDir()), Deps{})
	return newInitTracker(context.Background(), srv)
}

func udpAddr(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: port} }

// fakeInitial monta um cabeçalho longo de Initial v1 com o DCID dado e n bytes de lixo (não decifra).
func fakeInitial(dcid byte, n int) []byte {
	b := []byte{0xc0, 0, 0, 0, 1, 8, dcid, 1, 2, 3, 4, 5, 6, 7, 0, 0}
	b = quicparse.AppendVarint(b, uint64(n))
	return append(b, make([]byte, n)...)
}

// TestInitTracker: entrada por 5-tupla, conn_id e DCID no fluxo, claim/release abrindo uma entrada nova,
// datagrama de cabeçalho curto ignorado e o teto de entradas.
func TestInitTracker(t *testing.T) {
	tr := newTestTracker(t)
	local := udpAddr(443)
	tr.observe(local, udpAddr(1000), []byte{0x40, 1, 2, 3}) // cabeçalho curto sem entrada: ignorado
	if len(tr.m) != 0 {
		t.Fatal("curto abriu entrada")
	}
	tr.observe(local, udpAddr(1000), fakeInitial(9, 1200))
	e, info := tr.claim(udpAddr(1000), 10*time.Millisecond)
	if e == nil || info == nil || e.flow.L4 != "udp" || e.flow.SrcPort != 1000 || e.flow.DstPort != 443 ||
		!strings.HasPrefix(e.flow.QUICDCIDHex, "09") || e.connID == nil {
		t.Fatalf("entrada %+v", e)
	}
	if info.Version != "00000001" || info.ClientHello != nil {
		t.Fatalf("info %+v", info)
	}
	tr.release(e)
	tr.observe(local, udpAddr(1000), fakeInitial(10, 1200))
	e2, _ := tr.claim(udpAddr(1000), 0)
	if e2 == nil || e2 == e || !strings.HasPrefix(e2.flow.QUICDCIDHex, "0a") {
		t.Fatal("release não abriu entrada nova")
	}
	if tr.bytes != e2.bytes {
		t.Fatalf("bytes %d, entrada %d", tr.bytes, e2.bytes)
	}
	if e, _ := tr.claim(udpAddr(5), 0); e != nil {
		t.Fatal("claim sem entrada")
	}
	tr.release(nil)

	// teto de entradas
	tr = newTestTracker(t)
	for i := range initMaxEntries + 10 {
		tr.observe(local, udpAddr(10000+i), fakeInitial(1, 10))
	}
	if len(tr.m) != initMaxEntries {
		t.Fatalf("%d entradas", len(tr.m))
	}
}

// TestInitTrackerMemory: datagramas grandes param no teto de bytes global (só as primeiras 5-tuplas chegam a
// ser analisadas, sem vazamento) e a limpeza devolve os bytes; o lixo que nada decifrou não sai como
// handshake_failed (task 430).
func TestInitTrackerMemory(t *testing.T) {
	tr := newTestTracker(t)
	now := time.Unix(1000, 0)
	tr.srv.now = func() time.Time { return now }
	for i := range 400 {
		for range quicparse.DefaultMaxDatagrams + 2 {
			tr.observe(udpAddr(443), udpAddr(2000+i), fakeInitial(byte(i), 60000))
		}
	}
	if tr.bytes > initMaxBytes {
		t.Fatalf("%d bytes guardados > %d", tr.bytes, initMaxBytes)
	}
	for _, e := range trackerEntries(tr) {
		if e.asm.Datagrams() > quicparse.DefaultMaxDatagrams {
			t.Fatalf("%d datagramas", e.asm.Datagrams())
		}
	}
	var orphans int
	tr.orphans = func(*initEntry, *quicparse.Info) { orphans++ }
	now = now.Add(initOrphanAfter + time.Second)
	tr.sweep()
	if len(tr.m) != 0 || tr.bytes != 0 || orphans != 0 {
		t.Fatalf("depois da limpeza: %d entradas, %d bytes, %d órfãs", len(tr.m), tr.bytes, orphans)
	}
}

// smallInitial remonta o Initial da RFC 9001 sem o PADDING: decifra e traz o ClientHello inteiro, mas tem
// menos de 1200 bytes (o quic-go o descarta; o espelho o registra com padded_to_1200 false).
func smallInitial(t testing.TB) []byte {
	t.Helper()
	full := rfcInitial(t)
	h, err := quicparse.ParseLongHeader(full)
	if err != nil {
		t.Fatal(err)
	}
	k, err := quicparse.NewInitialKeys(h.Version, h.DCID, false)
	if err != nil {
		t.Fatal(err)
	}
	o, err := k.Open(full[:h.Size], h, -1)
	if err != nil {
		t.Fatal(err)
	}
	payload := o.Payload
	for len(payload) > 0 && payload[len(payload)-1] == 0 {
		payload = payload[:len(payload)-1]
	}
	hdr := []byte{0xc1, byte(h.Version >> 24), byte(h.Version >> 16), byte(h.Version >> 8), byte(h.Version)}
	hdr = append(hdr, byte(len(h.DCID)))
	hdr = append(hdr, h.DCID...)
	hdr = append(hdr, byte(len(h.SCID)))
	hdr = append(hdr, h.SCID...)
	hdr = append(hdr, 0) // sem token
	length := 2 + len(payload) + 16
	hdr = append(hdr, byte(length>>8)|0x40, byte(length))
	pnOff := len(hdr)
	hdr = append(hdr, 0, 2)
	return k.Seal(hdr, pnOff, 2, payload)
}

// TestInitTrackerConnIDOnlyOnDecryptedInitial: datagramas de cabeçalho longo que não decifram (1 byte 0x80,
// cabeçalho truncado, versão desconhecida, Initial com lixo) de 5-tuplas distintas não pedem conn_id ao
// store; um Initial válido pede no primeiro datagrama; um Initial válido abaixo de 1200 bytes também, e sai
// como órfão com padded_to_1200 false; a 5-tupla reclamada sem Initial decifrado pede no claim (task 350).
func TestInitTrackerConnIDOnlyOnDecryptedInitial(t *testing.T) {
	var calls atomic.Int64
	srv := NewServer(testConfig(t.TempDir()), Deps{
		ConnID: func(context.Context, event.Flow, time.Time) (string, error) {
			calls.Add(1)
			return "c1", nil
		},
	})
	// relógio real: o prazo do conn_id conta do instante do pedido
	now := time.Now()
	srv.now = func() time.Time { return now }
	local := udpAddr(443)

	tr := newInitTracker(context.Background(), srv)
	junk := [][]byte{{0x80}, {0xc0, 0, 0, 0}, unknownVersion(1), fakeInitial(1, 40), {0xc0, 0, 0, 0, 0, 0, 0}}
	for i := range 10000 {
		for j, d := range junk {
			tr.observe(local, &net.UDPAddr{IP: net.IPv4(198, 51, byte(j), byte(i>>8)), Port: 1024 + i}, d)
		}
	}
	tr.mu.Lock()
	for _, e := range trackerEntries(tr) {
		if e.connID != nil {
			t.Fatalf("entrada %s com pedido de conn_id", e.key)
		}
	}
	tr.mu.Unlock()
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d pedidos de conn_id para datagramas que não decifram", n)
	}
	checkTrackerInvariants(t, tr)

	now = time.Now()
	tr = newInitTracker(context.Background(), srv)
	var orphans []*quicparse.Info
	tr.orphans = func(_ *initEntry, info *quicparse.Info) { orphans = append(orphans, info) }
	tr.observe(local, udpAddr(1), rfcInitial(t))
	e := trackerEntry(tr, udpAddr(1))
	if e == nil || e.connID == nil {
		t.Fatal("Initial válido sem pedido de conn_id no primeiro datagrama")
	}
	if got := e.connID.get(); got != "c1" || calls.Load() != 1 {
		t.Fatalf("conn_id %q, %d pedidos", got, calls.Load())
	}
	tr.observe(local, udpAddr(1), rfcInitial(t)) // retransmissão: nenhum pedido novo
	small := smallInitial(t)
	if len(small) >= 1200 {
		t.Fatalf("Initial pequeno com %d bytes", len(small))
	}
	tr.observe(local, udpAddr(2), small)
	e2 := trackerEntry(tr, udpAddr(2))
	if e2 == nil || e2.connID == nil {
		t.Fatal("Initial pequeno sem pedido de conn_id")
	}
	e2.connID.get()
	if calls.Load() != 2 {
		t.Fatalf("%d pedidos", calls.Load())
	}
	// reclamada sem Initial decifrado: o pedido sai no claim
	tr.observe(local, udpAddr(3), fakeInitial(3, 40))
	if trackerEntry(tr, udpAddr(3)).connID != nil {
		t.Fatal("Initial com lixo pediu conn_id")
	}
	e3, _ := tr.claim(udpAddr(3), 0)
	if e3 == nil || e3.connID == nil || e3.connID.get() != "c1" || calls.Load() != 3 {
		t.Fatalf("claim sem pedido de conn_id: %d pedidos", calls.Load())
	}
	// o pequeno não reclamado vira handshake_failed com padded_to_1200 false
	now = now.Add(initOrphanAfter + time.Second)
	tr.sweep()
	var smallInfo *quicparse.Info
	for _, in := range orphans {
		if in.InitialDatagramSize == len(small) {
			smallInfo = in
		}
	}
	if smallInfo == nil || smallInfo.PaddedTo1200 || smallInfo.ClientHello == nil {
		t.Fatalf("órfão do Initial pequeno: %+v", smallInfo)
	}
}

// FuzzInitTracker: datagramas arbitrários de algumas 5-tuplas não derrubam o tracker nem passam dos tetos.
func FuzzInitTracker(f *testing.F) {
	f.Add(fakeInitial(1, 100), uint8(3), uint16(50))
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0, 0, 0, 0x41, 0}, uint8(1), uint16(5))
	tr := newTestTracker(f)
	f.Fuzz(func(t *testing.T, b []byte, peers uint8, cut uint16) {
		c := min(int(cut), len(b))
		for i := range int(peers%8) + 1 {
			tr.observe(udpAddr(443), udpAddr(3000+i), b[:c])
			tr.observe(udpAddr(443), udpAddr(3000+i), b[c:])
		}
		if tr.bytes > initMaxBytes || len(tr.m) > initMaxEntries || tr.bytes < 0 {
			t.Fatalf("tetos: %d bytes, %d entradas", tr.bytes, len(tr.m))
		}
		for _, e := range trackerEntries(tr) {
			if e.asm.Datagrams() > quicparse.DefaultMaxDatagrams {
				t.Fatalf("%d datagramas", e.asm.Datagrams())
			}
			_ = snapshotInfo(e.asm)
		}
		if len(tr.m) > 1000 {
			tr.mu.Lock()
			for _, e := range trackerEntries(tr) {
				e.closed = true
			}
			tr.sweepLocked(time.Now())
			tr.mu.Unlock()
		}
	})
}

// TestH3HandshakeFailed: um cliente QUIC sem ALPN h3 é recusado no handshake e o web publica o
// http3.connection com o Initial analisado e close.how = handshake_failed.
func TestH3HandshakeFailed(t *testing.T) {
	old := initOrphanAfter
	initOrphanAfter = 300 * time.Millisecond
	t.Cleanup(func() { initOrphanAfter = old })
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	go func() {
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			h.srv.h3.tracker.sweep()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}}, nil)
	if err == nil {
		t.Fatal("handshake sem h3 passou")
	}
	evs := h.events.wait(t, event.SubjectWebHTTP3Connection, 0, 1)
	p := evs[0].Payload
	cls, _ := p["close"].(map[string]any)
	if cls == nil || cls["how"] != quicparse.CloseHandshakeFailed || p["client_hello"] == nil ||
		evs[0].Env.ProbeID == nil || *evs[0].Env.ProbeID != testProbe {
		t.Fatalf("evento %v", p)
	}
	checkContract(t, contractBlocks(t), evs[0])
}

// TestUDPPortsConfig: FS_WEB_UDP_PORTS ausente vale 8443 (ADR 0038); vazio desliga o h3; inválido falha.
func TestUDPPortsConfig(t *testing.T) {
	t.Setenv("FS_LISTEN_IPV4", "192.0.2.1")
	t.Setenv("FS_LISTEN_IPV6", "")
	base, err := service.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FS_WEB_UDP_PORTS", "")
	c, err := LoadConfig(base)
	if err != nil || len(c.UDPPorts) != 0 || len(c.udpAddrs()) != 0 {
		t.Fatal(c.UDPPorts, err)
	}
	if err := os.Unsetenv("FS_WEB_UDP_PORTS"); err != nil {
		t.Fatal(err)
	}
	c, err = LoadConfig(base)
	if err != nil || len(c.udpAddrs()) != 1 || c.udpAddrs()[0] != "192.0.2.1:8443" {
		t.Fatal(c.udpAddrs(), err)
	}
	t.Setenv("FS_WEB_UDP_PORTS", "8443,x")
	if _, err := LoadConfig(base); err == nil {
		t.Fatal("aceitou porta inválida")
	}
}
