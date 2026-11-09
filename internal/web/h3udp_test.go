package web

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
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
// ser analisadas, sem vazamento) e a
// limpeza devolve os bytes.
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
	for _, e := range tr.m {
		if e.asm.Datagrams() > quicparse.DefaultMaxDatagrams {
			t.Fatalf("%d datagramas", e.asm.Datagrams())
		}
	}
	var orphans int
	tr.orphans = func(*initEntry, *quicparse.Info) { orphans++ }
	now = now.Add(initOrphanAfter + time.Second)
	tr.sweep()
	if len(tr.m) != 0 || tr.bytes != 0 || orphans == 0 || orphans >= 400 {
		t.Fatalf("depois da limpeza: %d entradas, %d bytes, %d órfãs", len(tr.m), tr.bytes, orphans)
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
		for _, e := range tr.m {
			if e.asm.Datagrams() > quicparse.DefaultMaxDatagrams {
				t.Fatalf("%d datagramas", e.asm.Datagrams())
			}
			_ = snapshotInfo(e.asm)
		}
		if len(tr.m) > 1000 {
			tr.mu.Lock()
			for _, e := range tr.m {
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
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}}, nil) //nolint:gosec // teste
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

// TestUDPPortsConfig: FS_WEB_UDP_PORTS ausente vale 443; vazio desliga o h3; inválido falha.
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
	if err != nil || len(c.udpAddrs()) != 1 || c.udpAddrs()[0] != "192.0.2.1:443" {
		t.Fatal(c.udpAddrs(), err)
	}
	t.Setenv("FS_WEB_UDP_PORTS", "443,x")
	if _, err := LoadConfig(base); err == nil {
		t.Fatal("aceitou porta inválida")
	}
}
