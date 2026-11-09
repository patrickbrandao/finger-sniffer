package dns

import (
	"context"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// startServer sobe o servidor em 127.0.0.1 com portas efêmeras e devolve os endereços UDP e TCP.
func startServer(t *testing.T, z *Zone, opts ...func(*Server)) (*Server, string, string) {
	t.Helper()
	srv := NewServer(testConfig(), z, nil, nil)
	for _, o := range opts {
		o(srv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)
	t.Cleanup(func() { cancel(); srv.Close() })
	udp, tcp := srv.Addrs()
	if len(udp) != 1 || len(tcp) != 1 {
		t.Fatalf("listeners %v %v", udp, tcp)
	}
	if st, r := srv.Status(); st != event.StatusOK {
		t.Fatalf("status %s %v", st, r)
	}
	return srv, udp[0].String(), tcp[0].String()
}

func exchange(t *testing.T, proto, addr string, m *mdns.Msg) *mdns.Msg {
	t.Helper()
	c := &mdns.Client{Net: proto, Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", proto, addr, err)
	}
	return r
}

// TestServerACMEIntegration: set de dois valores pelo NATS, TXT com os dois em UDP e TCP, clear de um,
// expiração; REFUSED fora da zona; CAA → NOERROR/NODATA com SOA.
func TestServerACMEIntegration(t *testing.T) {
	nc := startNATS(t)
	z, clk := newTestZone()
	if _, err := SubscribeACME(nc, z, nil); err != nil {
		t.Fatal(err)
	}
	_, udp, tcp := startServer(t, z)
	const name = "_acme-challenge.dns-monitor.tmsoft.com.br."

	for _, v := range []string{"first-token", "second-token"} {
		if r := acmeCall(t, nc, SubjectACMESet, name, v); !r.OK {
			t.Fatalf("set: %+v", r)
		}
	}
	txts := func(proto, addr string) []string {
		r := exchange(t, proto, addr, query(name, mdns.TypeTXT))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || r.RecursionAvailable {
			t.Fatalf("%s TXT: %v", proto, r)
		}
		var out []string
		for _, rr := range r.Answer {
			txt := rr.(*mdns.TXT)
			if txt.Hdr.Ttl != 5 {
				t.Fatalf("TTL %d", txt.Hdr.Ttl)
			}
			out = append(out, strings.Join(txt.Txt, ""))
		}
		slices.Sort(out)
		return out
	}
	for _, p := range []struct{ proto, addr string }{{"udp", udp}, {"tcp", tcp}} {
		if got := txts(p.proto, p.addr); !slices.Equal(got, []string{"first-token", "second-token"}) {
			t.Fatalf("%s: %v", p.proto, got)
		}
	}
	if r := acmeCall(t, nc, SubjectACMEClear, name, "first-token"); !r.OK {
		t.Fatalf("clear: %+v", r)
	}
	for _, p := range []struct{ proto, addr string }{{"udp", udp}, {"tcp", tcp}} {
		if got := txts(p.proto, p.addr); !slices.Equal(got, []string{"second-token"}) {
			t.Fatalf("%s após clear: %v", p.proto, got)
		}
	}
	clk.advance(10 * time.Minute)
	if got := txts("udp", udp); len(got) != 0 {
		t.Fatalf("após expirar: %v", got)
	}

	for _, proto := range []string{"udp", "tcp"} {
		addr := map[string]string{"udp": udp, "tcp": tcp}[proto]
		r := exchange(t, proto, addr, query("example.com.", mdns.TypeA))
		if r.Rcode != mdns.RcodeRefused || r.RecursionAvailable || r.Authoritative {
			t.Fatalf("%s example.com: %v", proto, r)
		}
		r = exchange(t, proto, addr, query("dns-monitor.tmsoft.com.br.", mdns.TypeCAA))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 0 || len(r.Ns) != 1 {
			t.Fatalf("%s CAA: %v", proto, r)
		}
		r = exchange(t, proto, addr, query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
			t.Fatalf("%s SOA: %v", proto, r)
		}
	}
}

func TestServerEDNS(t *testing.T) {
	z, _ := newTestZone()
	_, udp, _ := startServer(t, z)

	m := query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA)
	m.SetEdns0(4096, true)
	r := exchange(t, "udp", udp, m)
	opt := r.IsEdns0()
	if opt == nil || opt.UDPSize() != udpMaxEDNS || opt.Do() {
		t.Fatalf("OPT %v", opt)
	}

	// Versão EDNS desconhecida → BADVERS.
	m = query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA)
	m.SetEdns0(1232, false)
	m.IsEdns0().SetVersion(1)
	r = exchange(t, "udp", udp, m)
	if r.Rcode != mdns.RcodeBadVers || len(r.Answer) != 0 {
		t.Fatalf("BADVERS: rcode %d %v", r.Rcode, r)
	}
}

// TestServerTruncation: 40 valores TXT longos não cabem em 512 bytes → TC=1 em UDP; inteiros em TCP.
func TestServerTruncation(t *testing.T) {
	z, _ := newTestZone()
	const name = "_acme-challenge.dns-monitor.tmsoft.com.br."
	for i := range 40 {
		if err := z.SetACME(name, strings.Repeat(string(rune('a'+i%26)), 60)+string(rune('A'+i/26))); err != nil {
			t.Fatal(err)
		}
	}
	_, udp, tcp := startServer(t, z)
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	r, _, err := c.Exchange(query(name, mdns.TypeTXT), udp)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Answer) == 40 {
		t.Fatalf("UDP sem TC: tc=%v n=%d", r.Truncated, len(r.Answer))
	}
	r = exchange(t, "tcp", tcp, query(name, mdns.TypeTXT))
	if r.Truncated || len(r.Answer) != 40 {
		t.Fatalf("TCP: tc=%v n=%d", r.Truncated, len(r.Answer))
	}
}

// TestServerMalformed: lixo com cabeçalho → FORMERR com o mesmo ID; curto ou resposta (QR=1) → descartado.
func TestServerMalformed(t *testing.T) {
	z, _ := newTestZone()
	var mu sync.Mutex
	var seen []*Query
	_, udp, tcp := startServer(t, z, func(s *Server) {
		s.Observer = func(q *Query) { mu.Lock(); seen = append(seen, q); mu.Unlock() }
	})

	conn, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Cabeçalho com QDCOUNT=1 e pergunta cortada.
	bad := []byte{0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05, 'a'}
	if _, err := conn.Write(bad); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var resp mdns.Msg
	if err := resp.Unpack(buf[:n]); err != nil || resp.Id != 0xbeef || resp.Rcode != mdns.RcodeFormatError || !resp.Response {
		t.Fatalf("FORMERR: %v %v", err, resp)
	}

	// Curto e QR=1: nada volta.
	_, _ = conn.Write([]byte{1, 2, 3})
	reply := query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA)
	reply.Response = true
	pk, _ := reply.Pack()
	_, _ = conn.Write(pk)
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("resposta inesperada")
	}

	// TCP: duas consultas na mesma conexão (pipelining sequencial) e depois lixo curto fecha a conexão.
	tc, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	for _, id := range []uint16{7, 8} {
		q := query("dns-monitor.tmsoft.com.br.", mdns.TypeNS)
		q.Id = id
		pk, _ := q.Pack()
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(pk)))
		if _, err := tc.Write(append(frame, pk...)); err != nil {
			t.Fatal(err)
		}
	}
	co := &mdns.Conn{Conn: tc}
	for _, id := range []uint16{7, 8} {
		r, err := co.ReadMsg()
		if err != nil || r.Id != id || len(r.Answer) != 1 {
			t.Fatalf("tcp %d: %v %v", id, err, r)
		}
	}
	_, _ = tc.Write([]byte{0, 3, 1, 2, 3})
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := tc.Read(buf); err == nil {
		t.Fatal("conexão devia fechar")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 5 {
		t.Fatalf("observer viu %d consultas", len(seen))
	}
	first := seen[0]
	if first.Proto != "udp" || first.Req != nil || first.Resp == nil || !slices.Equal(first.Raw, bad) ||
		first.Src.Addr().String() != "127.0.0.1" || first.Dst.Port() == 0 {
		t.Fatalf("observer: %+v", first)
	}
}

// TestServerListenerFailure: porta já ocupada → degraded com motivo; quando libera, o retry sobe e volta a ok.
func TestServerListenerFailure(t *testing.T) {
	busyUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := busyUDP.LocalAddr().(*net.UDPAddr).Port
	busyTCP, err := net.Listen("tcp", busyUDP.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Port = port
	z, _ := newTestZone()
	srv := NewServer(cfg, z, nil, nil)
	srv.RetryEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		st, reasons := srv.Status()
		if st == event.StatusDegraded && len(reasons) == 2 && strings.HasPrefix(reasons[0], "listener tcp 127.0.0.1:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %s %v", st, reasons)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = busyUDP.Close()
	_ = busyTCP.Close()
	for {
		if st, _ := srv.Status(); st == event.StatusOK {
			break
		}
		if time.Now().After(deadline.Add(2 * time.Second)) {
			t.Fatal("listener não subiu no retry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r := exchange(t, "udp", busyUDP.LocalAddr().String(), query("dns-monitor.tmsoft.com.br.", mdns.TypeSOA))
	if !r.Authoritative {
		t.Fatal(r)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
