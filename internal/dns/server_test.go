package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	const name = "_acme-challenge.finger-west-01.badblock.net.br."

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
		r = exchange(t, proto, addr, query("finger-west-01.badblock.net.br.", mdns.TypeCAA))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 0 || len(r.Ns) != 1 {
			t.Fatalf("%s CAA: %v", proto, r)
		}
		r = exchange(t, proto, addr, query("finger-west-01.badblock.net.br.", mdns.TypeSOA))
		if r.Rcode != mdns.RcodeSuccess || !r.Authoritative || len(r.Answer) != 1 {
			t.Fatalf("%s SOA: %v", proto, r)
		}
	}
}

func TestServerEDNS(t *testing.T) {
	z, _ := newTestZone()
	_, udp, _ := startServer(t, z)

	m := query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	m.SetEdns0(4096, true)
	r := exchange(t, "udp", udp, m)
	opt := r.IsEdns0()
	if opt == nil || opt.UDPSize() != udpMaxEDNS || opt.Do() {
		t.Fatalf("OPT %v", opt)
	}

	// Versão EDNS desconhecida → BADVERS.
	m = query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	m.SetEdns0(1232, false)
	m.IsEdns0().SetVersion(1)
	r = exchange(t, "udp", udp, m)
	if r.Rcode != mdns.RcodeBadVers || len(r.Answer) != 0 {
		t.Fatalf("BADVERS: rcode %d %v", r.Rcode, r)
	}
}

// TestServerTruncation: 8 valores TXT longos (o teto por nome) não cabem em 512 bytes → TC=1 em UDP; inteiros em TCP.
func TestServerTruncation(t *testing.T) {
	z, _ := newTestZone()
	const name = "_acme-challenge.finger-west-01.badblock.net.br."
	for i := range maxACMEValuesPerName {
		if err := z.SetACME(name, strings.Repeat(string(rune('a'+i)), 200)); err != nil {
			t.Fatal(err)
		}
	}
	_, udp, tcp := startServer(t, z)
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	r, _, err := c.Exchange(query(name, mdns.TypeTXT), udp)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Answer) == maxACMEValuesPerName {
		t.Fatalf("UDP sem TC: tc=%v n=%d", r.Truncated, len(r.Answer))
	}
	r = exchange(t, "tcp", tcp, query(name, mdns.TypeTXT))
	if r.Truncated || len(r.Answer) != maxACMEValuesPerName {
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
	reply := query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
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
		q := query("finger-west-01.badblock.net.br.", mdns.TypeNS)
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

// reservePortPair ocupa a mesma porta em UDP e TCP de 127.0.0.1 sem soltá-la entre as duas reservas. A porta
// efêmera UDP pode já estar em uso em TCP por outro teste ou processo; nesse caso tenta outra em vez de falhar.
func reservePortPair(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	var lastErr error
	for range 50 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, l
		}
		lastErr = err
		_ = pc.Close()
	}
	t.Fatalf("nenhuma porta livre em UDP e TCP ao mesmo tempo: %v", lastErr)
	return nil, nil
}

// TestServerListenerFailure: porta já ocupada → degraded com motivo; quando libera, o retry sobe e volta a ok.
func TestServerListenerFailure(t *testing.T) {
	busyUDP, busyTCP := reservePortPair(t)
	port := busyUDP.LocalAddr().(*net.UDPAddr).Port
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
	r := exchange(t, "udp", busyUDP.LocalAddr().String(), query("finger-west-01.badblock.net.br.", mdns.TypeSOA))
	if !r.Authoritative {
		t.Fatal(r)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// tcpQuery manda uma consulta SOA enquadrada na conexão e informa se a resposta voltou dentro do prazo.
func tcpQuery(t *testing.T, c net.Conn, id uint16) bool {
	t.Helper()
	q := query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	q.Id = id
	pk, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(pk))), pk...)); err != nil {
		return false
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return false
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, buf); err != nil {
		return false
	}
	var r mdns.Msg
	return r.Unpack(buf) == nil && r.Id == id && r.Rcode == mdns.RcodeSuccess
}

// closedWithin informa se o servidor fechou a conexão (EOF ou reset) dentro de d, sem mandar dados.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		return false
	}
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout()
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestServerTCPPerSourceLimit: teto global 4 e por origem 2; a 3ª conexão da mesma origem é fechada, a de outra
// origem ainda é atendida, e a vaga volta quando uma conexão da origem fecha. A chave de origem é injetada porque
// 127.0.0.2 não existe no loopback do macOS.
func TestServerTCPPerSourceLimit(t *testing.T) {
	z, _ := newTestZone()
	var src atomic.Value
	src.Store(netip.MustParseAddr("192.0.2.1"))
	srv, _, tcp := startServer(t, z, func(s *Server) {
		s.TCPMaxConns, s.TCPMaxPerSrc = 4, 2
		s.tcpSrcKey = func(netip.Addr) netip.Addr { return src.Load().(netip.Addr) }
	})

	a1, a2 := dialTCP(t, tcp), dialTCP(t, tcp)
	if !tcpQuery(t, a1, 1) || !tcpQuery(t, a2, 2) {
		t.Fatal("as duas primeiras conexões da origem devem ser atendidas")
	}
	a3 := dialTCP(t, tcp)
	if !closedWithin(a3, 2*time.Second) {
		t.Fatal("3ª conexão da mesma origem deveria ser fechada")
	}
	src.Store(netip.MustParseAddr("192.0.2.2"))
	if b1 := dialTCP(t, tcp); !tcpQuery(t, b1, 3) {
		t.Fatal("conexão de outra origem deveria ser atendida")
	}
	if got := srv.metrics.Get(MetricDropped); got != 1 {
		t.Fatalf("%s = %v, quer 1", MetricDropped, got)
	}

	// Fechar uma conexão da primeira origem devolve a vaga dela.
	_ = a1.Close()
	src.Store(netip.MustParseAddr("192.0.2.1"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		if a4 := dialTCP(t, tcp); tcpQuery(t, a4, 4) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a vaga da origem não voltou depois de fechar a conexão")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServerTCPGlobalLimit: com o teto global 4 e origens distintas, a 5ª conexão simultânea é fechada.
func TestServerTCPGlobalLimit(t *testing.T) {
	z, _ := newTestZone()
	var n atomic.Uint32
	_, _, tcp := startServer(t, z, func(s *Server) {
		s.TCPMaxConns, s.TCPMaxPerSrc = 4, 2
		s.tcpSrcKey = func(netip.Addr) netip.Addr {
			return netip.AddrFrom4([4]byte{192, 0, 2, byte(n.Add(1))})
		}
	})
	for i := range 4 {
		if c := dialTCP(t, tcp); !tcpQuery(t, c, uint16(i+1)) {
			t.Fatalf("conexão %d deveria ser atendida", i+1)
		}
	}
	if c := dialTCP(t, tcp); !closedWithin(c, 2*time.Second) {
		t.Fatal("5ª conexão simultânea deveria ser fechada")
	}
}

// TestServerTCPFirstQueryTimeout: conexão muda fecha no prazo da primeira consulta; depois da primeira, vale a
// ociosidade (mais longa) entre consultas.
func TestServerTCPFirstQueryTimeout(t *testing.T) {
	z, _ := newTestZone()
	_, _, tcp := startServer(t, z, func(s *Server) {
		s.TCPFirstTimeout, s.TCPIdleTimeout = 200*time.Millisecond, 1500*time.Millisecond
	})
	start := time.Now()
	if c := dialTCP(t, tcp); !closedWithin(c, 2*time.Second) {
		t.Fatal("conexão parada deveria ser fechada")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("fechou em %v, prazo da primeira consulta 200ms", d)
	}

	c := dialTCP(t, tcp)
	if !tcpQuery(t, c, 1) {
		t.Fatal("primeira consulta")
	}
	// Depois da primeira consulta, 600 ms parado ainda está dentro da ociosidade de 1,5 s.
	time.Sleep(600 * time.Millisecond)
	if !tcpQuery(t, c, 2) {
		t.Fatal("segunda consulta dentro da ociosidade")
	}
	if !closedWithin(c, 3*time.Second) {
		t.Fatal("conexão ociosa deveria ser fechada")
	}
}

// TestServerTCPMaxQueries: com os padrões, as 100 primeiras consultas de uma conexão são respondidas; a 101ª não, e
// a conexão fecha.
func TestServerTCPMaxQueries(t *testing.T) {
	z, _ := newTestZone()
	srv, _, tcp := startServer(t, z)
	if srv.TCPMaxQueries != tcpMaxQueries || srv.TCPMaxConns != tcpMaxConns || srv.TCPMaxPerSrc != tcpMaxPerSrc ||
		srv.TCPFirstTimeout != tcpFirstTimeout || srv.TCPIdleTimeout != tcpIdleTimeout {
		t.Fatal("padrões dos limites TCP diferentes das constantes")
	}
	c := dialTCP(t, tcp)
	for i := range tcpMaxQueries {
		if !tcpQuery(t, c, uint16(i+1)) {
			t.Fatalf("consulta %d sem resposta", i+1)
		}
	}
	if tcpQuery(t, c, 101) {
		t.Fatal("a 101ª consulta não deveria ser respondida")
	}
	if !closedWithin(c, 2*time.Second) {
		t.Fatal("conexão deveria fechar depois do máximo de consultas")
	}
}
