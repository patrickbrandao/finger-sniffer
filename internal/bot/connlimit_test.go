package bot

import (
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// TestSourceOf: IPv4 e IPv4 mapeado viram o mesmo IPv4; IPv6 vira o /64 (ADR 0073 item 1.1).
func TestSourceOf(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 1}, "192.0.2.7"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 1}, "192.0.2.7"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:aaaa::1"), Port: 1}, "2001:db8:1:2::"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:bbbb::9"), Port: 1}, "2001:db8:1:2::"},
		{fakeAddr("[2001:db8:1:3::1%eth0]:443"), "2001:db8:1:3::"},
	}
	for _, c := range cases {
		got, ok := sourceOf(c.addr)
		if !ok || got != netip.MustParseAddr(c.want) {
			t.Errorf("%s → %s %v, quer %s", c.addr, got, ok, c.want)
		}
	}
	if _, ok := sourceOf(fakeAddr("pipe")); ok {
		t.Error("endereço sem IP aceito")
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// TestSourceListener: a conexão acima do teto da origem é fechada no Accept e contada; fechar uma devolve a vaga;
// outras origens não são afetadas.
func TestSourceListener(t *testing.T) {
	inner := &queueListener{conns: make(chan net.Conn, 8)}
	rejected := 0
	l := newSourceListener(inner, 2, func() { rejected++ })
	_, a2, a3, b1 := pipeFrom(inner, "192.0.2.1"), pipeFrom(inner, "192.0.2.1"), pipeFrom(inner, "192.0.2.1"), pipeFrom(inner, "198.51.100.1")
	got := []net.Conn{}
	for range 3 {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, c)
	}
	if rejected != 1 || !a3.closed {
		t.Fatalf("recusadas %d, a3 fechada %v", rejected, a3.closed)
	}
	if got[2].RemoteAddr().String() != b1.RemoteAddr().String() {
		t.Fatalf("terceira aceita %s", got[2].RemoteAddr())
	}
	_ = got[0].Close()
	_ = got[0].Close() // segundo Close não devolve outra vaga
	a4, a5 := pipeFrom(inner, "192.0.2.1"), pipeFrom(inner, "192.0.2.1")
	if _, err := l.Accept(); err != nil {
		t.Fatal(err)
	}
	inner.conns <- nil // fim
	if _, err := l.Accept(); err == nil {
		t.Fatal("esperava o fim")
	}
	if !a5.closed || a4.closed || rejected != 2 || a2.closed {
		t.Fatalf("a4 %v a5 %v recusadas %d", a4.closed, a5.closed, rejected)
	}
}

// TestConnTracker: com high ou mais abertas, as ociosas mais antigas fecham até ficarem menos de high; as ativas
// e as novas nunca; o uso no teto marca o health.
func TestConnTracker(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	closed := 0
	tr := newConnTracker(3, 4, func() time.Time { return now }, func() { closed++ })
	c := make([]*fakeConn, 5)
	for i := range c {
		c[i] = &fakeConn{}
	}
	tr.state(c[0], http.StateNew)
	tr.state(c[0], http.StateIdle)
	time.Sleep(time.Millisecond)
	tr.state(c[1], http.StateNew)
	tr.state(c[1], http.StateIdle)
	tr.state(c[1], http.StateActive) // ativa de novo: não é ociosa
	if closed != 0 {
		t.Fatalf("fechou cedo %d", closed)
	}
	tr.state(c[2], http.StateNew) // 3 abertas: fecha a ociosa (c0)
	if closed != 1 || !c[0].closed || c[1].closed {
		t.Fatalf("fechadas %d c0 %v c1 %v", closed, c[0].closed, c[1].closed)
	}
	tr.state(c[0], http.StateClosed) // o Closed tardio da fechada não desconta de novo
	tr.state(c[3], http.StateNew)    // 3 abertas, nenhuma ociosa: nada fecha
	if closed != 1 || tr.fullSince(now, time.Minute) {
		t.Fatalf("fechadas %d cheio %v", closed, tr.fullSince(now, time.Minute))
	}
	tr.state(c[4], http.StateNew) // 4 = teto
	if !tr.fullSince(now, time.Minute) || tr.fullSince(now.Add(time.Minute), time.Minute) {
		t.Fatal("marca do teto errada")
	}
}

type fakeConn struct {
	net.Conn
	closed bool
	remote net.Addr
}

func (c *fakeConn) Close() error         { c.closed = true; return nil }
func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

// queueListener entrega as conexões postas na fila; nil encerra.
type queueListener struct {
	net.Listener
	conns chan net.Conn
}

func (l *queueListener) Accept() (net.Conn, error) {
	c := <-l.conns
	if c == nil {
		return nil, net.ErrClosed
	}
	return c, nil
}

func pipeFrom(l *queueListener, ip string) *fakeConn {
	c := &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000 + len(l.conns)}}
	l.conns <- c
	return c
}
