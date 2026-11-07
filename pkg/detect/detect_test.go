package detect

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		want     Protocol
		needMore bool
	}{
		{"empty", "", Unknown, true},
		{"tls handshake", "\x16\x03\x01\x02\x00", TLS, false},
		{"tls two bytes", "\x16\x03", TLS, false},
		{"tls first byte only", "\x16", Unknown, true},
		{"0x16 not tls", "\x16\x02", Unknown, false},
		{"tls alert is not handshake", "\x15\x03\x03", Unknown, false},
		{"h2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", H2CPriorKnowledge, false},
		{"h2 preface partial", "PRI * HT", Unknown, true},
		{"probe line", "PROBE abcdefgh\r\n", ProbeLine, false},
		{"probe partial", "PROB", Unknown, true},
		{"get", "GET / HTTP/1.1\r\n", HTTP1, false},
		{"get exact space", "GET ", HTTP1, false},
		{"get without space", "GET", Unknown, true},
		{"post", "POST /x HTTP/1.0\r\n", HTTP1, false},
		{"connect", "CONNECT host:443 HTTP/1.1\r\n", HTTP1, false},
		{"options asterisk", "OPTIONS * HTTP/1.1\r\n", HTTP1, false},
		{"webdav propfind", "PROPFIND /dav HTTP/1.1\r\n", HTTP1, false},
		{"version-control", "VERSION-CONTROL / HTTP/1.1\r\n", HTTP1, false},
		{"lowercase method is not http", "get / HTTP/1.1\r\n", Unknown, false},
		{"method with tab", "GET\t/", Unknown, false},
		{"smtp ehlo is not http", "EHLO client\r\n", Unknown, false},
		{"ssh banner", "SSH-2.0-OpenSSH_9.6\r\n", Unknown, false},
		{"pri prefix ambiguous with put", "P", Unknown, true},
		{"pri but not h2", "PRI / HTTP/1.1", Unknown, false},
		{"binary", "\x00\x01\x02", Unknown, false},
		{"echo text", "hello\r\n", Unknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, more := Classify([]byte(tt.in))
			if got != tt.want || more != tt.needMore {
				t.Fatalf("Classify(%q) = (%v, %v), want (%v, %v)", tt.in, got, more, tt.want, tt.needMore)
			}
		})
	}
}

func TestProtocolString(t *testing.T) {
	want := map[Protocol]string{
		Unknown: "unknown", TLS: "tls", H2CPriorKnowledge: "h2c", HTTP1: "http1",
		ProbeLine: "probe", Silent: "silent", Closed: "closed", Protocol(99): "unknown",
	}
	for p, s := range want {
		if p.String() != s {
			t.Errorf("Protocol(%d).String() = %q, want %q", int(p), p.String(), s)
		}
	}
}

// pipe cria um par de conexões em memória com suporte a prazo.
func pipe(t *testing.T) (server, client net.Conn) {
	t.Helper()
	server, client = net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return server, client
}

// writeChunks escreve os pedaços com uma pequena pausa entre eles (segmentos separados).
func writeChunks(c net.Conn, chunks ...string) {
	go func() {
		for _, ch := range chunks {
			if _, err := c.Write([]byte(ch)); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

func TestDetectReplaysBytes(t *testing.T) {
	server, client := pipe(t)
	msg := "GET /p/abcdefgh/ HTTP/1.1\r\nHost: x\r\n\r\n"
	writeChunks(client, "GE", "T /p/abc", msg[len("GET /p/abc"):])

	conn, res, err := Detect(server, DefaultMaxBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != HTTP1 {
		t.Fatalf("protocol = %v, want http1", res.Protocol)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("replayed %q, want %q", got, msg)
	}
}

func TestDetectTLSSplitRecordHeader(t *testing.T) {
	// O primeiro byte chega sozinho: a detecção precisa esperar o segundo.
	server, client := pipe(t)
	writeChunks(client, "\x16", "\x03\x01\x00\x05hello")
	_, res, err := Detect(server, DefaultMaxBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != TLS {
		t.Fatalf("protocol = %v, want tls", res.Protocol)
	}
	if !bytes.HasPrefix(res.Peeked, []byte{0x16, 0x03}) {
		t.Fatalf("peeked = %x", res.Peeked)
	}
}

func TestDetectSilent(t *testing.T) {
	// Cliente que espera o servidor falar (banner): nada chega dentro do prazo.
	server, _ := pipe(t)
	conn, res, err := Detect(server, DefaultMaxBytes, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != Silent || len(res.Peeked) != 0 {
		t.Fatalf("got %v %q, want silent and no bytes", res.Protocol, res.Peeked)
	}
	// O prazo foi removido: uma leitura posterior não expira na hora.
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("read returned early: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
}

func TestDetectAmbiguousThenTimeout(t *testing.T) {
	// "GE" e depois silêncio: decide com o que tem (unknown) e devolve os bytes.
	server, client := pipe(t)
	writeChunks(client, "GE")
	conn, res, err := Detect(server, DefaultMaxBytes, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != Unknown || string(res.Peeked) != "GE" {
		t.Fatalf("got %v %q", res.Protocol, res.Peeked)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "GE" {
		t.Fatalf("replay %q %v", b, err)
	}
}

// tcpPair cria um par TCP real em loopback (o net.Pipe recusa prazo depois que o outro lado fecha).
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return server, client
}

func TestDetectClosed(t *testing.T) {
	server, client := tcpPair(t)
	_ = client.Close()
	_, res, err := Detect(server, DefaultMaxBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != Closed {
		t.Fatalf("protocol = %v, want closed", res.Protocol)
	}
}

func TestDetectClosedAfterPartial(t *testing.T) {
	server, client := tcpPair(t)
	go func() {
		_, _ = client.Write([]byte("PR"))
		_ = client.Close()
	}()
	_, res, err := Detect(server, DefaultMaxBytes, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != Unknown || string(res.Peeked) != "PR" {
		t.Fatalf("got %v %q", res.Protocol, res.Peeked)
	}
}

func TestDetectMaxBytesBound(t *testing.T) {
	// Nunca lê além de maxBytes; o restante fica no socket e é lido depois, em ordem.
	server, client := pipe(t)
	msg := "hello world, this is raw tcp data beyond the limit"
	writeChunks(client, msg)
	conn, res, err := Detect(server, 4, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != Unknown || len(res.Peeked) > 4 {
		t.Fatalf("got %v, peeked %d bytes", res.Protocol, len(res.Peeked))
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != msg {
		t.Fatalf("replay %q %v", got, err)
	}
}

func TestDetectDefaults(t *testing.T) {
	server, client := pipe(t)
	writeChunks(client, "\x16\x03\x03")
	_, res, err := Detect(server, 0, 0)
	if err != nil || res.Protocol != TLS {
		t.Fatalf("got %v %v", res.Protocol, err)
	}
}

// errConn falha de formas controladas.
type errConn struct {
	net.Conn
	deadlineErr error
	readErr     error
}

func (c *errConn) SetReadDeadline(time.Time) error { return c.deadlineErr }
func (c *errConn) Read([]byte) (int, error)        { return 0, c.readErr }

func TestDetectErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, _, err := Detect(&errConn{deadlineErr: boom}, 0, 0); !errors.Is(err, boom) {
		t.Fatalf("deadline error not returned: %v", err)
	}
	if _, _, err := Detect(&errConn{readErr: boom}, 0, 0); !errors.Is(err, boom) {
		t.Fatalf("read error not returned: %v", err)
	}
	if _, res, err := Detect(&errConn{readErr: timeoutErr{}}, 0, 0); err != nil || res.Protocol != Silent {
		t.Fatalf("net.Error timeout: %v %v", res.Protocol, err)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// FuzzClassify garante que nunca há pânico e que uma decisão definitiva não muda com mais bytes.
func FuzzClassify(f *testing.F) {
	for _, s := range []string{"\x16\x03\x01", "PRI * HTTP/2.0\r\n", "PROBE x", "GET / HTTP/1.1", "EHLO", "", "\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var decided bool
		var first Protocol
		for i := 1; i <= len(b); i++ {
			p, more := Classify(b[:i])
			if decided {
				if more || p != first {
					t.Fatalf("decision changed at %d: %v -> %v (more=%v) for %q", i, first, p, more, b)
				}
				continue
			}
			if !more {
				decided, first = true, p
			}
		}
	})
}

// chunkConn entrega os dados em pedaços de tamanhos escolhidos pelo fuzz.
type chunkConn struct {
	net.Conn
	data  []byte
	sizes []byte
}

func (c *chunkConn) SetReadDeadline(time.Time) error { return nil }
func (c *chunkConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := 1
	if len(c.sizes) > 0 {
		n = int(c.sizes[0])%8 + 1
		c.sizes = c.sizes[1:]
	}
	n = min(n, len(p), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

// FuzzDetect garante que, qualquer que seja a segmentação, os bytes devolvidos são exatamente os enviados.
func FuzzDetect(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"), []byte{1, 2, 3})
	f.Add([]byte("\x16\x03\x01\x00"), []byte{0})
	f.Fuzz(func(t *testing.T, data, sizes []byte) {
		orig := append([]byte(nil), data...)
		conn, res, err := Detect(&chunkConn{data: data, sizes: sizes}, DefaultMaxBytes, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Peeked) > DefaultMaxBytes {
			t.Fatalf("peeked %d bytes", len(res.Peeked))
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, orig) {
			t.Fatalf("replay mismatch: %q vs %q", got, orig)
		}
		if want, _ := Classify(orig[:len(res.Peeked)]); len(orig) > 0 && want != res.Protocol {
			t.Fatalf("protocol %v, Classify(peeked) %v", res.Protocol, want)
		}
	})
}
