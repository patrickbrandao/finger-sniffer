package tlsparse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeRecorder guarda tudo o que o cliente escreve, para comparar com o que o servidor capturou.
type writeRecorder struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *writeRecorder) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(b)
	w.mu.Unlock()
	return w.Conn.Write(b)
}

// TestConnWithCryptoTLS: cliente e servidor crypto/tls reais por TCP; a Conn não pode alterar o handshake
// e precisa capturar exatamente os registros do ClientHello que o cliente escreveu.
func TestConnWithCryptoTLS(t *testing.T) {
	cert := testCert(t)
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	for _, v := range versions {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close() //nolint:errcheck // teste

			type result struct {
				conn     *Conn
				state    tls.ConnectionState
				inHook   *ClientHello
				complete bool
				err      error
			}
			done := make(chan result, 1)
			go func() {
				var res result
				defer func() { done <- res }()
				raw, err := ln.Accept()
				if err != nil {
					res.err = err
					return
				}
				defer raw.Close() //nolint:errcheck // teste
				c := NewConn(raw)
				res.conn = c
				cfg := &tls.Config{
					MinVersion: tls.VersionTLS10,
					GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
						// no callback o ClientHello já está inteiro na captura
						res.complete = c.Complete()
						res.inHook, _ = c.ClientHello()
						return nil, nil
					},
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{"h2", "http/1.1"},
				}
				s := tls.Server(c, cfg)
				if err := s.Handshake(); err != nil {
					res.err = err
					return
				}
				res.state = s.ConnectionState()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(s, buf); err != nil {
					res.err = err
					return
				}
				_, res.err = s.Write(buf)
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			rec := &writeRecorder{Conn: raw}
			cl := tls.Client(rec, &tls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true, //nolint:gosec // certificado de teste
				MinVersion:         v,
				MaxVersion:         v,
				NextProtos:         []string{"h2", "http/1.1"},
			})
			if err := cl.Handshake(); err != nil {
				t.Fatal(err)
			}
			rec.mu.Lock()
			sent := append([]byte(nil), rec.buf.Bytes()...)
			rec.mu.Unlock()
			if _, err := cl.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(cl, echo); err != nil || string(echo) != "ping" {
				t.Fatalf("eco: %q %v", echo, err)
			}
			_ = cl.Close()
			res := <-done
			if res.err != nil {
				t.Fatal(res.err)
			}
			if res.state.Version != v || res.state.NegotiatedProtocol != "h2" {
				t.Fatalf("handshake: versão 0x%04x alpn %q", res.state.Version, res.state.NegotiatedProtocol)
			}
			got, err := res.conn.Records()
			if err != nil {
				t.Fatal(err)
			}
			// o primeiro voo do cliente é só o ClientHello
			if !bytes.Equal(got, sent[:len(got)]) || len(got) == 0 {
				t.Fatalf("captura (%d bytes) difere do que o cliente enviou (%d bytes)", len(got), len(sent))
			}
			if !res.complete || res.inHook == nil || res.inHook.SNI != "example.com" {
				t.Fatalf("no GetConfigForClient: complete=%v ch=%v", res.complete, res.inHook)
			}
			ch, err := res.conn.ClientHello()
			if err != nil || ch.Records != 1 || len(ch.ALPN) != 2 {
				t.Fatalf("ClientHello: %v %+v", err, ch)
			}
		})
	}
}

// chunkConn devolve os dados em pedaços fixos, como uma rede que entrega segmentos pequenos.
type chunkConn struct {
	net.Conn
	data  []byte
	chunk int
}

func (c *chunkConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(b), c.chunk, len(c.data))
	copy(b, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func readAll(t *testing.T, c *Conn) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 333)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConnChunks(t *testing.T) {
	rec := readSample(t, "chrome-2records")
	after := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03}
	stream := append(append([]byte{}, rec...), after...)
	for _, chunk := range []int{1, 7, 100, 4096} {
		c := NewConn(&chunkConn{data: append([]byte{}, stream...), chunk: chunk})
		if c.Complete() {
			t.Fatal("completa antes de ler")
		}
		if _, err := c.Records(); !errors.Is(err, ErrIncomplete) {
			t.Fatal(err)
		}
		got := readAll(t, c)
		if !bytes.Equal(got, stream) {
			t.Fatalf("chunk %d: Read alterou o fluxo", chunk)
		}
		recs, err := c.Records()
		if err != nil || !bytes.Equal(recs, rec) {
			t.Fatalf("chunk %d: captura %d bytes, err %v", chunk, len(recs), err)
		}
		ch, err := c.ClientHello()
		if err != nil || ch.Records != 2 {
			t.Fatalf("chunk %d: %v records=%d", chunk, err, ch.Records)
		}
	}
}

func TestConnNotTLS(t *testing.T) {
	stream := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	c := NewConn(&chunkConn{data: append([]byte{}, stream...), chunk: 3})
	if got := readAll(t, c); !bytes.Equal(got, stream) {
		t.Fatal("Read alterou o fluxo")
	}
	if !c.Complete() {
		t.Fatal("captura deveria ter terminado")
	}
	if _, err := c.Records(); !errors.Is(err, ErrNotHandshake) {
		t.Fatal(err)
	}
	if _, err := c.ClientHello(); !errors.Is(err, ErrNotHandshake) {
		t.Fatal(err)
	}
}

// TestConnFragmentedBig (task 323): ClientHello de 60000 bytes em registros de 1 byte (360 KiB no fio) é
// remontado inteiro, os registros crus param em MaxCapturedRecords e a captura reserva o que aloca.
func TestConnFragmentedBig(t *testing.T) {
	msg := append([]byte{1, 0, 0xea, 0x60}, make([]byte, 60000)...)
	var stream []byte
	for _, b := range msg {
		stream = append(stream, 0x16, 0x03, 0x01, 0, 1, b)
	}
	c := NewConn(&chunkConn{data: stream, chunk: 1 << 16})
	var held int
	c.Reserve = func(n int) bool { held += n; return true }
	c.Unreserve = func(n int) { held -= n }
	if got := readAll(t, c); len(got) != len(stream) {
		t.Fatal("Read alterou o fluxo")
	}
	recs, err := c.Records()
	if err != nil || len(recs) != MaxCapturedRecords || cap(recs) != MaxCapturedRecords || !c.RecordsTruncated() {
		t.Fatalf("err=%v len=%d cap=%d", err, len(recs), cap(recs))
	}
	ch, _ := c.ClientHello()
	if !bytes.Equal(ch.Raw, msg) || ch.Records != len(msg) {
		t.Fatalf("mensagem %d bytes, %d registros", len(ch.Raw), ch.Records)
	}
	if want := len(msg) + MaxCapturedRecords; held != want || c.Reserved() != want {
		t.Fatalf("reservado %d, quer %d", held, want)
	}
	c.Release()
	c.Release()
	if recs, _ := c.Records(); recs != nil || held != 0 {
		t.Fatalf("depois de Release: %d bytes, reservado %d", len(recs), held)
	}
}

// TestConnNoBudget (task 323): reserva recusada encerra a leitura com ErrNoBudget, sem nada retido.
func TestConnNoBudget(t *testing.T) {
	c := NewConn(&chunkConn{data: readSample(t, "go"), chunk: 1 << 16})
	c.Reserve = func(int) bool { return false }
	if _, err := c.Read(make([]byte, 1<<16)); !errors.Is(err, ErrNoBudget) {
		t.Fatalf("err=%v", err)
	}
	if recs, err := c.Records(); recs != nil || !errors.Is(err, ErrNoBudget) || c.Reserved() != 0 {
		t.Fatalf("%d %v", len(recs), err)
	}
}

// TestConnReserveCoversHeap (task 323, ADR 0036 item 2): com o ClientHello de 60000 bytes em registros de 1
// byte parado antes do fim, a reserva cobre ao menos 90% do heap retido pela captura, e Release o devolve.
func TestConnReserveCoversHeap(t *testing.T) {
	msg := append([]byte{1, 0, 0xea, 0x60}, make([]byte, 60000)...)
	var stream []byte
	for _, b := range msg[:len(msg)-1] {
		stream = append(stream, 0x16, 0x03, 0x01, 0, 1, b)
	}
	heap := func() int64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc) //nolint:gosec // cabe em int64
	}
	const n = 32
	conns := make([]*Conn, n)
	var held int
	before := heap()
	for i := range conns {
		c := NewConn(nil)
		c.Reserve = func(k int) bool { held += k; return true }
		c.Unreserve = func(k int) { held -= k }
		for off := 0; off < len(stream); off += 1500 {
			c.capture(stream[off:min(off+1500, len(stream))])
		}
		conns[i] = c
	}
	retained := heap() - before
	ratio := float64(held) / float64(retained)
	t.Logf("reservado %d, retido %d (%.1f%%), %d por conexão", held, retained, 100*ratio, retained/n)
	if ratio < 0.9 || retained/n > 100<<10 {
		t.Fatalf("reservado %d, retido %d", held, retained)
	}
	for _, c := range conns {
		c.Release()
	}
	if held != 0 {
		t.Fatalf("sobra %d", held)
	}
}
