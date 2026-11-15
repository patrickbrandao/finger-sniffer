package loadstat

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCloseCause(t *testing.T) {
	cases := []struct {
		err   error
		write bool
		want  string
	}{
		{nil, false, ""},
		{io.EOF, false, CauseServerFIN},
		{fmt.Errorf("ler: %w", io.ErrUnexpectedEOF), false, CauseServerFIN},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, false, CauseServerRST},
		{&net.OpError{Op: "write", Err: os.NewSyscallError("write", syscall.EPIPE)}, true, CauseServerRST},
		{&net.OpError{Op: "write", Err: timeoutErr{}}, true, CauseClientWriteTimeout},
		{&net.OpError{Op: "read", Err: timeoutErr{}}, false, CauseClientReadTimeout},
		{os.ErrDeadlineExceeded, false, CauseClientReadTimeout},
		{net.ErrClosed, false, CauseOther},
	}
	for _, c := range cases {
		if got := CloseCause(c.err, c.write); got != c.want {
			t.Errorf("CloseCause(%v, %v) = %q, quer %q", c.err, c.write, got, c.want)
		}
	}
}

// Prazos reais de socket: leitura sem resposta e EOF do servidor.
func TestCloseCauseRealSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	srv := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv <- c
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s := <-srv
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if got := CloseCause(err, false); got != CauseClientReadTimeout {
		t.Fatalf("prazo de leitura: %q (%v)", got, err)
	}
	_ = s.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 1))
	if got := CloseCause(err, false); got != CauseServerFIN {
		t.Fatalf("FIN do servidor: %q (%v)", got, err)
	}
}

func TestMemWindows(t *testing.T) {
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file\n" +
		"1000000000,web,1,100,50,10\n" +
		"1000000000,store,1,999,999,0\n" +
		"11000000000,web,1,200,80,20\n" +
		"35000000000,web,1,150,60,10\n"
	ws, err := MemWindows(strings.NewReader(csv), "web", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2 {
		t.Fatalf("janelas = %d", len(ws))
	}
	if w := ws[0]; w.Samples != 2 || w.CurrentMax != 200 || w.AnonMax != 80 || w.KernelMax != 100 || w.StartS != 0 {
		t.Fatalf("janela 0 = %+v", w)
	}
	if w := ws[1]; w.Samples != 1 || w.KernelMax != 80 || w.StartS != 30 || w.EndS != 60 {
		t.Fatalf("janela 1 = %+v", w)
	}
	var b bytes.Buffer
	PrintMemWindows(&b, ws)
	if !strings.Contains(b.String(), "| 30–60 | 1 |") {
		t.Fatalf("tabela:\n%s", b.String())
	}
}
