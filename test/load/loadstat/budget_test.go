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

func TestMemWindowsStat(t *testing.T) {
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu\n" +
		"1000000000,web,1,100,50,10,7,20,5,1\n" +
		"2000000000,web,1,90,40,10,9,15,6,2\n" +
		"2000000000,host,1,2,3,0,0,0,0,0\n"
	ws, err := MemWindows(strings.NewReader(csv), "web", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("janelas = %d", len(ws))
	}
	w := ws[0]
	if !w.HasStat || w.Samples != 2 || w.SockMax != 9 || w.KStatMax != 20 || w.SlabMax != 6 || w.PercpuMax != 2 ||
		w.KernelMax != 40 {
		t.Fatalf("janela = %+v", w)
	}
	var b bytes.Buffer
	PrintMemWindows(&b, ws)
	if !strings.Contains(b.String(), "sock máx") || !strings.Contains(b.String(), "| 0–30 | 2 |") {
		t.Fatalf("tabela:\n%s", b.String())
	}
}

// TestMemWindowsThrottled: o formato de 11 colunas (nr_throttled no fim, ADR 0039) é lido como o de 10.
func TestMemWindowsThrottled(t *testing.T) {
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu,nr_throttled\n" +
		"1000000000,web,1,100,50,10,7,20,5,1,0\n" +
		"2000000000,web,1,90,40,10,9,15,6,2,3\n" +
		"2000000000,host,1,2,3,16,0,0,0,0,0\n"
	ws, err := MemWindows(strings.NewReader(csv), "web", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || !ws[0].HasStat || ws[0].Samples != 2 || ws[0].SockMax != 9 || ws[0].CurrentMax != 100 {
		t.Fatalf("janelas = %+v", ws)
	}
}

// TestMemWindows15: o formato de 15 colunas (shmem, memory_max e memory.events no fim, task 247) é lido como o de
// 10.
func TestMemWindows15(t *testing.T) {
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu,nr_throttled,shmem,memory_max,events_max,oom_kill\n" +
		"1000000000,store,1,100,50,10,7,20,5,1,0,30,6442450944,0,0\n" +
		"2000000000,store,1,120,40,10,9,15,6,2,0,60,6442450944,0,0\n"
	ws, err := MemWindows(strings.NewReader(csv), "store", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || !ws[0].HasStat || ws[0].Samples != 2 || ws[0].SockMax != 9 || ws[0].CurrentMax != 120 {
		t.Fatalf("janelas = %+v", ws)
	}
}

func TestNstatDelta(t *testing.T) {
	before := "#kernel\nTcpExtTCPRcvQDrop               57643              0.0\nUdpRcvbufErrors 361 0.0\n"
	after := "#kernel\nTcpExtTCPRcvQDrop 57700 0.0\nUdpRcvbufErrors 361 0.0\nTcpExtPruneCalled 4 0.0\n"
	var b bytes.Buffer
	NstatDelta(&b, before, after)
	out := b.String()
	for _, want := range []string{
		"TcpExtTCPRcvQDrop 57643 → 57700 (delta 57)\n",
		"UdpRcvbufErrors 361 → 361 (delta 0)\n",
		"TcpExtPruneCalled 0 → 4 (delta 4)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("falta %q em:\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") != len(NstatKeys) {
		t.Fatalf("linhas:\n%s", out)
	}
}
