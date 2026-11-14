package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

func dialQUIC(t *testing.T, pc *net.UDPConn) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h3"}}, //nolint:gosec // autoassinado de teste
		&quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	return qc
}

// isExcessiveLoad informa se err é o reset do servidor com H3_EXCESSIVE_LOAD.
func isExcessiveLoad(err error) bool {
	var se *quic.StreamError
	return errors.As(err, &se) && se.ErrorCode == h3ExcessiveLoad
}

// partialHeaders abre n streams, cada um com um HEADERS declarado de 1 MiB e só sent bytes do payload, e
// conta quantos o servidor recusou com H3_EXCESSIVE_LOAD (os demais ficam esperando o resto).
func partialHeaders(t *testing.T, qc *quic.Conn, n, sent int) (refused int, streams []*quic.Stream) {
	t.Helper()
	frame := append(quicparse.AppendH3FrameHeader(nil, quicparse.H3FrameHeaders, 1<<20), bytes.Repeat([]byte{0}, sent)...)
	var count atomic.Int32
	var wg sync.WaitGroup
	for range n {
		str, err := qc.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, str)
		go func() { _, _ = str.Write(frame) }()
		wg.Go(func() {
			_ = str.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadAll(str); isExcessiveLoad(err) {
				count.Add(1)
			}
		})
	}
	wg.Wait()
	return int(count.Load()), streams
}

// TestH3HeadersConnBudget (task 134): HEADERS incompletos de vários streams de uma conexão não passam de
// 2 MiB em espera; os excedentes recebem H3_EXCESSIVE_LOAD e tudo volta a zero quando a conexão fecha.
func TestH3HeadersConnBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	qc := dialQUIC(t, pc)
	var peak atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if v := h.srv.budget.inUse(); v > peak.Load() {
				peak.Store(v)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	// 8 × 400 KiB não cabem em 2 MiB: pelo menos 3 recusados (quantos exatamente depende de como os pedaços
	// dos streams se intercalam).
	refused, _ := partialHeaders(t, qc, 8, 400<<10)
	close(stop)
	if refused < 3 || peak.Load() > h3HeadersConnMax {
		t.Fatalf("refused %d of 8, peak %d", refused, peak.Load())
	}
	_ = qc.CloseWithError(0, "")
	waitFor(t, 3*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })
}

// TestH3HeadersGlobalBudget (task 134): com o orçamento global menor que o teto da conexão, é ele que recusa.
func TestH3HeadersGlobalBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.InputBudget = 600 << 10 }})
	pc := startH3(t, h)
	qc := dialQUIC(t, pc)
	refused, _ := partialHeaders(t, qc, 3, 400<<10)
	if refused < 2 || h.srv.metrics.Get(MetricInputBudgetDenied) < 1 {
		t.Fatalf("refused %d, denied %v", refused, h.srv.metrics.Get(MetricInputBudgetDenied))
	}
	_ = qc.CloseWithError(0, "")
	waitFor(t, 3*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })
}

// TestH3HeadersTimeout (task 134): HEADERS que não completa no prazo recusa o stream e devolve a reserva;
// stream com HEADERS completo e corpo lento não é afetado.
func TestH3HeadersTimeout(t *testing.T) {
	old := h3HeadersTimeout
	h3HeadersTimeout = 300 * time.Millisecond
	t.Cleanup(func() { h3HeadersTimeout = old })
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	qc := dialQUIC(t, pc)

	start := time.Now()
	refused, _ := partialHeaders(t, qc, 1, 1000)
	if refused != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("refused %d after %v", refused, time.Since(start))
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })

	// Corpo lento depois do HEADERS completo: atendido normalmente.
	str, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fields := quicparse.AppendFieldSection(nil, [][2]string{
		{":method", "POST"}, {":scheme", "https"}, {":authority", testSNI}, {":path", "/"},
	})
	if _, err := str.Write(quicparse.AppendH3Frame(nil, quicparse.H3FrameHeaders, fields)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * h3HeadersTimeout)
	if _, err := str.Write(quicparse.AppendH3Frame(nil, quicparse.H3FrameData, []byte("slow"))); err != nil {
		t.Fatal(err)
	}
	_ = str.Close()
	_ = str.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := io.ReadAll(str)
	if err != nil || len(resp) == 0 || resp[0] != byte(quicparse.H3FrameHeaders) {
		t.Fatalf("slow body: %v %q", err, resp)
	}
}
