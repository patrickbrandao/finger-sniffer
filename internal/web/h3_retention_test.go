package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// TestH3DecodedFieldsBudget (task 330): streams com HEADERS completo de ~700 KiB e sem FIN: o decodificado
// reserva do hold de 2 MiB da conexão, os excedentes recebem H3_EXCESSIVE_LOAD e tudo volta a zero ao fechar.
func TestH3DecodedFieldsBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	qc := dialQUIC(t, pc)
	fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", testSNI}, {":path", "/"}}
	big := strings.Repeat("v", 4000)
	for j := range 175 {
		fields = append(fields, [2]string{"x-" + strconv.Itoa(j), big})
	}
	frame := quicparse.AppendH3Frame(nil, quicparse.H3FrameHeaders, quicparse.AppendFieldSection(nil, fields))
	var refused atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		str, err := qc.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = str.Write(frame) }() // o stream recusado pode ser resetado no meio da escrita
		wg.Go(func() {
			_ = str.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadAll(str); isExcessiveLoad(err) {
				refused.Add(1)
			}
		})
	}
	wg.Wait()
	if refused.Load() < 2 {
		t.Fatalf("refused %d of 4", refused.Load())
	}
	// com -race o decodificado do segundo stream aceito pode chegar depois do prazo de leitura: espera a reserva.
	waitFor(t, 5*time.Second, func() bool { return h.srv.budget.inUse() >= 2*690<<10 },
		func() string { return fmt.Sprint("decoded fields reserved ", h.srv.budget.inUse()) })
	if got := h.srv.budget.inUse(); got > h3HeadersConnMax {
		t.Fatalf("decoded fields reserved %d", got)
	}
	_ = qc.CloseWithError(0, "")
	waitFor(t, 3*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })
}

// TestH3WriteBlocked (task 329): cliente que não lê respostas grandes em chunk= de 1 MiB: os buffers do corpo
// ficam em 32 KiB por stream e cada stream é resetado depois de idle (nunca antes), com o registro publicado.
func TestH3WriteBlocked(t *testing.T) {
	const idle = 1500 * time.Millisecond
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault = idle }})
	pc := startH3(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&quic.Config{
			MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 300 * time.Millisecond,
			InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10,
			InitialConnectionReceiveWindow: 64 << 10, MaxConnectionReceiveWindow: 64 << 10,
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	before := heapInUse()
	const streams = 20
	fields := quicparse.AppendFieldSection(nil, [][2]string{
		{":method", "GET"}, {":scheme", "https"}, {":authority", testSNI}, {":path", "/r?size=4000000&chunk=1048576"},
	})
	start := time.Now()
	for range streams {
		str, err := qc.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = str.Write(quicparse.AppendH3Frame(nil, quicparse.H3FrameHeaders, fields))
		_ = str.Close()
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.metrics.Get(MetricH3RequestsTotal) == streams },
		func() string { return fmt.Sprint("requests ", h.srv.metrics.Get(MetricH3RequestsTotal)) })
	time.Sleep(300 * time.Millisecond)
	if d := heapInUse() - before; d > 5<<20 {
		t.Fatalf("heap retained %d by %d blocked streams", d, streams)
	}
	if n := len(h.events.find(t, event.SubjectWebHTTP3Request, 0)); n != 0 {
		t.Fatalf("%d requests published before idle", n)
	}
	waitFor(t, 5*time.Second, func() bool { return len(h.events.find(t, event.SubjectWebHTTP3Request, 0)) == streams },
		func() string { return fmt.Sprint("published ", len(h.events.find(t, event.SubjectWebHTTP3Request, 0))) })
	if d := time.Since(start); d < idle {
		t.Fatalf("streams reset after %v (idle %v)", d, idle)
	}
}

// TestH3SecondControlStream (task 331): o primeiro stream de controle reserva o frame guardado; o segundo
// fecha a conexão com H3_STREAM_CREATION_ERROR e o orçamento volta a zero.
func TestH3SecondControlStream(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	qc := dialQUIC(t, pc)
	first, err := qc.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// SETTINGS declarado de 60 KiB com só 30 KiB enviados: fica em espera, reservado.
	b := append([]byte{byte(quicparse.StreamTypeControl)}, quicparse.AppendH3FrameHeader(nil, quicparse.H3FrameSettings, 60<<10)...)
	if _, err := first.Write(append(b, make([]byte, 30<<10)...)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() >= 30<<10 },
		func() string { return fmt.Sprint("control frame not reserved: ", h.srv.budget.inUse()) })
	second, err := qc.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = second.Write([]byte{byte(quicparse.StreamTypeControl)})
	select {
	case <-qc.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("connection not closed")
	}
	var ae *quic.ApplicationError
	if err := context.Cause(qc.Context()); !errors.As(err, &ae) || ae.ErrorCode != h3StreamCreationError {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })
}
