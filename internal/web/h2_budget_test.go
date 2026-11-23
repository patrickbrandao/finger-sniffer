package web

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH2MaxFrameSize (task 328): o SETTINGS do servidor anuncia MAX_FRAME_SIZE 16384 e um frame de 1 MiB é
// recusado com FRAME_SIZE_ERROR; o orçamento volta a zero no fim da conexão.
func TestH2MaxFrameSize(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	sf := r.until(func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && !s.IsAck() }).(*http2.SettingsFrame)
	if v, ok := sf.Value(http2.SettingMaxFrameSize); !ok || v != 16384 {
		t.Fatalf("MAX_FRAME_SIZE %d (%v)", v, ok)
	}
	// DATA de 1 MiB no stream 0 escrito à mão (o Framer do cliente não escreve acima de 16 KiB).
	const size = 1 << 20
	hdr := make([]byte, 9, 9+size)
	hdr[0], hdr[1], hdr[2] = 0x10, 0, 0 // 1 MiB
	binary.BigEndian.PutUint32(hdr[5:], 1)
	go func() { _, _ = c.Write(append(hdr, make([]byte, size)...)) }()
	ga := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.GoAwayFrame); return ok }).(*http2.GoAwayFrame)
	if ga.ErrCode != http2.ErrCodeFrameSize {
		t.Fatalf("goaway %v", ga.ErrCode)
	}
	_ = c.Close()
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("in use ", h.srv.budget.inUse()) })
}

// TestH2DecodedHeadersBudget (task 330): o cabeçalho decodificado de cada stream reserva de um hold de 2 MiB
// por conexão até o publish; o stream sem reserva recebe 431 na hora, sem esperar o corpo; tudo volta a zero.
func TestH2DecodedHeadersBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	big := strings.Repeat("v", 4000)
	for i := range 3 {
		fields := h2Get("/p/" + testProbe + "/")
		for j := range 175 { // ~700 KiB de cabeçalho decodificado: o terceiro passa de 2 MiB
			fields = append(fields, [2]string{"x-" + strconv.Itoa(i) + "-" + strconv.Itoa(j), big})
		}
		r.bigHeaders(uint32(2*i+1), fields)
	}
	hf := r.until(func(f http2.Frame) bool { _, ok := f.(*http2.MetaHeadersFrame); return ok }).(*http2.MetaHeadersFrame)
	if hf.StreamID != 5 || hf.PseudoValue("status") != "431" {
		t.Fatalf("stream %d status %s", hf.StreamID, hf.PseudoValue("status"))
	}
	if got := pathInUse(h.srv.budget); got < 2*700<<10 {
		t.Fatalf("decoded headers not reserved: %d", got)
	}
	_ = r.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	_ = r.fr.WriteData(3, true, nil)
	r.until(func(f http2.Frame) bool { m, ok := f.(*http2.MetaHeadersFrame); return ok && m.StreamID == 3 })
	_ = c.Close()
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("after close ", h.srv.budget.inUse()) })
}

// TestH2DecodedReserveCoversHeap (task 330, ADR 0036 item 2): para um stream de ~1 MiB de cabeçalho sem
// END_STREAM, a reserva cobre ≥ 90% do heap retido.
func TestH2DecodedReserveCoversHeap(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	r.until(func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && s.IsAck() })
	fields := h2Get("/p/" + testProbe + "/")
	big := strings.Repeat("v", 4000)
	for j := range 240 {
		fields = append(fields, [2]string{"x-" + strconv.Itoa(j), big})
	}
	r.bigHeaders(1, fields)
	r.hb = bytes.Buffer{} // o buffer do cliente não entra na conta
	waitFor(t, 2*time.Second, func() bool { return h.srv.metrics.Get(MetricH2StreamsTotal) == 1 },
		func() string { return "stream not served" })
	time.Sleep(100 * time.Millisecond)
	// Retido = o que sai do heap quando o stream termina e é publicado (os eventos do coletor do teste
	// ficam nas duas medidas).
	open := heapInUse()
	reserved := pathInUse(h.srv.budget)
	_ = r.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	waitFor(t, 2*time.Second, func() bool { return pathInUse(h.srv.budget) == 0 },
		func() string { return fmt.Sprint("in use ", pathInUse(h.srv.budget)) })
	time.Sleep(100 * time.Millisecond)
	retained := open - heapInUse()
	if float64(reserved) < 0.9*float64(retained) {
		t.Fatalf("reserved %d < 90%% of retained %d", reserved, retained)
	}
}

// TestH2WriteBlockedByFlowControl (task 329): cliente com janela 0 e respostas grandes em chunk= de 1 MiB: os
// buffers do corpo ficam em 32 KiB por stream e cada stream é resetado depois de idle (nunca antes); a vaga
// volta.
func TestH2WriteBlockedByFlowControl(t *testing.T) {
	const idle = 1500 * time.Millisecond
	h := newHarness(t, harnessOpts{cfg: func(c *Config) { c.IdleDefault = idle }})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	r.until(func(f http2.Frame) bool { s, ok := f.(*http2.SettingsFrame); return ok && s.IsAck() })
	before := heapInUse()
	const streams = 20
	start := time.Now()
	for i := range streams {
		r.rawHeaders(uint32(2*i+1), true, h2Get("/r?size=4000000&chunk=1048576")...)
	}
	waitFor(t, 2*time.Second, func() bool { return h.srv.metrics.Get(MetricH2StreamsTotal) == streams },
		func() string { return fmt.Sprint("streams ", h.srv.metrics.Get(MetricH2StreamsTotal)) })
	time.Sleep(200 * time.Millisecond)
	if d := heapInUse() - before; d > 5<<20 {
		t.Fatalf("heap retained %d by %d blocked streams", d, streams)
	}
	resets := 0
	_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
	for resets < streams {
		f, err := r.fr.ReadFrame()
		if err != nil {
			t.Fatalf("after %d resets: %v", resets, err)
		}
		if _, ok := f.(*http2.RSTStreamFrame); ok {
			if resets == 0 {
				if d := time.Since(start); d < idle-100*time.Millisecond {
					t.Fatalf("reset after %v (idle %v)", d, idle)
				}
			}
			resets++
		}
	}
	_ = c.Close()
	waitFor(t, 3*time.Second, func() bool { return len(h.srv.sem) == 0 && h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("sem ", len(h.srv.sem), " in use ", h.srv.budget.inUse()) })
}
