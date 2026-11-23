package web

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// bigHeaders manda um HEADERS (sem END_STREAM) com fields, dividido em CONTINUATION de 16 KiB.
func (r *h2raw) bigHeaders(id uint32, fields [][2]string) {
	r.t.Helper()
	r.hb.Reset()
	for _, f := range fields {
		_ = r.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	block := r.hb.Bytes()
	const piece = 16 << 10
	first := block[:min(piece, len(block))]
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: first, EndHeaders: len(block) <= piece}); err != nil {
		r.t.Fatal(err)
	}
	for rest := block[len(first):]; len(rest) > 0; {
		n := min(piece, len(rest))
		if err := r.fr.WriteContinuation(id, n == len(rest), rest[:n]); err != nil {
			r.t.Fatal(err)
		}
		rest = rest[n:]
	}
}

// TestH2RetainedFields (task 135): campos guardados acima de 1 MiB por conexão saem com fields_truncated; ao
// publicar cada stream os campos saem do parser e o orçamento volta a zero com a conexão ainda aberta.
func TestH2RetainedFields(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	big := strings.Repeat("v", 4000)
	const streams = 4
	for i := range streams {
		fields := h2Get("/p/" + testProbe + "/")
		for j := range 75 { // ~305 KiB de custo por stream: o quarto passa de 1 MiB
			fields = append(fields, [2]string{"x-" + strconv.Itoa(i) + "-" + strconv.Itoa(j), big})
		}
		r.bigHeaders(uint32(2*i+1), fields)
	}
	waitFor(t, 2*time.Second, func() bool { return pathInUse(h.srv.budget) > 3*300<<10 },
		func() string { return fmt.Sprint("in use ", pathInUse(h.srv.budget)) })
	// campos do parser passivo (até h2FieldsConnMax) + cabeçalho decodificado dos streams (task 330)
	if got := pathInUse(h.srv.budget); got > h2FieldsConnMax+h2DecodedConnMax {
		t.Fatalf("retained %d above %d", got, h2FieldsConnMax+h2DecodedConnMax)
	}
	for i := range streams {
		_ = r.fr.WriteData(uint32(2*i+1), true, nil)
	}
	got := byStreamID(t, h.events.wait(t, event.SubjectWebHTTP2Stream, srcPort(c), streams))
	cut := 0
	for id, p := range got {
		fs, _ := p["fields"].([]any)
		switch {
		case p["fields_truncated"] == true:
			cut++
		case len(fs) != 79:
			t.Fatalf("stream %d: %d fields without fields_truncated", id, len(fs))
		}
	}
	if cut != 1 {
		t.Fatalf("cut streams %d", cut)
	}
	waitFor(t, 2*time.Second, func() bool { return pathInUse(h.srv.budget) == 0 },
		func() string { return fmt.Sprint("after publish ", pathInUse(h.srv.budget)) })
	_ = c.Close()
	waitFor(t, 2*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return fmt.Sprint("after close ", h.srv.budget.inUse()) })
}
