package web

import (
	"testing"

	"golang.org/x/net/http2"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestH2RefusedStreams (task 146): streams que a biblioteca recusa antes do handler (connection: → 400,
// nome em maiúscula → RST_STREAM, sem :path → RST_STREAM) saem no fim da conexão como http2.stream com
// status 0, campos com a caixa preservada e repr HPACK; o stream atendido sai uma vez só.
func TestH2RefusedStreams(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	path := "/p/" + testProbe + "/"
	r.rawHeaders(1, true, h2Get(path, [2]string{"connection", "keep-alive"})...)
	r.rawHeaders(3, true, h2Get(path, [2]string{"X-Upper", "1"})...)
	r.rawHeaders(5, true, [2]string{":method", "GET"}, [2]string{":scheme", "http"}, [2]string{":authority", testSNI})
	r.rawHeaders(7, true, h2Get(path)...)
	r.until(func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamID == 7 && d.StreamEnded()
	})
	port := srcPort(c)
	h.events.wait(t, event.SubjectWebHTTP2Stream, port, 1)
	_ = c.Close()
	got := byStreamID(t, h.events.wait(t, event.SubjectWebHTTP2Stream, port, 4))
	if n := len(h.events.find(t, event.SubjectWebHTTP2Stream, port)); n != 4 {
		t.Fatalf("%d stream events, want 4 (no duplicates)", n)
	}
	if num(t, got[7]["status"]) != 200 {
		t.Fatalf("stream 7 %v", got[7]["status"])
	}
	for _, id := range []int{1, 3, 5} {
		p, ok := got[id]
		if !ok || num(t, p["status"]) != 0 || p["request_started_at"] == nil || p["ja4h"] == nil {
			t.Fatalf("refused stream %d: %v", id, p)
		}
		if po, _ := p["pseudo_order"].([]any); len(po) == 0 {
			t.Fatalf("stream %d pseudo_order %v", id, p["pseudo_order"])
		}
	}
	if streamField(got[1], "connection") != "keep-alive" || streamField(got[3], "X-Upper") != "1" {
		t.Fatalf("fields: %v / %v", got[1]["fields"], got[3]["fields"])
	}
	fs := got[3]["fields"].([]any)
	if f := fs[len(fs)-1].(map[string]any); f["repr"] == nil {
		t.Fatalf("repr missing: %v", f)
	}
}
