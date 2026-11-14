package web

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// rawHeaders manda um HEADERS com os campos dados, na ordem.
func (r *h2raw) rawHeaders(id uint32, endStream bool, fields ...[2]string) {
	r.t.Helper()
	r.hb.Reset()
	for _, f := range fields {
		_ = r.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: r.hb.Bytes(), EndStream: endStream, EndHeaders: true,
	}); err != nil {
		r.t.Fatal(err)
	}
}

// streamField devolve o valor do campo name no evento http2.stream.
func streamField(p map[string]any, name string) string {
	fs, _ := p["fields"].([]any)
	for _, f := range fs {
		if m, ok := f.(map[string]any); ok && m["name"] == name {
			s, _ := m["value"].(string)
			return s
		}
	}
	return ""
}

// byStreamID agrupa os eventos http2.stream pelo stream_id.
func byStreamID(t *testing.T, evs []decoded) map[int]map[string]any {
	t.Helper()
	out := map[int]map[string]any{}
	for _, e := range evs {
		out[num(t, e.Payload["stream_id"])] = e.Payload
	}
	return out
}

func h2Get(path string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", testSNI}, {":path", path}}, extra...)
}

// TestH2AssocRefusedStream (task 145): stream recusado pela biblioteca (connection:) seguido de um válido
// com os mesmos pseudo-cabeçalhos → o evento sai com o stream_id, os campos e o status do válido.
func TestH2AssocRefusedStream(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	path := "/p/" + testProbe + "/"
	r.rawHeaders(1, true, h2Get(path, [2]string{"connection", "keep-alive"})...)
	r.rawHeaders(3, true, h2Get(path, [2]string{"x-ok", "1"})...)
	r.until(func(f http2.Frame) bool {
		d, ok := f.(*http2.DataFrame)
		return ok && d.StreamID == 3 && d.StreamEnded()
	})
	h.events.wait(t, event.SubjectWebHTTP2Stream, srcPort(c), 1)
	time.Sleep(100 * time.Millisecond)
	evs := h.events.find(t, event.SubjectWebHTTP2Stream, srcPort(c))
	got := byStreamID(t, evs)
	st3, ok := got[3]
	if !ok || num(t, st3["status"]) != 200 || streamField(st3, "x-ok") != "1" || st3["request_started_at"] == nil {
		t.Fatalf("stream 3: %v", got)
	}
	if st1, ok := got[1]; ok && num(t, st1["status"]) == 200 {
		t.Fatalf("refused stream 1 published with 200: %v", st1)
	}
}

// TestH2AssocConcurrentFields (task 145): duas requisições ao mesmo caminho com campos regulares diferentes
// saem cada uma com o seu stream_id e os seus campos; inline=1 devolve os cabeçalhos do próprio stream.
func TestH2AssocConcurrentFields(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	path := "/p/" + testProbe + "/?inline=1"
	r.rawHeaders(1, true, h2Get(path, [2]string{"x-test", "a"})...)
	r.rawHeaders(3, true, h2Get(path, [2]string{"x-test", "b"})...)
	bodies := map[uint32][]byte{}
	ended := 0
	r.until(func(f http2.Frame) bool {
		if d, ok := f.(*http2.DataFrame); ok {
			bodies[d.StreamID] = append(bodies[d.StreamID], d.Data()...)
			if d.StreamEnded() {
				ended++
			}
		}
		return ended == 2
	})
	for id, want := range map[uint32]string{1: `"x-test","value":"a"`, 3: `"x-test","value":"b"`} {
		if !strings.Contains(string(bodies[id]), want) {
			t.Fatalf("inline body of stream %d: %s", id, bodies[id])
		}
	}
	got := byStreamID(t, h.events.wait(t, event.SubjectWebHTTP2Stream, srcPort(c), 2))
	if streamField(got[1], "x-test") != "a" || streamField(got[3], "x-test") != "b" {
		t.Fatalf("streams %v", got)
	}
}

// TestH2AssocConnect (task 145): CONNECT simples (sem :protocol) casa com o seu stream: stream_id real e 405.
func TestH2AssocConnect(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr80)
	r := newH2Raw(t, c, true)
	_ = r.fr.WriteSettings()
	r.rawHeaders(1, false, [2]string{":method", "CONNECT"}, [2]string{":authority", "example.com:443"})
	hf := r.until(func(f http2.Frame) bool { m, ok := f.(*http2.MetaHeadersFrame); return ok && m.StreamID == 1 }).(*http2.MetaHeadersFrame)
	if hf.PseudoValue("status") != "405" {
		t.Fatalf("status %s", hf.PseudoValue("status"))
	}
	_ = r.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	st := h.events.wait(t, event.SubjectWebHTTP2Stream, srcPort(c), 1)[0].Payload
	if num(t, st["stream_id"]) != 1 || num(t, st["status"]) != 405 {
		t.Fatalf("connect stream %v %v", st["stream_id"], st["status"])
	}
}
