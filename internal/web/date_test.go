package web

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// Testes do Date automático e do controle date=0 (ADR 0021, spec 005 RF-07a) nas três versões.

var dateNow = time.Date(2026, 11, 9, 8, 30, 5, 0, time.FixedZone("BRT", -3*3600))

func TestWithDate(t *testing.T) {
	base := []h1.HeaderField{{Name: "Content-Type", Value: "text/plain"}}
	got := withDate(200, base, false, dateNow)
	if len(got) != 2 || got[0] != (h1.HeaderField{Name: "Date", Value: "Mon, 09 Nov 2026 11:30:05 GMT"}) {
		t.Fatalf("200: %v", got)
	}
	for _, st := range []int{100, 101, 103} {
		if got := withDate(st, base, false, dateNow); len(got) != 1 {
			t.Fatalf("%d com Date: %v", st, got)
		}
	}
	if got := withDate(404, base, true, dateNow); len(got) != 1 {
		t.Fatalf("date=0: %v", got)
	}
	user := append(base, h1.HeaderField{Name: "date", Value: "x"})
	if got := withDate(200, user, false, dateNow); len(got) != 2 || got[1].Value != "x" {
		t.Fatalf("h=date:x: %v", got)
	}
}

func TestParseControlsDate(t *testing.T) {
	c := ParseControls("date=0", ControlLimits{})
	if !c.Valid() || !c.NoDate || c.Record.Params["date"] != "0" {
		t.Fatalf("date=0: %+v", c)
	}
	for _, v := range []string{"1", "", "no"} {
		c := ParseControls("date="+v, ControlLimits{})
		if c.Valid() || len(c.Record.Invalid) != 1 || c.Record.Invalid[0] != "date" {
			t.Fatalf("date=%s: %+v", v, c.Record)
		}
		if !strings.Contains(c.InvalidText(), "date="+v+": must be 0") {
			t.Fatalf("explicação %q", c.InvalidText())
		}
	}
}

// TestDateHTTP1: Date logo depois da linha de status em 200, 404 e 400 de controle; h=Date:x vale no
// lugar do automático, na posição de h=; date=0 omite; 103 sem Date.
func TestDateHTTP1(t *testing.T) {
	h := ctlHarness(t)
	cases := []struct{ path, want string }{
		{"/r?size=1", head200("1") + "0"},
		{"/r?size=0&status=404", strings.Replace(head200("0"), "200 OK", "404 Not Found", 1)},
		{"/r?date=1", "HTTP/1.1 400 Bad Request\r\n" + dateLine + "Content-Type: text/plain; charset=utf-8\r\n"},
		{"/r?size=0&h=X-A:1&h=Date:x&h=X-B:2", "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" +
			"Cache-Control: no-store\r\nX-A: 1\r\nDate: x\r\nX-B: 2\r\nContent-Length: 0\r\n\r\n"},
		{"/r?size=0&h=date:Thu,%2001%20Jan%201970%2000:00:00%20GMT", "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" +
			"Cache-Control: no-store\r\ndate: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n"},
		{"/r?size=0&date=0", "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\n" +
			"Content-Length: 0\r\n\r\n"},
		{"/r?size=0&date=0&status=103", "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n" +
			"Content-Type: application/octet-stream\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			cl := ctlDo(t, h, tc.path+"&alt_svc=0")
			cl.expect(tc.want)
		})
	}
	t.Run("404 route", func(t *testing.T) {
		cl := ctlDo(t, h, "/nope")
		cl.expect("HTTP/1.1 404 Not Found\r\n" + dateLine)
	})
}

// h2Response manda um GET em h2c e devolve os campos (com :status) de cada HEADERS do stream, na ordem.
func h2Response(t *testing.T, h *harness, id uint32, path string) [][][2]string {
	t.Helper()
	r := newH2Raw(t, dial(t, h.addr80), true)
	if err := r.fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	r.headers(id, "GET", path, http2.PriorityParam{})
	var out [][][2]string
	r.until(func(f http2.Frame) bool {
		if f.Header().StreamID != id {
			return false
		}
		if mh, ok := f.(*http2.MetaHeadersFrame); ok {
			var fields [][2]string
			for _, hf := range mh.Fields {
				fields = append(fields, [2]string{hf.Name, hf.Value})
			}
			out = append(out, fields)
		}
		return f.Header().Flags.Has(http2.FlagDataEndStream) ||
			(f.Header().Type == http2.FrameHeaders && f.Header().Flags.Has(http2.FlagHeadersEndStream))
	})
	return out
}

// checkDateFirst confere o date como primeiro campo depois de :status (com o valor, se want != "").
func checkDateFirst(t *testing.T, fields [][2]string, want string) {
	t.Helper()
	if len(fields) < 2 || fields[0][0] != ":status" || fields[1][0] != "date" {
		t.Fatalf("date não é o primeiro campo: %v", fields)
	}
	if want != "" && fields[1][1] != want {
		t.Fatalf("date %q, quer %q", fields[1][1], want)
	}
	if want == "" && !dateRE.MatchString("Date: "+fields[1][1]+"\r\n") {
		t.Fatalf("date fora do IMF-fixdate: %q", fields[1][1])
	}
	n := 0
	for _, f := range fields {
		if f[0] == "date" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d campos date: %v", n, fields)
	}
}

func hasH3Field(fields [][2]string, name string) bool {
	for _, f := range fields {
		if f[0] == name {
			return true
		}
	}
	return false
}

func TestDateH2(t *testing.T) {
	h := ctlHarness(t)
	for _, path := range []string{"/r?size=1&h=A-First:1", "/r?status=404", "/r?date=x", "/nope", "/"} {
		t.Run(path, func(t *testing.T) {
			resp := h2Response(t, h, 1, path)
			if len(resp) == 0 {
				t.Fatal("sem HEADERS")
			}
			checkDateFirst(t, resp[0], "")
			// um content-type só: o x/net não fareja outro (chave "Content-Type" presente e vazia)
			n := 0
			for _, f := range resp[0] {
				if f[0] == "content-type" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d content-type: %v", n, resp[0])
			}
		})
	}
	t.Run("h=Date", func(t *testing.T) {
		resp := h2Response(t, h, 1, "/r?h=Date:x")
		checkDateFirst(t, resp[0], "x")
	})
	t.Run("date=0", func(t *testing.T) {
		resp := h2Response(t, h, 1, "/r?date=0&status=103")
		if len(resp) != 2 || resp[0][0][1] != "103" || hasH3Field(resp[0], "date") || hasH3Field(resp[1], "date") {
			t.Fatalf("date=0: %v", resp)
		}
	})
	t.Run("103 sem date", func(t *testing.T) {
		resp := h2Response(t, h, 1, "/r?status=103")
		if len(resp) != 2 || hasH3Field(resp[0], "date") {
			t.Fatalf("103: %v", resp)
		}
		checkDateFirst(t, resp[1], "")
	})
}

// h3Response manda um GET em h3 (com SETTINGS antes) e devolve os campos de cada HEADERS da resposta.
func h3Response(t *testing.T, c *rawH3, path string) [][][2]string {
	t.Helper()
	str := c.request(path)
	_ = str.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(str)
	if err != nil {
		t.Fatal(err)
	}
	var out [][][2]string
	for len(b) > 0 {
		typ, n1, ok1 := quicparse.ReadVarint(b)
		ln, n2, ok2 := quicparse.ReadVarint(b[n1:])
		if !ok1 || !ok2 || uint64(len(b)-n1-n2) < ln {
			t.Fatalf("frame truncado %x", b)
		}
		payload := b[n1+n2 : n1+n2+int(ln)] //nolint:gosec // ln <= len(b)
		b = b[n1+n2+int(ln):]               //nolint:gosec // idem
		if typ != quicparse.H3FrameHeaders {
			continue
		}
		_, fields, err := quicparse.DecodeFieldSection(payload, 64)
		if err != nil {
			t.Fatal(err)
		}
		var fs [][2]string
		for _, f := range fields {
			fs = append(fs, [2]string{f.Name, f.Value})
		}
		out = append(out, fs)
	}
	return out
}

func TestDateH3(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	c := dialRawH3(t, pc)
	c.sendSettings()
	defer func() { _ = c.qc.CloseWithError(h3NoError, "") }()
	for _, path := range []string{"/r?size=1", "/r?status=404", "/r?date=x", "/nope"} {
		resp := h3Response(t, c, path)
		if len(resp) == 0 {
			t.Fatalf("%s: sem HEADERS", path)
		}
		checkDateFirst(t, resp[0], "")
	}
	// h=Date:x fica na posição de h= (depois dos campos do espelho) e sem o automático.
	resp := h3Response(t, c, "/r?h=Date:x")
	last := resp[0][len(resp[0])-1]
	if last != [2]string{"date", "x"} || resp[0][1][0] == "date" {
		t.Fatalf("h=Date:x: %v", resp[0])
	}
	resp = h3Response(t, c, "/r?date=0&status=103")
	if len(resp) != 2 || resp[0][0][1] != "103" || hasH3Field(resp[0], "date") || hasH3Field(resp[1], "date") {
		t.Fatalf("date=0: %v", resp)
	}
	resp = h3Response(t, c, "/r?status=103")
	if len(resp) != 2 || hasH3Field(resp[0], "date") {
		t.Fatalf("103: %v", resp)
	}
	checkDateFirst(t, resp[1], "")
	if _, err := http.ParseTime(resp[1][1][1]); err != nil {
		t.Fatal(err)
	}
}
