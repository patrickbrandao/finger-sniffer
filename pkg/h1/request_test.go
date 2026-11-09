package h1

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func newReader(s string) *Reader {
	return NewReader(bufio.NewReader(strings.NewReader(s)))
}

// Caso 1 da matriz (spec 017): caixa e ordem incomuns, duplicatas, valor com espaços, LF puro.
func TestReadHeadMatrixCase1(t *testing.T) {
	raw := "GET /p/abc123/r?x=1 HTTP/1.1\r\n" +
		"hOsT: abc123.dns-monitor.tmsoft.com.br\r\n" +
		"X-Custom-B:   value with   spaces  \r\n" +
		"accept: */*\n" +
		"X-Dup: one\r\n" +
		"x-dup:two\r\n" +
		"User-Agent : curl/8.7.1\r\n" +
		"\r\n"
	r := newReader(raw)
	req, err := r.ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if string(req.RawHead) != raw {
		t.Fatalf("raw head differs:\n%q", req.RawHead)
	}
	want := []Field{
		{"hOsT", ": ", "abc123.dns-monitor.tmsoft.com.br", TermCRLF},
		{"X-Custom-B", ":   ", "value with   spaces  ", TermCRLF},
		{"accept", ": ", "*/*", TermLF},
		{"X-Dup", ": ", "one", TermCRLF},
		{"x-dup", ":", "two", TermCRLF},
		{"User-Agent", " : ", "curl/8.7.1", TermCRLF},
	}
	if !reflect.DeepEqual(req.Fields, want) {
		t.Fatalf("fields:\n got %q\nwant %q", req.Fields, want)
	}
	rl := RequestLine{Method: "GET", Target: "/p/abc123/r?x=1", Form: FormOrigin, Version: "HTTP/1.1", Terminator: TermCRLF}
	if req.RequestLine != rl {
		t.Fatalf("request line %+v", req.RequestLine)
	}
	if req.FieldCount != 6 || req.HeadSize != len(raw) || req.ObsFold || req.HeadTooLarge {
		t.Fatalf("counts %d %d %v %v", req.FieldCount, req.HeadSize, req.ObsFold, req.HeadTooLarge)
	}
	if !reflect.DeepEqual(req.Duplicates, []string{"x-dup"}) {
		t.Fatalf("duplicates %v", req.Duplicates)
	}
	if v, ok := req.Get("HOST"); !ok || v != "abc123.dns-monitor.tmsoft.com.br" {
		t.Fatalf("Get host %q", v)
	}
	if got := req.Values("x-DUP"); !reflect.DeepEqual(got, []string{"one", "two"}) {
		t.Fatalf("values %v", got)
	}
	if _, ok := req.Get("missing"); ok {
		t.Fatal("missing field found")
	}
	if req.Upgrade != nil || req.ExpectsContinue() {
		t.Fatal("unexpected upgrade/expect")
	}
	if err := r.ReadBody(req, BodyOptions{}); err != nil || req.Body.Framing != FramingNone || req.Body.SHA256 != nil {
		t.Fatalf("body %v %+v", err, req.Body)
	}
}

func TestReadHeadAllLF(t *testing.T) {
	raw := "POST /x HTTP/1.0\nHost: a\nContent-Length: 3\n\nabc"
	r := newReader(raw)
	req, err := r.ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if req.RequestLine.Terminator != TermLF || req.Fields[1].Term() != TermLF || req.RequestLine.Version != "HTTP/1.0" {
		t.Fatalf("%+v %q", req.RequestLine, req.Fields)
	}
	if req.Body.Framing != FramingContentLength || req.Body.Size != 3 || string(req.Body.Raw) != "abc" {
		t.Fatalf("%+v", req.Body)
	}
	// sha256("abc")
	if *req.Body.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(*req.Body.SHA256)
	}
	if f := req.Fields[0]; f.Name() != "Host" || f.Sep() != ": " || f.Value() != "a" {
		t.Fatal(f)
	}
	if r.Consumed() != int64(len(raw)) || r.Buffered() != 0 {
		t.Fatalf("consumed %d", r.Consumed())
	}
	if _, err := r.ReadHead(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadHeadObsFold(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nX-Long: a\r\n  b\r\n\tc\nHost: h\r\n\r\n"
	req, err := newReader(raw).ReadHead()
	if err != nil {
		t.Fatal(err)
	}
	if !req.ObsFold || req.FieldCount != 2 {
		t.Fatalf("obs-fold %v count %d", req.ObsFold, req.FieldCount)
	}
	want := Field{"X-Long", ": ", "a\r\n  b\r\n\tc", TermLF}
	if req.Fields[0] != want {
		t.Fatalf("%q", req.Fields[0])
	}
	if _, err := newReader("GET / HTTP/1.1\r\n folded\r\n\r\n").ReadHead(); !errors.Is(err, ErrObsFoldFirst) {
		t.Fatal(err)
	}
}

// RF-10: cabeçalho acima de 1 MiB → ErrHeadTooLarge (431) com o que foi lido registrado.
func TestReadHeadTooLarge(t *testing.T) {
	big := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", DefaultMaxHeadBytes) + "\r\n\r\n"
	req, err := newReader(big).ReadHead()
	if !errors.Is(err, ErrHeadTooLarge) {
		t.Fatalf("want ErrHeadTooLarge, got %v", err)
	}
	if !req.HeadTooLarge || req.HeadSize != DefaultMaxHeadBytes || len(req.RawHead) != DefaultMaxHeadBytes {
		t.Fatalf("too large %v size %d", req.HeadTooLarge, req.HeadSize)
	}
	// Muitos campos pequenos também contam, e o teto é configurável.
	many := "GET / HTTP/1.1\r\n" + strings.Repeat("A: b\r\n", 100) + "\r\n"
	r := newReader(many)
	r.MaxHeadBytes = 100
	req, err = r.ReadHead()
	if !errors.Is(err, ErrHeadTooLarge) || req.HeadSize != 100 || req.FieldCount == 0 {
		t.Fatalf("%v %d %d", err, req.HeadSize, req.FieldCount)
	}
	// Exatamente no teto passa.
	exact := "GET / HTTP/1.1\r\n\r\n"
	r = newReader(exact)
	r.MaxHeadBytes = len(exact)
	if _, err := r.ReadHead(); err != nil {
		t.Fatal(err)
	}
	// Linha de requisição sozinha estourando o teto.
	r = newReader("GET /" + strings.Repeat("x", 200) + " HTTP/1.1\r\n\r\n")
	r.MaxHeadBytes = 50
	if req, err := r.ReadHead(); !errors.Is(err, ErrHeadTooLarge) || !req.HeadTooLarge {
		t.Fatal(err)
	}
}

func TestReadHeadForms(t *testing.T) {
	cases := []struct{ line, form, target string }{
		{"GET / HTTP/1.1", FormOrigin, "/"},
		{"GET http://example.com/a?b HTTP/1.1", FormAbsolute, "http://example.com/a?b"},
		{"GET HTTPS://example.com HTTP/1.1", FormAbsolute, "HTTPS://example.com"},
		{"CONNECT example.com:443 HTTP/1.1", FormAuthority, "example.com:443"},
		{"FOO example.com:443 HTTP/1.1", FormAuthority, "example.com:443"},
		{"OPTIONS * HTTP/1.1", FormAsterisk, "*"},
		{"GET /a b HTTP/1.1", FormOrigin, "/a b"},
		{"GET 1x://y HTTP/1.1", FormOrigin, "1x://y"},
		{"GET a_b://y HTTP/1.1", FormOrigin, "a_b://y"},
		{"GET foo HTTP/1.1", FormOrigin, "foo"},
		{"CONNECT /x HTTP/1.1", FormOrigin, "/x"},
	}
	for _, c := range cases {
		req, err := newReader(c.line + "\r\n\r\n").ReadHead()
		if err != nil {
			t.Fatalf("%s: %v", c.line, err)
		}
		if req.RequestLine.Form != c.form || req.RequestLine.Target != c.target {
			t.Errorf("%s: form %s target %q", c.line, req.RequestLine.Form, req.RequestLine.Target)
		}
	}
}

func TestReadHeadErrors(t *testing.T) {
	cases := []struct {
		in  string
		err error
	}{
		{"GET\r\n\r\n", ErrMalformedRequestLine},
		{"GET /\r\n\r\n", ErrMalformedRequestLine},
		{" / HTTP/1.1\r\n\r\n", ErrMalformedRequestLine},
		{"GET / \r\n\r\n", ErrMalformedRequestLine},
		{"GET  HTTP/1.1\r\n\r\n", ErrMalformedRequestLine},
		{"GET / FTP/1.1\r\n\r\n", ErrMalformedRequestLine},
		{"GET / HTTP/1.1\r\nNoColon\r\n\r\n", ErrMalformedField},
		{"GET / HTTP/1.1\r\n: v\r\n\r\n", ErrMalformedField},
		{"GET / HTTP/1.1\r\nHost: a\r\n", io.ErrUnexpectedEOF},
		{"GET / HTTP/1.1", io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		req, err := newReader(c.in).ReadHead()
		if !errors.Is(err, c.err) {
			t.Errorf("%q: want %v, got %v", c.in, c.err, err)
		}
		if req == nil || string(req.RawHead) != c.in && !strings.HasPrefix(c.in, string(req.RawHead)) {
			t.Errorf("%q: raw %q", c.in, req.RawHead)
		}
	}
	// Erro de leitura que não é EOF é repassado.
	boom := errors.New("boom")
	r := NewReader(bufio.NewReader(iotest.ErrReader(boom)))
	if req, err := r.ReadHead(); !errors.Is(err, boom) || req != nil {
		t.Fatal(req, err)
	}
}

// TestReadHeadTimeoutNoBytes: prazo de leitura vencido sem nenhum byte (ociosidade entre requisições) não
// devolve requisição; com bytes parciais, devolve o que chegou junto do erro.
func TestReadHeadTimeoutNoBytes(t *testing.T) {
	r := NewReader(bufio.NewReader(iotest.ErrReader(os.ErrDeadlineExceeded)))
	if req, err := r.ReadHead(); req != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want nil request and deadline error, got %+v %v", req, err)
	}
	// Só linhas vazias (toleradas antes da linha de requisição) e EOF: também não há requisição.
	if req, err := newReader("\r\n\n").ReadHead(); req != nil || !errors.Is(err, io.EOF) {
		t.Fatalf("empty lines: %+v %v", req, err)
	}
	partial := io.MultiReader(strings.NewReader("GET / HT"), iotest.ErrReader(os.ErrDeadlineExceeded))
	r = NewReader(bufio.NewReader(partial))
	req, err := r.ReadHead()
	if req == nil || !errors.Is(err, os.ErrDeadlineExceeded) || string(req.RawHead) != "GET / HT" {
		t.Fatalf("partial: %+v %v", req, err)
	}
}

func TestReadHeadLeadingEmptyLines(t *testing.T) {
	raw := "\r\n\nGET / HTTP/1.1\r\n\r\n"
	req, err := newReader(raw).ReadHead()
	if err != nil || string(req.RawHead) != raw || req.RequestLine.Method != "GET" {
		t.Fatalf("%v %q", err, req.RawHead)
	}
}

// Linhas maiores que o buffer do bufio são lidas inteiras.
func TestReadHeadLongLineSmallBuffer(t *testing.T) {
	val := strings.Repeat("v", 5000)
	raw := "GET / HTTP/1.1\r\nX: " + val + "\r\n\r\n"
	r := NewReader(bufio.NewReaderSize(iotest.OneByteReader(strings.NewReader(raw)), 16))
	req, err := r.ReadHead()
	if err != nil || req.Fields[0].Value() != val || string(req.RawHead) != raw {
		t.Fatal(err)
	}
}

func TestUpgradeAndExpect(t *testing.T) {
	cases := []struct {
		fields string
		want   string
	}{
		{"Upgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n", UpgradeH2C},
		{"Upgrade: WebSocket\r\n", UpgradeWebSocket},
		{"Upgrade: foo/1, websocket/13\r\n", UpgradeWebSocket},
		{"Upgrade: tls/1.2\r\n", ""},
	}
	for _, c := range cases {
		req, err := newReader("GET / HTTP/1.1\r\n" + c.fields + "\r\n").ReadHead()
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if req.Upgrade != nil {
			got = *req.Upgrade
		}
		if got != c.want {
			t.Errorf("%q: got %q", c.fields, got)
		}
	}
	req, _ := newReader("PUT / HTTP/1.1\r\nExpect:  100-Continue \r\nContent-Length: 1\r\n\r\n").ReadHead()
	if !req.ExpectsContinue() {
		t.Fatal("expect not recognized")
	}
}

// Pipelining: 3 requisições num só buffer; o servidor marca pipelined pelas que já estavam no buffer.
func TestPipelineThreeRequests(t *testing.T) {
	one := "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n"
	two := "POST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nbody"
	three := "GET /3 HTTP/1.1\r\nHost: a\r\n\r\n"
	r := newReader(one + two + three)
	var reqs []*Request
	for {
		req, err := r.ReadRequest(BodyOptions{})
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		reqs = append(reqs, req)
	}
	if len(reqs) != 3 {
		t.Fatalf("got %d requests", len(reqs))
	}
	// Como o servidor faz: a requisição i+1 é pipelined se havia bytes no buffer ao fim da i.
	for i := 1; i < len(reqs); i++ {
		reqs[i].Pipelined = reqs[i-1].BufferedAfter > 0
	}
	if reqs[0].Pipelined || !reqs[1].Pipelined || !reqs[2].Pipelined {
		t.Fatalf("pipelined flags %v %v %v", reqs[0].Pipelined, reqs[1].Pipelined, reqs[2].Pipelined)
	}
	if reqs[2].BufferedAfter != 0 {
		t.Fatal("bytes left after last request")
	}
	offs := []int64{0, int64(len(one)), int64(len(one + two))}
	for i, req := range reqs {
		if req.InOffset != offs[i] {
			t.Errorf("req %d offset %d want %d", i, req.InOffset, offs[i])
		}
	}
	if string(reqs[1].Body.Raw) != "body" || reqs[2].RequestLine.Target != "/3" {
		t.Fatal("pipeline contents")
	}
}

func TestRequestJSON(t *testing.T) {
	req, err := newReader("GET / HTTP/1.1\r\nHost: a\r\n\r\n").ReadRequest(BodyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"index", "raw_head_b64", "request_line", "fields", "duplicates", "proxy_signals", "body", "upgrade", "ja4h", "response_sent_size"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s in %s", k, b)
		}
	}
	if _, ok := m["BufferedAfter"]; ok {
		t.Error("BufferedAfter leaked")
	}
	if !strings.Contains(string(b), `"fields":[["Host",": ","a","crlf"]]`) {
		t.Errorf("field encoding: %s", b)
	}
	if !strings.Contains(string(b), `"raw_head_b64":"R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGENCg0K"`) {
		t.Errorf("raw head encoding: %s", b)
	}
}

func TestLimitInlineAndFields(t *testing.T) {
	req := &Request{
		RawHead:      []byte("0123456789"),
		ResponseSent: []byte("abcdefghij"),
		Body:         &Body{Raw: []byte("xyzxyzxyz")},
		Fields:       []Field{{"A", ": ", "1", TermCRLF}, {"B", ": ", "2", TermCRLF}, {"C", ": ", "3", TermCRLF}},
	}
	req.LimitInline(0)
	if req.RawHeadTruncated {
		t.Fatal("limit 0 cut")
	}
	req.LimitInline(4)
	if string(req.RawHead) != "0123" || !req.RawHeadTruncated || string(req.ResponseSent) != "abcd" ||
		!req.ResponseSentTruncated || string(req.Body.Raw) != "xyzx" || !req.Body.RawTruncated {
		t.Fatalf("%+v", req)
	}
	req.LimitFields(100)
	if req.FieldsTruncated || len(req.Fields) != 3 {
		t.Fatal("cut too early")
	}
	req.LimitFields(17) // cada campo tem 8 bytes
	if !req.FieldsTruncated || len(req.Fields) != 2 {
		t.Fatalf("%d", len(req.Fields))
	}
}
