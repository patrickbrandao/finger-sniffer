package web

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

var testLimits = ControlLimits{SizeMax: 1000, DelayMax: 2 * time.Second, HSizeMax: 500, ChunkMax: 64, IdleMax: 10 * time.Second}

// TestParseControlsValues: cada parâmetro da RF-07 vira o campo certo.
func TestParseControlsValues(t *testing.T) {
	q := "status=103&status=404&ver=1.0&size=10&frame=chunked&chunk=4&trailers=1&conn=keep&ka=5,100" +
		"&close=mid-body&rst=1&delay_head=100&delay_body=200&idle=7&h=X-One:1&h=x-TWO:%20two%20&hsize=300" +
		"&continue=late&alt_svc=0&inline=1&_=123"
	c := ParseControls(q, testLimits)
	if !c.Valid() {
		t.Fatalf("invalid: %v", c.InvalidText())
	}
	want := Controls{
		Interim: []int{103}, Status: 404, Version: "HTTP/1.0", Size: 10, HasSize: true, Frame: FrameChunked,
		Chunk: 4, Trailers: true, Conn: ConnKeep, KeepAlive: "timeout=5, max=100", Close: CloseMidBody, RST: true,
		DelayHead: 100 * time.Millisecond, DelayBody: 200 * time.Millisecond, Idle: 7 * time.Second,
		Fields: []h1.HeaderField{{Name: "X-One", Value: "1"}, {Name: "x-TWO", Value: " two "}},
		HSize:  300, Continue: ContinueLate, NoAltSvc: true, Inline: true,
	}
	got := *c
	got.Record = h1.Controls{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if c.Record.Params["h"] != "X-One:1\nx-TWO: two " || c.Record.Params["_"] != "123" ||
		c.Record.Params["status"] != "103\n404" || len(c.Record.Clamped) != 0 || len(c.Record.Invalid) != 0 {
		t.Fatalf("record %+v", c.Record)
	}
}

// TestParseControlsClamp: valores acima dos tetos são reduzidos e listados em clamped.
func TestParseControlsClamp(t *testing.T) {
	c := ParseControls("size=5000&delay_head=99999999999&delay_body=3000&idle=11&hsize=501&chunk=65", testLimits)
	if !c.Valid() {
		t.Fatal(c.InvalidText())
	}
	if c.Size != 1000 || c.DelayHead != 2*time.Second || c.DelayBody != 2*time.Second || c.Idle != 10*time.Second ||
		c.HSize != 500 || c.Chunk != 64 {
		t.Fatalf("clamped values %+v", c)
	}
	want := []string{"size", "delay_head", "delay_body", "idle", "hsize", "chunk"}
	if !reflect.DeepEqual(c.Record.Clamped, want) {
		t.Fatalf("clamped %v", c.Record.Clamped)
	}
	// No teto exato não há clamped.
	if c := ParseControls("size=1000&delay_head=2000&idle=10", testLimits); len(c.Record.Clamped) != 0 {
		t.Fatalf("at limit: %v", c.Record.Clamped)
	}
}

// TestParseControlsInvalid: cada valor inválido vira uma linha do 400 e entra em invalid.
func TestParseControlsInvalid(t *testing.T) {
	cases := map[string]string{
		"status=abc": "status", "status=99": "status", "status=1000": "status", "status=200&status=404": "status",
		"status=101": "status", "ver=2": "ver", "size=-1": "size", "size=1e3": "size", "frame=gzip": "frame",
		"chunk=0": "chunk", "trailers=yes": "trailers", "conn=upgrade": "conn", "ka=a": "ka", "ka=5,": "ka",
		"close=now": "close", "rst=2": "rst", "delay_head=-5": "delay_head", "idle=0": "idle", "h=NoColon": "h",
		"h=Bad%20Name:1": "h", "h=X:a%0d%0aInjected:1": "h", "hsize=x": "hsize", "continue=maybe": "continue",
		"upgrade=h2c": "upgrade", "alt_svc=2": "alt_svc", "size=%zz": "size",
	}
	for q, name := range cases {
		c := ParseControls(q, testLimits)
		if c.Valid() || !reflect.DeepEqual(c.Record.Invalid, []string{name}) {
			t.Errorf("%s: invalid %v", q, c.Record.Invalid)
			continue
		}
		if txt := c.InvalidText(); !strings.HasPrefix(txt, "invalid response controls:\n"+name+"=") {
			t.Errorf("%s: text %q", q, txt)
		}
	}
	// Vários inválidos: todos explicados.
	c := ParseControls("status=x&ver=3", testLimits)
	if strings.Count(c.InvalidText(), "\n") != 3 {
		t.Fatalf("text %q", c.InvalidText())
	}
}

// TestParseControlsImplied: chunk/trailers implicam chunked; rst sozinho implica close=after; vazio é válido.
func TestParseControlsImplied(t *testing.T) {
	if c := ParseControls("trailers=1", testLimits); c.Frame != FrameChunked {
		t.Fatalf("frame %q", c.Frame)
	}
	if c := ParseControls("chunk=3&frame=close", testLimits); c.Frame != FrameClose {
		t.Fatalf("frame %q", c.Frame)
	}
	if c := ParseControls("rst=1", testLimits); c.Close != CloseAfter || !c.closes() {
		t.Fatalf("close %q", c.Close)
	}
	if c := ParseControls("status=101&upgrade=ws", testLimits); !c.Valid() || c.Status != 101 {
		t.Fatal(c.InvalidText())
	}
	c := ParseControls("", testLimits)
	if !c.Valid() || c.Record.Params != nil || c.closes() {
		t.Fatalf("empty %+v", c)
	}
}

// TestParseControlsRecordBounded: o registro dos parâmetros tem teto de quantidade e de tamanho.
func TestParseControlsRecordBounded(t *testing.T) {
	var b strings.Builder
	for i := range 200 {
		b.WriteString("p")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString("=" + strings.Repeat("v", 5000) + "&")
	}
	b.WriteString("h=X:" + strings.Repeat("a", 3000) + "&h=Y:1")
	c := ParseControls(b.String(), testLimits)
	if len(c.Record.Params) > recordMaxParams {
		t.Fatalf("%d params", len(c.Record.Params))
	}
	for k, v := range c.Record.Params {
		if len(v) > recordMaxValueLen {
			t.Fatalf("%s: %d bytes", k, len(v))
		}
	}
	if len(c.Fields) != 2 || len(c.Fields[0].Value) != 3000 {
		t.Fatalf("fields %d", len(c.Fields))
	}
}

func TestPatternReader(t *testing.T) {
	p := &patternReader{left: 130}
	buf := make([]byte, 7)
	var out []byte
	for {
		n, err := p.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(out) != bodyPattern+bodyPattern+"01" {
		t.Fatalf("%q", out)
	}
}

// FuzzParseControls: qualquer query é aceita ou recusada sem pânico, e o registro respeita os tetos.
func FuzzParseControls(f *testing.F) {
	for _, s := range []string{
		"status=103&size=10&frame=chunked&chunk=3&trailers=1&h=X:1", "ka=1,2&idle=99999999999999999999",
		"h=%zz&delay_head=1", "status=101", "&&=&a==b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		c := ParseControls(q, testLimits)
		if c.Size > testLimits.SizeMax || c.DelayHead > testLimits.DelayMax || c.Idle > testLimits.IdleMax ||
			c.HSize > testLimits.HSizeMax || len(c.Record.Params) > recordMaxParams {
			t.Fatalf("limits %+v", c)
		}
		for _, f := range c.Fields {
			if strings.ContainsAny(f.Value, "\r\n") || !isToken(f.Name) {
				t.Fatalf("field %q", f)
			}
		}
	})
}

func TestLoadControlLimits(t *testing.T) {
	t.Setenv("FS_SIZE_MAX", "1024")
	t.Setenv("FS_DELAY_MAX", "5s")
	t.Setenv("FS_HSIZE_MAX", "2048")
	l, err := loadControlLimits()
	if err != nil || l.SizeMax != 1024 || l.DelayMax != 5*time.Second || l.HSizeMax != 2048 {
		t.Fatalf("%+v %v", l, err)
	}
	t.Setenv("FS_SIZE_MAX", "0")
	if _, err := loadControlLimits(); err == nil {
		t.Fatal("FS_SIZE_MAX=0 accepted")
	}
}
