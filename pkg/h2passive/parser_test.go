package h2passive

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// frame monta um frame HTTP/2 à mão.
func frame(typ, flags uint8, sid uint32, payload []byte) []byte {
	b := make([]byte, 9, 9+len(payload))
	b[0], b[1], b[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	b[3], b[4] = typ, flags
	binary.BigEndian.PutUint32(b[5:], sid)
	return append(b, payload...)
}

func settings(pairs ...uint32) []byte {
	var p []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		p = binary.BigEndian.AppendUint16(p, uint16(pairs[i]))
		p = binary.BigEndian.AppendUint32(p, pairs[i+1])
	}
	return frame(FrameSettings, 0, 0, p)
}

func windowUpdate(sid, inc uint32) []byte {
	return frame(FrameWindowUpdate, 0, sid, binary.BigEndian.AppendUint32(nil, inc))
}

func priority(sid uint32, excl bool, dep uint32, wireWeight uint8) []byte {
	return frame(FramePriority, 0, sid, prioBytes(excl, dep, wireWeight))
}

func prioBytes(excl bool, dep uint32, w uint8) []byte {
	if excl {
		dep |= 0x80000000
	}
	return append(binary.BigEndian.AppendUint32(nil, dep), w)
}

// bloco HPACK de um GET típico de navegador: :method GET (indexado 2), :authority literal com nome
// indexado (1), :scheme https (7), :path / (4).
func simpleBlock() []byte {
	return []byte{0x82, 0x41, 0x03, 'a', '.', 'b', 0x87, 0x84}
}

func conn(frames ...[]byte) []byte {
	b := []byte(Preface)
	for _, f := range frames {
		b = append(b, f...)
	}
	return b
}

func TestSettingsOrderWithRepeatedIDs(t *testing.T) {
	in := conn(
		settings(4, 6291456, 1, 65536, 4, 1, 2, 0, 1, 4096, 0xff, 7),
		windowUpdate(0, 15663105),
		frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, simpleBlock()),
	)
	info := Parse(in, Options{Mode: ModeALPN})
	want := [][2]uint32{{4, 6291456}, {1, 65536}, {4, 1}, {2, 0}, {1, 4096}, {0xff, 7}}
	if !reflect.DeepEqual(info.Settings, want) {
		t.Fatalf("settings = %v, want %v", info.Settings, want)
	}
	if !info.PrefaceOK || info.Mode != ModeALPN {
		t.Fatalf("preface_ok=%v mode=%q", info.PrefaceOK, info.Mode)
	}
	if info.WindowUpdate == nil || *info.WindowUpdate != 15663105 {
		t.Fatalf("window_update = %v", info.WindowUpdate)
	}
	// JSON: [[id, valor], ...] na ordem
	js, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(js, []byte(`"settings":[[4,6291456],[1,65536],[4,1],[2,0],[1,4096],[255,7]]`)) {
		t.Fatalf("json sem a ordem dos settings: %s", js)
	}
}

func TestOnlyFirstSettingsRecorded(t *testing.T) {
	in := conn(settings(1, 1), frame(FrameSettings, FlagAck, 0, nil), settings(2, 2))
	info := Parse(in, Options{})
	if !reflect.DeepEqual(info.Settings, [][2]uint32{{1, 1}}) {
		t.Fatalf("settings = %v", info.Settings)
	}
	if len(info.Frames) != 3 || info.Frames[1].Flags != FlagAck {
		t.Fatalf("frames = %+v", info.Frames)
	}
	// SETTINGS ACK primeiro não conta como o SETTINGS do cliente; SETTINGS com tamanho errado também não
	info = Parse(conn(frame(FrameSettings, FlagAck, 0, nil), frame(FrameSettings, 0, 0, []byte{1, 2, 3}), settings(3, 3)), Options{})
	if !reflect.DeepEqual(info.Settings, [][2]uint32{{3, 3}}) {
		t.Fatalf("settings = %v", info.Settings)
	}
}

func TestPriorityFramesAndHeadersPriority(t *testing.T) {
	// Firefox clássico: PRIORITY em 3,5,7,9,11,13 antes do primeiro HEADERS
	in := conn(
		settings(1, 65536, 4, 131072, 5, 16384),
		windowUpdate(0, 12517377),
		priority(3, false, 0, 200),
		priority(5, false, 0, 100),
		priority(7, false, 0, 0),
		priority(9, false, 7, 0),
		priority(11, false, 3, 0),
		priority(13, false, 0, 240),
		frame(FrameHeaders, FlagEndHeaders|FlagEndStream|FlagPriority, 15,
			append(prioBytes(true, 13, 41), simpleBlock()...)),
		priority(17, true, 15, 255),
	)
	info := Parse(in, Options{})
	if len(info.Priorities) != 7 || info.PrioritiesBeforeHeaders != 6 || info.PriorityFramesCapped {
		t.Fatalf("priorities = %+v before=%d", info.Priorities, info.PrioritiesBeforeHeaders)
	}
	if p := info.Priorities[0]; p.StreamID != 3 || p.Weight != 201 || p.Exclusive || p.DependsOn != 0 {
		t.Fatalf("priority[0] = %+v", p)
	}
	if p := info.Priorities[6]; p.StreamID != 17 || p.Weight != 256 || !p.Exclusive || p.DependsOn != 15 {
		t.Fatalf("priority[6] = %+v", p)
	}
	if info.FirstHeadersStream != 15 || len(info.Streams) != 1 {
		t.Fatalf("streams = %+v", info.Streams)
	}
	st := info.Streams[0]
	if st.Priority == nil || *st.Priority != (StreamPriority{Exclusive: true, DependsOn: 13, Weight: 42}) {
		t.Fatalf("stream priority = %+v", st.Priority)
	}
	if !st.EndStream || !reflect.DeepEqual(st.PseudoOrder, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("stream = %+v", st)
	}
}

func TestPriorityFramesCapped(t *testing.T) {
	var fs [][]byte
	for i := range 20 {
		fs = append(fs, priority(uint32(2*i+1), false, 0, 15))
	}
	fs = append(fs, frame(FramePriority, 0, 99, []byte{1, 2})) // tamanho inválido: conta, não registra
	lim := DefaultLimits()
	lim.MaxPriorityFrames = 5
	info := Parse(conn(fs...), Options{Limits: lim})
	if len(info.Priorities) != 5 || !info.PriorityFramesCapped || info.PriorityFrames != 21 {
		t.Fatalf("priorities=%d capped=%v total=%d", len(info.Priorities), info.PriorityFramesCapped, info.PriorityFrames)
	}
	if len(info.Frames) != 21 {
		t.Fatalf("frames = %d", len(info.Frames))
	}
}

func TestWindowUpdateOnlyInitial(t *testing.T) {
	in := conn(
		windowUpdate(1, 10), // stream != 0 não conta
		frame(FrameWindowUpdate, 0, 0, []byte{1}),
		windowUpdate(0, 0x80000005), // bit reservado descartado
		windowUpdate(0, 7),
	)
	info := Parse(in, Options{})
	if info.WindowUpdate == nil || *info.WindowUpdate != 5 {
		t.Fatalf("window_update = %v", info.WindowUpdate)
	}
	// WINDOW_UPDATE depois do primeiro HEADERS não é o inicial
	info = Parse(conn(frame(FrameHeaders, FlagEndHeaders, 1, simpleBlock()), windowUpdate(0, 9)), Options{})
	if info.WindowUpdate != nil {
		t.Fatalf("window_update = %v", *info.WindowUpdate)
	}
}

func TestBadPreface(t *testing.T) {
	p := NewParser(Options{})
	p.Feed(0, []byte("PRI * HTTP/2.0\r\n"))
	p.Feed(1, []byte("GET / HTTP/1.1\r\n\r\n"))
	p.Feed(2, settings(1, 1))
	info := p.Info()
	if info.PrefaceOK || !errors.Is(p.Err(), ErrBadPreface) || len(info.Frames) != 0 {
		t.Fatalf("info=%+v err=%v", info, p.Err())
	}
	// sentido out e SkipPreface não esperam prefácio
	for _, o := range []Options{{Dir: DirOut}, {SkipPreface: true}} {
		info := Parse(settings(3, 100), o)
		if !info.PrefaceOK || len(info.Settings) != 1 {
			t.Fatalf("%+v: %+v", o, info)
		}
	}
}

func TestFeedByteByByteMatchesWhole(t *testing.T) {
	in := conn(
		settings(1, 65536, 2, 0),
		windowUpdate(0, 100),
		priority(3, false, 0, 1),
		frame(FrameHeaders, FlagPriority|FlagPadded, 1,
			append(append([]byte{3}, append(prioBytes(false, 0, 255), simpleBlock()[:3]...)...), 0, 0, 0)),
		frame(FrameContinuation, 0, 1, simpleBlock()[3:5]),
		frame(FrameContinuation, FlagEndHeaders, 1, simpleBlock()[5:]),
		frame(FrameData, FlagEndStream, 1, []byte("hello")),
		frame(0xee, 0, 0, []byte("x")),
	)
	whole := Parse(in, Options{})
	p := NewParser(Options{})
	for i, c := range in {
		p.Feed(float64(i), []byte{c})
	}
	parts := p.Info()
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	// os tempos diferem; o resto é igual
	for i := range parts.Frames {
		if parts.Frames[i].TMs < 24 {
			t.Fatalf("frame %d com tempo %v anterior ao prefácio", i, parts.Frames[i].TMs)
		}
		parts.Frames[i].TMs = 0
	}
	if !reflect.DeepEqual(whole, parts) {
		t.Fatalf("diferente:\n%+v\n%+v", whole, parts)
	}
	if len(whole.Streams) != 1 || len(whole.Streams[0].Fields) != 4 || !whole.Streams[0].EndStream {
		t.Fatalf("stream = %+v", whole.Streams)
	}
	if whole.Frames[7].Type != "UNKNOWN_0xee" || whole.Frames[6].Type != "DATA" || whole.Frames[6].Length != 5 {
		t.Fatalf("frames = %+v", whole.Frames)
	}
}

func TestFrameTimes(t *testing.T) {
	p := NewParser(Options{})
	p.Feed(1, []byte(Preface))
	s := settings(1, 1)
	p.Feed(2, s[:4])
	p.Feed(3, s[4:])
	p.Feed(4, windowUpdate(0, 1))
	f := p.Info().Frames
	if len(f) != 2 || f[0].TMs != 2 || f[1].TMs != 4 || f[0].Dir != DirIn {
		t.Fatalf("frames = %+v", f)
	}
}

func TestLimits(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxFrames = 2
	lim.MaxStreams = 1
	in := conn(
		frame(FrameHeaders, FlagEndHeaders, 1, simpleBlock()),
		frame(FrameHeaders, FlagEndHeaders, 3, []byte{0x82}),
		frame(FramePing, 0, 0, make([]byte, 8)),
	)
	info := Parse(in, Options{Limits: lim})
	if len(info.Frames) != 2 || !info.FramesTruncated || info.FrameCount != 3 {
		t.Fatalf("frames=%d truncated=%v count=%d", len(info.Frames), info.FramesTruncated, info.FrameCount)
	}
	if len(info.Streams) != 1 {
		t.Fatalf("streams = %d", len(info.Streams))
	}

	// bloco acima do teto para o HPACK, mas os frames seguem
	lim = DefaultLimits()
	lim.MaxHeaderBlock = 6
	p := NewParser(Options{Limits: lim})
	p.Feed(0, conn(
		frame(FrameHeaders, 0, 1, simpleBlock()[:4]),
		frame(FrameContinuation, FlagEndHeaders, 1, simpleBlock()[4:]),
		frame(FrameHeaders, FlagEndHeaders, 3, make([]byte, 7)),
		windowUpdate(0, 1),
	))
	info = p.Info()
	if !errors.Is(p.Err(), ErrHeaderBlockLimit) || len(info.Frames) != 4 || len(info.Streams[0].Fields) != 0 {
		t.Fatalf("err=%v info=%+v", p.Err(), info)
	}

	// SETTINGS gigante não é registrado
	lim = DefaultLimits()
	lim.MaxSettings = 1
	info = Parse(conn(settings(1, 1, 2, 2)), Options{Limits: lim})
	if len(info.Settings) != 0 {
		t.Fatalf("settings = %v", info.Settings)
	}
}

func TestLimitsFromEnv(t *testing.T) {
	t.Setenv("FS_MAX_H2_PRIORITY_FRAMES", "42")
	l, err := LimitsFromEnv()
	if err != nil || l.MaxPriorityFrames != 42 || l.MaxFrames != DefaultMaxFrames {
		t.Fatalf("%+v %v", l, err)
	}
	t.Setenv("FS_MAX_H2_PRIORITY_FRAMES", "x")
	if _, err := LimitsFromEnv(); err == nil {
		t.Fatal("esperava erro")
	}
	t.Setenv("FS_MAX_H2_PRIORITY_FRAMES", "")
	if l, _ := LimitsFromEnv(); l != DefaultLimits() {
		t.Fatalf("%+v", l)
	}
	if n := (Limits{MaxPriorityFrames: -1}).normalize(); n != DefaultLimits() {
		t.Fatalf("%+v", n)
	}
}

func TestContinuationViolations(t *testing.T) {
	// frame intercalado num bloco aberto
	p := NewParser(Options{})
	p.Feed(0, conn(
		frame(FrameHeaders, 0, 1, simpleBlock()[:2]),
		windowUpdate(0, 1),
		frame(FrameContinuation, FlagEndHeaders, 1, simpleBlock()[2:]),
		frame(FrameHeaders, FlagEndHeaders|FlagPriority, 3, append(prioBytes(false, 1, 9), 0x82)),
	))
	info := p.Info()
	if !errors.Is(p.Err(), ErrContinuationOrder) || len(info.Frames) != 4 {
		t.Fatalf("err=%v frames=%d", p.Err(), len(info.Frames))
	}
	// com o HPACK parado, a prioridade dos HEADERS seguintes continua sendo lida
	if len(info.Streams) != 2 || info.Streams[1].Priority == nil || info.Streams[1].Priority.Weight != 10 ||
		len(info.Streams[1].Fields) != 0 {
		t.Fatalf("streams = %+v", info.Streams)
	}
	// CONTINUATION sem bloco aberto é ignorado
	info = Parse(conn(frame(FrameContinuation, FlagEndHeaders, 1, []byte{0x82})), Options{})
	if len(info.Streams) != 0 {
		t.Fatalf("streams = %+v", info.Streams)
	}
}

func TestMalformedHeaders(t *testing.T) {
	for name, f := range map[string][]byte{
		"padded vazio":      frame(FrameHeaders, FlagEndHeaders|FlagPadded, 1, nil),
		"padding demais":    frame(FrameHeaders, FlagEndHeaders|FlagPadded, 1, []byte{9, 0x82}),
		"prioridade curta":  frame(FrameHeaders, FlagEndHeaders|FlagPriority, 1, []byte{0, 0}),
		"hpack inválido":    frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x80}),
		"hpack truncado":    frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x41, 0x05, 'a'}),
		"tabela grande":     frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x3f, 0xe1, 0x7f}),
		"índice dinâmico":   frame(FrameHeaders, FlagEndHeaders, 1, []byte{0xbe}),
		"nome com índice 0": frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x0f, 0x7f}),
	} {
		p := NewParser(Options{})
		p.Feed(0, conn(f, frame(FrameHeaders, FlagEndHeaders, 3, simpleBlock())))
		info := p.Info()
		if p.Err() == nil || len(info.Frames) != 2 {
			t.Errorf("%s: err=%v frames=%d", name, p.Err(), len(info.Frames))
		}
		// depois do erro o HPACK fica parado
		if len(info.Streams) == 2 && len(info.Streams[1].Fields) != 0 {
			t.Errorf("%s: stream 3 decodificado depois do erro", name)
		}
	}
}

func TestOutDirectionStatusAndMerge(t *testing.T) {
	// resposta: :status 200 (indexado 8), depois :status 404 (13) em outro stream
	out := Parse(conn(settings(3, 100),
		frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x88}),
		frame(FrameHeaders, FlagEndHeaders, 3, []byte{0x8d}),
		frame(FrameHeaders, FlagEndHeaders, 5, []byte{0x08, 0x02, 'x', 'y'}), // :status inválido
	)[len(Preface):], Options{Dir: DirOut})
	if out.Streams[0].Status != 200 || out.Streams[1].Status != 404 || out.Streams[2].Status != 0 {
		t.Fatalf("streams = %+v", out.Streams)
	}
	pi := NewParser(Options{})
	pi.Feed(0, []byte(Preface))
	pi.Feed(1, settings(1, 1))
	pi.Feed(3, frame(FrameHeaders, FlagEndHeaders, 1, simpleBlock()))
	pi.Feed(5, frame(FrameHeaders, FlagEndHeaders, 3, []byte{0x82}))
	in := pi.Info()
	po := NewParser(Options{Dir: DirOut})
	po.Feed(2, settings(3, 100))
	po.Feed(4, frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x88}))
	m := Merge(in, po.Info(), 0)
	var dirs []string
	for _, f := range m.Frames {
		dirs = append(dirs, f.Dir)
	}
	if strings.Join(dirs, ",") != "in,out,in,out,in" || m.FramesTruncated || m.FrameCount != 5 {
		t.Fatalf("frames = %+v", m.Frames)
	}
	if m.Streams[0].Status != 200 || m.Streams[1].Status != 0 || in.Streams[0].Status != 0 {
		t.Fatalf("streams = %+v", m.Streams)
	}
	m = Merge(in, po.Info(), 3)
	if len(m.Frames) != 3 || !m.FramesTruncated {
		t.Fatalf("frames = %d truncated=%v", len(m.Frames), m.FramesTruncated)
	}
	if m := Merge(in, nil, 0); len(m.Frames) != 3 {
		t.Fatalf("merge sem out = %+v", m)
	}
}

func TestTrailers(t *testing.T) {
	in := conn(
		frame(FrameHeaders, FlagEndHeaders, 1, simpleBlock()),
		frame(FrameData, 0, 1, []byte("a")),
		frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, []byte{0x00, 0x01, 'x', 0x01, 'y', 0x84}),
		frame(FrameData, FlagEndStream, 7, nil), // DATA de stream desconhecido não cria stream
	)
	info := Parse(in, Options{})
	st := info.Streams[0]
	if len(info.Streams) != 1 || st.HeadFields != 4 || len(st.Fields) != 6 || len(st.PseudoOrder) != 4 || !st.EndStream {
		t.Fatalf("stream = %+v", st)
	}
}

func TestInfoNeverNullLists(t *testing.T) {
	js, err := json.Marshal(Parse(nil, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"settings":[]`, `"priorities":[]`, `"streams":[]`, `"frames":[]`, `"window_update":null`} {
		if !bytes.Contains(js, []byte(k)) {
			t.Errorf("sem %s em %s", k, js)
		}
	}
	js, _ = json.Marshal(Parse(conn(frame(FrameHeaders, FlagEndHeaders, 1, nil)), Options{}))
	if !bytes.Contains(js, []byte(`"pseudo_order":[],"fields":[]`)) {
		t.Errorf("stream vazio: %s", js)
	}
}

func TestFrameTypeName(t *testing.T) {
	for typ, want := range map[uint8]string{0: "DATA", 9: "CONTINUATION", 0xc: "ORIGIN", 0x10: "PRIORITY_UPDATE", 0xb: "UNKNOWN_0x0b"} {
		if got := FrameTypeName(typ); got != want {
			t.Errorf("%d: %q", typ, got)
		}
	}
}

// TestChromeFoxIOCapture lê o sentido do cliente (decifrado pelo tshark) do http2-with-cookies.pcapng da
// FoxIO e confere nomes e representações HPACK de cada stream contra o tshark 4.4.
func TestChromeFoxIOCapture(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome-foxio-in.bin")
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(Options{Mode: ModeALPN})
	// pedaços de tamanho irregular, como chegam do TLS
	for i, n := 0, 1; i < len(raw); i, n = i+n, n%97+13 {
		p.Feed(float64(i), raw[i:min(i+n, len(raw))])
	}
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	info := p.Info()
	want := [][2]uint32{{1, 65536}, {2, 0}, {3, 1000}, {4, 6291456}, {6, 262144}}
	if !info.PrefaceOK || !reflect.DeepEqual(info.Settings, want) {
		t.Fatalf("settings = %v", info.Settings)
	}
	if info.WindowUpdate == nil || *info.WindowUpdate != 15663105 {
		t.Fatalf("window_update = %v", info.WindowUpdate)
	}
	f, err := os.Open("testdata/chrome-foxio-in.tshark.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // só leitura
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		sid, _ := strconv.Atoi(cols[0])
		names := strings.Split(cols[1], "|")
		reprs := strings.Split(cols[2], "|")
		var st *HTTP2Stream
		for i := range info.Streams {
			if info.Streams[i].StreamID == uint32(sid) {
				st = &info.Streams[i]
			}
		}
		if st == nil {
			t.Fatalf("stream %d ausente", sid)
		}
		if len(st.Fields) != len(names) {
			t.Fatalf("stream %d: %d campos, tshark %d", sid, len(st.Fields), len(names))
		}
		for i, fl := range st.Fields {
			if fl.Name != names[i] || fl.Repr != tsharkRepr(reprs[i]) {
				t.Errorf("stream %d campo %d: %s/%s, tshark %s/%s", sid, i, fl.Name, fl.Repr, names[i], reprs[i])
			}
			if strings.HasSuffix(reprs[i], "New Name") != (fl.Index == nil) {
				t.Errorf("stream %d campo %d: índice %v com %s", sid, i, fl.Index, reprs[i])
			}
		}
		dep, _ := strconv.Atoi(cols[4])
		w, _ := strconv.Atoi(cols[5])
		wantPrio := StreamPriority{Exclusive: cols[3] == "True", DependsOn: uint32(dep), Weight: w}
		if st.Priority == nil || *st.Priority != wantPrio || !st.EndStream {
			t.Errorf("stream %d: priority=%+v end=%v, tshark %+v", sid, st.Priority, st.EndStream, wantPrio)
		}
		n++
	}
	if n != 15 || len(info.Streams) != 15 {
		t.Fatalf("streams: tshark %d, parser %d", n, len(info.Streams))
	}
	if got := info.Streams[0].PseudoOrder; !reflect.DeepEqual(got, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("pseudo_order = %v", got)
	}
}

func tsharkRepr(s string) string {
	switch {
	case s == "Indexed Header Field":
		return ReprIndexed
	case strings.HasPrefix(s, "Literal Header Field with Incremental Indexing"):
		return ReprLiteralIndexed
	case strings.HasPrefix(s, "Literal Header Field without Indexing"):
		return ReprLiteralNotIndexed
	case strings.HasPrefix(s, "Literal Header Field never Indexed"):
		return ReprLiteralNeverIndexed
	}
	return "?" + s
}

// TestStreamInstants: FeedAt marca o fim do primeiro HEADERS, o END_STREAM e o RST_STREAM de cada stream
// (ADR 0029); no sentido out o RST de um stream sem HEADERS cria o stream.
func TestStreamInstants(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	p := NewParser(Options{})
	p.FeedAt(at(0), 0, []byte(Preface))
	h := frame(FrameHeaders, FlagEndHeaders, 1, simpleBlock())
	p.FeedAt(at(1), 1, h[:5])
	p.FeedAt(at(2), 2, h[5:])
	p.FeedAt(at(3), 3, frame(FrameData, 0, 1, []byte("ab")))
	p.FeedAt(at(4), 4, frame(FrameData, FlagEndStream, 1, []byte("c")))
	p.FeedAt(at(5), 5, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 3, []byte{0x82, 0x87, 0x84}))
	p.FeedAt(at(6), 6, frame(FrameHeaders, FlagEndHeaders, 1, []byte{0x82}))
	p.FeedAt(at(7), 7, frame(FrameRSTStream, 0, 9, []byte{0, 0, 0, 8}))
	st := p.Info().Streams
	if len(st) != 2 || !st[0].HeadersAt.Equal(at(2)) || !st[0].EndAt.Equal(at(4)) || !st[0].ResetAt.IsZero() ||
		!st[1].HeadersAt.Equal(at(5)) || !st[1].EndAt.Equal(at(5)) {
		t.Fatalf("streams %+v", st)
	}
	out := NewParser(Options{Dir: DirOut})
	out.FeedAt(at(8), 8, frame(FrameRSTStream, 0, 5, []byte{0, 0, 0, 2}))
	if ost := out.Info().Streams; len(ost) != 1 || ost[0].StreamID != 5 || !ost[0].ResetAt.Equal(at(8)) {
		t.Fatalf("out %+v", ost)
	}
	// Feed sem instante deixa tudo zero.
	q := NewParser(Options{})
	q.Feed(0, conn(frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, simpleBlock())))
	if s := q.Info().Streams[0]; !s.HeadersAt.IsZero() || !s.EndAt.IsZero() {
		t.Fatalf("Feed %+v", s)
	}
}
