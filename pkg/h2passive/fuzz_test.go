package h2passive

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// FuzzParse alimenta o parser com bytes arbitrários, inteiros e em dois pedaços: não pode entrar em pânico,
// o resultado tem de virar JSON e os tetos têm de ser respeitados.
func FuzzParse(f *testing.F) {
	if raw, err := os.ReadFile("testdata/chrome-foxio-in.bin"); err == nil {
		f.Add(raw[:min(len(raw), 4096)], uint16(100), true)
	}
	f.Add(conn(settings(1, 1, 1, 2), windowUpdate(0, 9), priority(3, true, 1, 9),
		frame(FrameHeaders, FlagPadded|FlagPriority, 1, append([]byte{1}, append(prioBytes(false, 0, 1), 0x82, 0)...)),
		frame(FrameContinuation, FlagEndHeaders, 1, []byte{0x40, 0x81, 0x1f, 0x00})), uint16(30), true)
	f.Add([]byte(Preface[:10]), uint16(3), false)
	f.Fuzz(func(t *testing.T, b []byte, cut uint16, preface bool) {
		lim := DefaultLimits()
		lim.MaxFrames = 64
		lim.MaxStreams = 8
		lim.MaxPriorityFrames = 4
		lim.MaxHeaderBlock = 512
		opts := Options{SkipPreface: !preface, Limits: lim}
		p := NewParser(opts)
		c := min(int(cut), len(b))
		p.Feed(0, b[:c])
		p.Feed(1, b[c:])
		info := p.Info()
		if len(info.Frames) > 64 || len(info.Streams) > 8 || len(info.Priorities) > 4 {
			t.Fatalf("teto violado: frames=%d streams=%d prio=%d", len(info.Frames), len(info.Streams), len(info.Priorities))
		}
		if _, err := json.Marshal(info); err != nil {
			t.Fatal(err)
		}
		_ = Merge(info, Parse(b, Options{Dir: DirOut, Limits: lim}), 64)
	})
}

// FuzzHPACK confere o decodificador contra o do x/net: quando os dois aceitam o bloco, nomes e valores
// têm de ser iguais.
func FuzzHPACK(f *testing.F) {
	f.Add([]byte{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff})
	f.Add([]byte{0x40, 0x01, 'a', 0x01, 'b', 0xbe, 0x10, 0x01, 'c', 0x00})
	f.Add([]byte{0x3f, 0x09, 0x0f, 0x2b, 0x01, 'x'})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := newHPACKDecoder(4096, 1<<16).decode(b)
		want, refErr := hpack.NewDecoder(4096, nil).DecodeFull(b)
		if err != nil || refErr != nil {
			return
		}
		if len(got) != len(want) {
			t.Fatalf("%d campos, x/net %d", len(got), len(want))
		}
		for i := range got {
			if got[i].Name != want[i].Name || got[i].Value != want[i].Value {
				t.Fatalf("campo %d: %q=%q, x/net %q=%q", i, got[i].Name, got[i].Value, want[i].Name, want[i].Value)
			}
		}
	})
}
