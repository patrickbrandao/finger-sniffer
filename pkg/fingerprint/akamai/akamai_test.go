package akamai

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

func frame(typ, flags uint8, sid uint32, payload []byte) []byte {
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags}
	b = binary.BigEndian.AppendUint32(b, sid)
	return append(b, payload...)
}

func settings(pairs ...uint32) []byte {
	var p []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		p = binary.BigEndian.AppendUint16(p, uint16(pairs[i]))
		p = binary.BigEndian.AppendUint32(p, pairs[i+1])
	}
	return frame(h2passive.FrameSettings, 0, 0, p)
}

func priority(sid uint32, dep uint32, w uint8) []byte {
	return frame(h2passive.FramePriority, 0, sid, append(binary.BigEndian.AppendUint32(nil, dep), w))
}

func conn(fs ...[]byte) []byte {
	b := []byte(h2passive.Preface)
	for _, f := range fs {
		b = append(b, f...)
	}
	return b
}

// blocos HPACK com os pseudo-cabeçalhos em ordens diferentes (todos indexados na tabela estática)
var (
	masp = []byte{0x82, 0x81, 0x87, 0x84} // :method :authority :scheme :path
	mpas = []byte{0x82, 0x84, 0x81, 0x87} // :method :path :authority :scheme
)

// Vetores do fingerproxy (Chrome 120 e Firefox 120), montados frame a frame.
func TestFingerproxyVectors(t *testing.T) {
	wu := binary.BigEndian.AppendUint32(nil, 15663105)
	chrome := conn(
		settings(1, 65536, 2, 0, 4, 6291456, 6, 262144),
		frame(h2passive.FrameWindowUpdate, 0, 0, wu),
		frame(h2passive.FrameHeaders, 0x25, 1, append([]byte{0x80, 0, 0, 0, 255}, masp...)),
	)
	if got, want := FromInfo(h2passive.Parse(chrome, h2passive.Options{})),
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"; got != want {
		t.Errorf("chrome = %q, want %q", got, want)
	}
	firefox := conn(
		settings(1, 65536, 4, 131072, 5, 16384),
		frame(h2passive.FrameWindowUpdate, 0, 0, binary.BigEndian.AppendUint32(nil, 12517377)),
		priority(3, 0, 200), priority(5, 0, 100), priority(7, 0, 0),
		priority(9, 7, 0), priority(11, 3, 0), priority(13, 0, 240),
		frame(h2passive.FrameHeaders, 0x25, 15, append([]byte{0, 0, 0, 13, 41}, mpas...)),
		priority(17, 0x80000000|15, 7), // depois do primeiro HEADERS: fora do fingerprint
	)
	if got, want := FromInfo(h2passive.Parse(firefox, h2passive.Options{})),
		"1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s"; got != want {
		t.Errorf("firefox = %q, want %q", got, want)
	}
}

// TestChromeFoxIOCapture: Chrome do http2-with-cookies.pcapng da FoxIO (sentido do cliente decifrado pelo
// tshark); SETTINGS, WINDOW_UPDATE e pseudo-cabeçalhos conferidos com o tshark 4.4 no mesmo pcap.
func TestChromeFoxIOCapture(t *testing.T) {
	raw, err := os.ReadFile("../../h2passive/testdata/chrome-foxio-in.bin")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FromInfo(h2passive.Parse(raw, h2passive.Options{})),
		"1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"; got != want {
		t.Fatalf("akamai = %q, want %q", got, want)
	}
}

func TestEdgeCases(t *testing.T) {
	if FromInfo(nil) != "" {
		t.Fatal("nil")
	}
	// sem nada: settings vazio, WU 00, prioridade 0, sem pseudo
	if got := FromInfo(h2passive.Parse(nil, h2passive.Options{})); got != "|00|0|" {
		t.Fatalf("vazio = %q", got)
	}
	zero := uint32(0)
	got := Fingerprint(Input{
		Settings:     [][2]uint32{{1, 1}, {1, 2}},
		WindowUpdate: &zero,
		Priorities:   []h2passive.Priority{{StreamID: 1, Exclusive: true, DependsOn: 0, Weight: 256}},
		PseudoOrder:  []string{":method", "x", ":", ":protocol"},
	})
	if got != "1:1;1:2|00|1:1:0:256|m,p" {
		t.Fatalf("got %q", got)
	}
	// PRIORITY cortado pelo teto continua consistente
	lim := h2passive.DefaultLimits()
	lim.MaxPriorityFrames = 1
	info := h2passive.Parse(conn(priority(3, 0, 1), priority(5, 0, 1), frame(h2passive.FrameHeaders, 4, 1, masp)),
		h2passive.Options{Limits: lim})
	if got := FromInfo(info); got != "|00|3:0:0:2|m,a,s,p" || !info.PriorityFramesCapped {
		t.Fatalf("capped = %q", got)
	}
}
