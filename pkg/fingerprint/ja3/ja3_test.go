package ja3

import (
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// TestGoldenTshark: JA3 e MD5 batem com tls.handshake.ja3_full/ja3 do tshark 4.4 em todos os ClientHellos
// dos pcaps de testdata/tls (FoxIO e clientes reais).
func TestGoldenTshark(t *testing.T) {
	golden, err := pcaptest.TLSGolden()
	if err != nil {
		t.Fatal(err)
	}
	files, err := pcaptest.TLSFiles()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, file := range files {
		hellos, err := pcaptest.ClientHellos(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hellos {
			g, ok := golden[file][h.Key()]
			if !ok || g.JA3 == "" {
				t.Errorf("%s %s: sem gabarito do tshark", file, h.Key())
				continue
			}
			ch, err := tlsparse.Parse(h.Records)
			if err != nil {
				t.Fatal(err)
			}
			f := Compute(ch)
			if f.JA3 != g.JA3 || f.JA3MD5 != g.JA3MD5 {
				t.Errorf("%s stream %d:\n got %s %s\nwant %s %s", file, g.Stream, f.JA3, f.JA3MD5, g.JA3, g.JA3MD5)
			}
			total++
		}
	}
	if total < 150 {
		t.Fatalf("só %d ClientHellos conferidos", total)
	}
	t.Logf("%d ClientHellos conferidos em %d pcaps", total, len(files))
}
