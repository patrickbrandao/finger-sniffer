package ja4

import (
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// TestGoldenFoxIO: JA4, JA4_r, JA4_o e JA4_ro batem com o ja4 oficial em todos os ClientHellos TCP dos
// pcaps da FoxIO e dos clientes reais (testdata/tls).
func TestGoldenFoxIO(t *testing.T) {
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
		want := golden[file]
		got := map[string]bool{}
		for _, h := range hellos {
			g, ok := want[h.Key()]
			if !ok || g.JA4 == "" {
				t.Errorf("%s %s: ClientHello sem gabarito do ja4", file, h.Key())
				continue
			}
			got[h.Key()] = true
			ch, err := tlsparse.Parse(h.Records)
			if err != nil {
				t.Errorf("%s %s: %v", file, h.Key(), err)
				continue
			}
			f := Compute(ch, TCP)
			for _, c := range [][3]string{
				{"ja4", f.JA4, g.JA4}, {"ja4_r", f.JA4R, g.JA4R}, {"ja4_o", f.JA4O, g.JA4O}, {"ja4_ro", f.JA4RO, g.JA4RO},
			} {
				if c[1] != c[2] {
					t.Errorf("%s stream %d %s:\n got %s\nwant %s", file, g.Stream, c[0], c[1], c[2])
				}
			}
			// a parte a (com o trecho ALPN da definição publicada, spec 008 RF-03) bate com o tshark 4.4 em
			// todos os pcaps; o hash das assinaturas do tshark difere do ja4 0.18.6 em alguns, por isso só a parte a
			if a, _, _ := strings.Cut(f.JA4, "_"); g.TsharkJA4 != "" && !strings.HasPrefix(g.TsharkJA4, a+"_") {
				t.Errorf("%s stream %d parte a x tshark: got %s, tshark %s", file, g.Stream, f.JA4, g.TsharkJA4)
			}
			total++
		}
		for k, g := range want {
			if g.JA4 != "" && !got[k] {
				t.Errorf("%s stream %d (%s): o ja4 achou um ClientHello que o teste não achou", file, g.Stream, k)
			}
		}
	}
	if total < 150 {
		t.Fatalf("só %d ClientHellos conferidos", total)
	}
	t.Logf("%d ClientHellos conferidos em %d pcaps", total, len(files))
}
