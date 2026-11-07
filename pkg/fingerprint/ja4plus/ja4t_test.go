package ja4plus

import (
	"errors"
	"path"
	"slices"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
)

// tcpHdr monta um cabeçalho TCP com as opções dadas (com padding até múltiplo de 4).
func tcpHdr(flags uint8, win uint16, opts ...byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	h := make([]byte, 20, 20+len(opts))
	h[12] = byte((20+len(opts))/4) << 4
	h[13] = flags
	h[14], h[15] = byte(win>>8), byte(win)
	return append(h, opts...)
}

func TestJA4TFormat(t *testing.T) {
	cases := []struct {
		name string
		hdr  []byte
		want string
	}{
		{"linux", tcpHdr(0x02, 64240, 2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7), "64240_2-4-8-1-3_1460_7"},
		{"windows", tcpHdr(0x02, 64240, 2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2), "64240_2-1-3-1-1-4_1460_8"},
		{"sem opções", tcpHdr(0x02, 8192), "8192_00_00_00"},
		{"wscale zero", tcpHdr(0x02, 5744, 2, 4, 0x05, 0x9c, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 0), "5744_2-4-8-1-3_1436_00"},
		{"mss de um dígito", tcpHdr(0x02, 8192, 2, 4, 0, 9), "8192_2_09_00"},
		{"ECN no SYN", tcpHdr(0xc2, 65535, 2, 4, 5, 0xb4), "65535_2_1460_00"},
		{"EOL e zeros", tcpHdr(0x02, 65535, 2, 4, 5, 0xb4, 4, 2, 0, 0), "65535_2-4-0-0_1460_00"},
		{"EOL e lixo", tcpHdr(0x02, 1, 0, 1, 3, 3, 7, 0, 0, 0), "1_0_00_00"},
		{"MSS com tamanho errado", tcpHdr(0x02, 1, 2, 3, 5, 1), "1_2-1_00_00"},
		{"WS com tamanho errado", tcpHdr(0x02, 1, 3, 4, 7, 0), "1_3_00_00"},
		{"tamanho zero", tcpHdr(0x02, 1, 2, 4, 5, 0xb4, 30, 0, 1, 1), "1_2_1460_00"},
		{"passa do fim", tcpHdr(0x02, 1, 2, 4, 5, 0xb4, 1, 3, 9, 7), "1_2-1_1460_00"},
		{"sem byte de tamanho", tcpHdr(0x02, 1, 1, 1, 1, 30), "1_1-1-1_00_00"},
		{"último MSS vale", tcpHdr(0x02, 1, 2, 4, 5, 0xb4, 2, 4, 2, 0x18), "1_2-2_536_00"},
		{"truncado", tcpHdr(0x02, 1, 2, 4, 5, 0xb4)[:22], "1_2_00_00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := JA4T(c.hdr)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("JA4T = %q, quer %q", got, c.want)
			}
		})
	}
}

func TestJA4TErrors(t *testing.T) {
	if _, err := JA4T(make([]byte, 19)); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("curto: %v", err)
	}
	if _, err := JA4T(tcpHdr(0x12, 1)); !errors.Is(err, ErrNotSYN) {
		t.Fatalf("SYN-ACK: %v", err)
	}
	h := tcpHdr(0x02, 1)
	h[12] = 4 << 4
	if _, err := JA4T(h); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("doff 4: %v", err)
	}
	if _, err := ParseSYN(nil); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("ParseSYN: %v", err)
	}
	// ParseSYN não olha as flags: lê o SYN-ACK
	s, err := ParseSYN(tcpHdr(0x12, 65535, 2, 4, 5, 0xb4, 1, 3, 3, 13))
	if err != nil || s.MSS != 1460 || s.WScale != 13 {
		t.Fatalf("SYN-ACK: %+v %v", s, err)
	}
}

func TestIsInitialSYN(t *testing.T) {
	for flags, want := range map[uint8]bool{0x02: true, 0xc2: true, 0x12: false, 0x10: false, 0x00: false} {
		if IsInitialSYN(flags) != want {
			t.Errorf("IsInitialSYN(%#x) != %v", flags, want)
		}
	}
}

// TestJA4TGolden compara com a saída da ferramenta oficial ja4 da FoxIO sobre os mesmos pcaps
// (testdata/ja4t.golden.json, gerado por testdata/regen.sh): 100% dos fluxos precisam bater.
func TestJA4TGolden(t *testing.T) {
	golden, err := pcaptest.JA4TGolden()
	if err != nil {
		t.Fatal(err)
	}
	files, err := pcaptest.Files()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, file := range files {
		name := path.Base(file)
		pkts, err := pcaptest.Read(file)
		if err != nil {
			t.Fatal(err)
		}
		ours := map[string][]string{}
		for _, p := range pkts {
			if !IsInitialSYN(p.Flags) {
				continue
			}
			got, err := JA4T(p.TCP)
			if err != nil {
				t.Fatalf("%s frame %d: %v", name, p.Index, err)
			}
			k := pcaptest.FlowKey(p.Src, p.Dst)
			ours[k] = append(ours[k], got)
		}
		for _, g := range golden[name] {
			total++
			got := ours[g.Key()]
			if len(got) == 0 {
				t.Errorf("%s fluxo %d (%s): SYN não encontrado; ja4 = %s", name, g.Stream, g.Key(), g.JA4T)
				continue
			}
			if !slices.Contains(got, g.JA4T) {
				t.Errorf("%s fluxo %d (%s): JA4T = %v, ja4 da FoxIO = %s", name, g.Stream, g.Key(), got, g.JA4T)
			}
		}
	}
	if total < 70 {
		t.Fatalf("gabarito com só %d fluxos; regere com testdata/regen.sh", total)
	}
	t.Logf("%d fluxos conferidos contra o ja4 da FoxIO", total)
}

func FuzzJA4T(f *testing.F) {
	f.Add(tcpHdr(0x02, 64240, 2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7))
	f.Add(tcpHdr(0x02, 1, 0, 1, 3, 3, 7, 0, 0, 0))
	f.Add(tcpHdr(0x02, 1, 2, 4, 5, 0xb4)[:22])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSYN(b)
		if err != nil {
			return
		}
		doff := int(b[12]>>4) * 4
		// nunca lista mais opções que bytes de opção, e os valores ficam nas faixas válidas
		if len(s.Kinds) > max(0, min(doff, len(b))-20) {
			t.Fatalf("%d opções em %d bytes", len(s.Kinds), doff-20)
		}
		if s.MSS > 65535 || s.WScale > 255 {
			t.Fatalf("valores fora da faixa: %+v", s)
		}
		_ = s.String()
	})
}
