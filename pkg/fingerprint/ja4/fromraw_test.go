package ja4_test

import (
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// checkFromRaw confere FromRaw(f.JA4R) == (f.JA4, f.Stable, true) (ADR 0072 item 1.2).
func checkFromRaw(t *testing.T, where string, f ja4.Fingerprint) {
	t.Helper()
	j, st, ok := ja4.FromRaw(f.JA4R)
	if !ok || j != f.JA4 || st != f.Stable {
		t.Errorf("%s: FromRaw(%s) = %s %s %v; Compute %s %s", where, f.JA4R, j, st, ok, f.JA4, f.Stable)
	}
}

// TestFromRawPcaps: para todo ClientHello TCP dos pcaps de testdata/tls e todo Initial QUIC golden, o JA4 e o
// stable recalculados do JA4_r são os de Compute.
func TestFromRawPcaps(t *testing.T) {
	files, err := pcaptest.TLSFiles()
	if err != nil {
		t.Fatal(err)
	}
	total, resumed := 0, 0
	for _, file := range files {
		hellos, err := pcaptest.ClientHellos(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hellos {
			ch, err := tlsparse.Parse(h.Records)
			if err != nil {
				continue // o TestGoldenFoxIO já acusa o ClientHello que não analisa
			}
			f := ja4.Compute(ch, ja4.TCP)
			checkFromRaw(t, file+" "+h.Key(), f)
			if f.Stable != f.JA4 {
				resumed++
			}
			total++
		}
	}
	quic, err := pcaptest.QUICFiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range quic {
		ds, err := pcaptest.Datagrams(file)
		if err != nil {
			t.Fatal(err)
		}
		var payloads [][]byte
		for _, d := range ds {
			payloads = append(payloads, d.Payload)
		}
		a := quicparse.Analyze(payloads, quicparse.Options{})
		if !a.Complete() || a.Err() != nil {
			t.Fatalf("%s: ClientHello incompleto: %v", file, a.Err())
		}
		checkFromRaw(t, file, ja4.Compute(a.ClientHello(), ja4.QUIC))
		total++
	}
	if total < 150 || resumed == 0 {
		t.Fatalf("só %d ClientHellos conferidos (%d com stable diferente do JA4)", total, resumed)
	}
	t.Logf("%d ClientHellos conferidos, %d com stable diferente do JA4", total, resumed)
}

func TestFromRawEdges(t *testing.T) {
	// exemplo da especificação JA4 da FoxIO: 0015 e 0023 saem do stable (16 → 14 extensões)
	spec := "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" +
		"0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
	j, st, ok := ja4.FromRaw(spec)
	if !ok || j != "t13d1516h2_8daaf6152771_e5627efa2ab1" || st[:11] != "t13d1514h2_" {
		t.Fatalf("exemplo da FoxIO: %s %s %v", j, st, ok)
	}
	for _, raw := range []string{
		"",
		"t13d1516h2",
		"t13d1516h2_002f",
		"t13d1516h2_002f_0005_0403_x",
		"t13d1516h2_002f_0005_",          // separador de assinaturas sem assinaturas
		"t13d15xxh2_002f_0005",           // contagem não numérica
		"x13d1516h2_002f_0005",           // transporte
		"t13d151h2_002f_0005",            // parte a curta
		"t13d1516h2_002F_0005",           // hexadecimal maiúsculo
		"t13d1516h2_002f_005",            // valor de 3 dígitos
		"t13d1599h2_002f_0005",           // teto 99: a contagem real não se recupera
		"t13d1501h2_002f_0015,0023,0029", // contagem negativa no stable
	} {
		if j, st, ok := ja4.FromRaw(raw); ok {
			t.Errorf("FromRaw(%q) = %s %s, quer ok=false", raw, j, st)
		}
	}
	// sem extensões nem assinaturas: o hash vazio é o de Compute
	if j, st, ok := ja4.FromRaw("t12i000000__"); !ok || j != "t12i000000_000000000000_000000000000" || st != j {
		t.Fatalf("vazio: %s %s %v", j, st, ok)
	}
}
