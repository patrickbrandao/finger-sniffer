package tlsparse_test

import (
	"encoding/json"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// hugeHello monta registros TLS com um ClientHello válido de listas longas: ciphers cópias de 0xc02b,
// groups grupos x25519, sigalgs ecdsa_secp256r1_sha256 e exts extensões vazias de tipos distintos.
func hugeHello(ciphers, groups, sigalgs, exts int) []byte {
	u16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }
	var ex []byte
	if groups > 0 {
		ex = u16(ex, 10)
		ex = u16(ex, 2+2*groups)
		ex = u16(ex, 2*groups)
		for range groups {
			ex = u16(ex, 0x001d)
		}
	}
	if sigalgs > 0 {
		ex = u16(ex, 13)
		ex = u16(ex, 2+2*sigalgs)
		ex = u16(ex, 2*sigalgs)
		for range sigalgs {
			ex = u16(ex, 0x0403)
		}
	}
	for i := range exts {
		ex = u16(ex, 0x1000+i)
		ex = u16(ex, 0)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = u16(body, 2*ciphers)
	for range ciphers {
		body = u16(body, 0xc02b)
	}
	body = append(body, 1, 0)
	body = u16(body, len(ex))
	body = append(body, ex...)
	n := len(body)
	msg := append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	var out []byte
	for len(msg) > 0 {
		k := min(16384, len(msg))
		out = append(out, 0x16, 0x03, 0x01, byte(k>>8), byte(k))
		out = append(out, msg[:k]...)
		msg = msg[k:]
	}
	return out
}

func encodeJSON(t *testing.T) func(*tlsparse.Info) []byte {
	return func(i *tlsparse.Info) []byte {
		b, err := json.Marshal(i)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

func TestFitHugeClientHello(t *testing.T) {
	const limit = 900 << 10
	cases := map[string][]byte{
		"ciphers-15000": hugeHello(15000, 0, 0, 0),
		"ciphers-32000": hugeHello(32000, 0, 0, 0),
		"empty-exts":    hugeHello(1, 0, 0, 16000),
		"groups-sigs":   hugeHello(1, 16000, 16000, 0),
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			ch, err := tlsparse.Parse(rec)
			if err != nil {
				t.Fatal(err)
			}
			in := tlsparse.NewInfo(ch, rec, 0)
			ja3.Fill(in, ch)
			ja4.Fill(in, ch, ja4.TCP)
			md5, j4, j4s := in.JA3MD5, in.JA4, in.JA4Stable
			full := len(encodeJSON(t)(in))
			data := in.Fit(encodeJSON(t), limit)
			if len(data) > limit {
				t.Fatalf("%d bytes > %d", len(data), limit)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			// Só marca o corte quando o evento inteiro não cabia.
			if (full > limit) != (got["lists_truncated"] == true) {
				t.Fatalf("lists_truncated=%v com %d bytes inteiros", got["lists_truncated"], full)
			}
			// Os hashes vêm do ClientHello completo, antes do corte.
			if got["ja3_md5"] != md5 || got["ja4"] != j4 || got["ja4_stable"] != j4s || md5 == "" || j4 == "" {
				t.Fatalf("fingerprints mudaram: %v %v", got["ja3_md5"], got["ja4"])
			}
			for _, k := range []string{"cipher_suites", "extensions", "supported_groups", "signature_algorithms", "alpn", "key_share"} {
				if _, ok := got[k].([]any); !ok {
					t.Fatalf("%s não é lista: %v", k, got[k])
				}
			}
		})
	}
}

// O caso de 15.000 cifras de nome conhecido passa do teto inteiro (critério da task 165).
func TestFitCiphers15000Truncates(t *testing.T) {
	rec := hugeHello(15000, 0, 0, 0)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := tlsparse.NewInfo(ch, rec, 0)
	ja3.Fill(in, ch)
	ja4.Fill(in, ch, ja4.TCP)
	if full := len(encodeJSON(t)(in)); full <= 900<<10 {
		t.Fatalf("caso de teste pequeno demais: %d bytes", full)
	}
	in.Fit(encodeJSON(t), 900<<10)
	if !in.ListsTruncated || len(in.CipherSuites) == 0 || len(in.CipherSuites) >= 15000 {
		t.Fatalf("truncated=%v ciphers=%d", in.ListsTruncated, len(in.CipherSuites))
	}
}

func TestFitSmallUnchanged(t *testing.T) {
	rec := hugeHello(16, 4, 4, 4)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := tlsparse.NewInfo(ch, rec, 0)
	ja3.Fill(in, ch)
	want := encodeJSON(t)(in)
	calls := 0
	got := in.Fit(func(i *tlsparse.Info) []byte {
		calls++
		return encodeJSON(t)(i)
	}, 900<<10)
	if string(got) != string(want) || calls != 1 || in.ListsTruncated {
		t.Fatalf("ClientHello pequeno mudou (calls=%d)", calls)
	}
}

func TestFitEncodeError(t *testing.T) {
	rec := hugeHello(16, 0, 0, 0)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := tlsparse.NewInfo(ch, rec, 0)
	if got := in.Fit(func(*tlsparse.Info) []byte { return nil }, 10); got != nil {
		t.Fatal("encode nil deveria devolver nil")
	}
}

// Teto muito baixo: as listas zeram, o inline encolhe e o laço termina.
func TestFitTinyLimit(t *testing.T) {
	rec := hugeHello(32000, 0, 0, 0)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	in := tlsparse.NewInfo(ch, rec, 0)
	ja3.Fill(in, ch)
	data := in.Fit(encodeJSON(t), 2048)
	if len(data) > 2048 || !in.ClientHelloTruncated || len(in.CipherSuites) != 0 {
		t.Fatalf("%d bytes, truncated=%v, ciphers=%d", len(data), in.ClientHelloTruncated, len(in.CipherSuites))
	}
}
