package quicparse

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestCryptoStreamFragmentCap: no máximo MaxCryptoFragments pendentes; o seguinte vira ErrCryptoTooLarge
// e o Add seguinte não faz nada (task 144).
func TestCryptoStreamFragmentCap(t *testing.T) {
	var c CryptoStream
	for i := range MaxCryptoFragments {
		c.Add(uint64(10+2*i), []byte{byte(i)})
	}
	if c.Err() != nil || len(c.frags) != MaxCryptoFragments || c.stored != MaxCryptoFragments {
		t.Fatalf("dentro do teto: err=%v frags=%d stored=%d", c.Err(), len(c.frags), c.stored)
	}
	c.Add(5, []byte{1})
	if !errors.Is(c.Err(), ErrCryptoTooLarge) || len(c.frags) != MaxCryptoFragments {
		t.Fatalf("acima do teto: err=%v frags=%d", c.Err(), len(c.frags))
	}
	c.Add(0, []byte("abc"))
	if len(c.Prefix()) != 0 {
		t.Fatal("Add depois do erro")
	}
}

// TestCryptoStreamDuplicates: duplicata exata (ou parte) de um pendente não consome o teto nem os bytes;
// fora de ordem dentro do teto remonta o prefixo certo e devolve os bytes guardados.
func TestCryptoStreamDuplicates(t *testing.T) {
	var c CryptoStream
	for range 1000 {
		c.Add(5, []byte("fgh"))
		c.Add(5, []byte("fg"))
	}
	if c.Err() != nil || len(c.frags) != 1 || c.stored != 3 {
		t.Fatalf("duplicatas: err=%v frags=%d stored=%d", c.Err(), len(c.frags), c.stored)
	}
	c.Add(5, []byte("XYZW")) // mesmo offset, maior: guarda, mas os bytes do primeiro valem
	c.Add(10, []byte("k"))
	c.Add(8, []byte("ij"))
	c.Add(0, []byte("abcde"))
	if got := string(c.Prefix()); got != "abcdefghWjk" {
		t.Fatalf("prefixo %q", got)
	}
	if len(c.frags) != 0 || c.stored != 0 || c.Err() != nil {
		t.Fatalf("depois de fundir: frags=%d stored=%d err=%v", len(c.frags), c.stored, c.Err())
	}

	// embaralhado: cada byte em um frame, ordem invertida, mais repetições
	want := bytes.Repeat([]byte("0123456789"), 6)
	var d CryptoStream
	for i := len(want) - 1; i >= 0; i-- {
		d.Add(uint64(i), want[i:i+1])
		d.Add(uint64(i), want[i:i+1])
	}
	if !bytes.Equal(d.Prefix(), want) || d.Err() != nil || len(d.frags) != 0 {
		t.Fatalf("embaralhado: %q err=%v", d.Prefix(), d.Err())
	}
}

// TestAssemblerCryptoFragmentFlood: um Initial cheio de frames CRYPTO de 1 byte que nunca encaixam termina
// a análise no mesmo datagrama com ErrCryptoTooLarge, em tempo linear (task 144).
func TestAssemblerCryptoFragmentFlood(t *testing.T) {
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)
	dg := floodInitial(t, k, dcid, 0)
	a := NewAssembler(Options{})
	if !a.Add(dg) || a.Complete() || !errors.Is(a.Err(), ErrCryptoTooLarge) || a.Datagrams() != 1 {
		t.Fatalf("done=%v err=%v datagramas=%d", a.Done(), a.Err(), a.Datagrams())
	}
	if n := len(a.crypto.frags); n > MaxCryptoFragments {
		t.Fatalf("%d fragmentos", n)
	}

	// 10.000 frames de 1 byte fora de ordem num CryptoStream: custo linear (bem abaixo de 1 s)
	start := time.Now()
	var c CryptoStream
	for i := range 10000 {
		c.Add(uint64(10000-i), []byte{1})
	}
	if !errors.Is(c.Err(), ErrCryptoTooLarge) || len(c.frags) != MaxCryptoFragments {
		t.Fatalf("err=%v frags=%d", c.Err(), len(c.frags))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("10.000 frames em %v", d)
	}
}

// floodInitial monta um Initial de ~1200 bytes só com frames CRYPTO de 1 byte em offsets > 0 (4 bytes
// cada, offsets distintos).
func floodInitial(t testing.TB, k *InitialKeys, dcid []byte, pn uint64) []byte {
	t.Helper()
	var f []byte
	for i := 0; len(f) < 1150; i++ {
		f = append(f, cryptoFrame(5+i%250, []byte{byte(i)})...)
	}
	return buildInitial(t, k, Version1, dcid, nil, nil, pn, f, len(f))
}

// BenchmarkCryptoStreamPendingFragments: 2.800 frames de 1 byte que nunca encostam no offset 0 (o pior
// caso de 8 datagramas de 1452 bytes); depois do teto cada Add custa O(1).
func BenchmarkCryptoStreamPendingFragments(b *testing.B) {
	data := []byte{0}
	for b.Loop() {
		var c CryptoStream
		for i := range 2800 {
			c.Add(uint64(5+i), data)
			c.Add(5, data)
		}
	}
}

// BenchmarkAssemblerCryptoFlood: 8 datagramas cheios de frames CRYPTO de 1 byte em offset > 0.
func BenchmarkAssemblerCryptoFlood(b *testing.B) {
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)
	dgs := make([][]byte, 8)
	for i := range dgs {
		dgs[i] = floodInitial(b, k, dcid, uint64(i))
	}
	for b.Loop() {
		a := NewAssembler(Options{})
		for _, d := range dgs {
			if a.Add(d) {
				break
			}
		}
	}
}

// FuzzCryptoStream: frames tirados de um mesmo fluxo (offsets e tamanhos do fuzzer, fora de ordem,
// duplicados e sobrepostos) nunca passam dos tetos e o prefixo é sempre um prefixo do fluxo.
func FuzzCryptoStream(f *testing.F) {
	f.Add([]byte{5, 3, 0, 5, 5, 3, 2, 4})
	f.Add([]byte{200, 1, 100, 1, 0, 255})
	src := make([]byte, 4096)
	for i := range src {
		src[i] = byte(i * 7)
	}
	f.Fuzz(func(t *testing.T, ops []byte) {
		var c CryptoStream
		for i := 0; i+1 < len(ops); i += 2 {
			off := int(ops[i]) * 8
			n := min(int(ops[i+1]), len(src)-off)
			c.Add(uint64(off), src[off:off+n])
			if len(c.frags) > MaxCryptoFragments || c.stored < 0 || c.stored > 2*MaxCryptoLen {
				t.Fatalf("tetos: %d frags, %d bytes", len(c.frags), c.stored)
			}
			sum := 0
			for j, fr := range c.frags {
				sum += len(fr.data)
				if fr.off <= uint64(len(c.prefix)) || (j > 0 && fr.off < c.frags[j-1].off) {
					t.Fatalf("pendente %d fora de ordem ou encostado no prefixo", j)
				}
			}
			if sum != c.stored {
				t.Fatalf("stored %d, soma %d", c.stored, sum)
			}
			if !bytes.Equal(c.prefix, src[:len(c.prefix)]) {
				t.Fatal("prefixo diverge do fluxo")
			}
		}
	})
}
