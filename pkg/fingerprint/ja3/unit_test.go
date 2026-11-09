package ja3

import (
	"slices"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

func TestJA3AndJA3N(t *testing.T) {
	ch := &tlsparse.ClientHello{
		HandshakeVersion: 0x0303,
		CipherSuites:     []uint16{0x0a0a, 0x1301, 0xc02b},
		Extensions: []tlsparse.Extension{
			{Type: 0x1a1a}, {Type: 0x002b}, {Type: 0x0000}, {Type: 0x000a}, {Type: 0x000b}, {Type: 0xfafa},
		},
		SupportedGroups: []uint16{0x2a2a, 0x001d, 0x0017},
		ECPointFormats:  []uint8{0, 1},
	}
	f := Compute(ch)
	if f.JA3 != "771,4865-49195,43-0-10-11,29-23,0-1" {
		t.Fatalf("JA3 = %s", f.JA3)
	}
	if f.JA3N != "771,4865-49195,0-10-11-43,29-23,0-1" {
		t.Fatalf("JA3N = %s", f.JA3N)
	}
	if len(f.JA3MD5) != 32 || f.JA3MD5 == f.JA3NMD5 {
		t.Fatalf("MD5: %s %s", f.JA3MD5, f.JA3NMD5)
	}
	// permutar as extensões muda o JA3 e não o JA3N
	p := *ch
	p.Extensions = slices.Clone(ch.Extensions)
	slices.Reverse(p.Extensions)
	g := Compute(&p)
	if g.JA3 == f.JA3 || g.JA3N != f.JA3N || g.JA3NMD5 != f.JA3NMD5 {
		t.Fatalf("permutação: %s / %s", g.JA3, g.JA3N)
	}
	info := &tlsparse.Info{}
	Fill(info, ch)
	if info.JA3 != f.JA3 || info.JA3MD5 != f.JA3MD5 || info.JA3N != f.JA3N || info.JA3NMD5 != f.JA3NMD5 {
		t.Fatal("Fill")
	}
	// ClientHello sem extensões (TLS 1.0 antigo): campos vazios
	empty := Compute(&tlsparse.ClientHello{HandshakeVersion: 0x0301, CipherSuites: []uint16{4, 5}})
	if empty.JA3 != "769,4-5,,," || empty.JA3MD5 != "1d70598d8ccdfcb836bfeb091ab8e469" {
		t.Fatalf("sem extensões: %s %s", empty.JA3, empty.JA3MD5)
	}
}

func FuzzCompute(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, _ := tlsparse.Parse(data)
		if fp := Compute(ch); len(fp.JA3MD5) != 32 || len(fp.JA3NMD5) != 32 {
			t.Fatal(fp)
		}
	})
}
