package quicparse

import (
	"encoding/json"
	"os"
	"testing"
)

func checkInfo(t *testing.T, a *Assembler) {
	t.Helper()
	in := a.Info()
	if len(in.InitialFrames) > MaxInitialFrames {
		t.Fatalf("initial_frames com %d itens", len(in.InitialFrames))
	}
	if a.Datagrams() > DefaultMaxDatagrams {
		t.Fatalf("%d datagramas analisados", a.Datagrams())
	}
	if _, err := json.Marshal(in); err != nil {
		t.Fatal(err)
	}
}

// FuzzAssembler: datagramas arbitrários (o fuzzer corta a entrada em até 3 datagramas) não derrubam o
// Assembler e não alteram a entrada.
func FuzzAssembler(f *testing.F) {
	if b, err := os.ReadFile("testdata/rfc9001-client-initial.hex"); err == nil {
		f.Add(unhexFile(b), uint16(1200), uint16(0))
	}
	if b, err := os.ReadFile("testdata/rfc9369-client-initial.hex"); err == nil {
		f.Add(unhexFile(b), uint16(600), uint16(900))
	}
	f.Add([]byte{0xc0, 0, 0, 0, 1, 1, 2, 0, 0, 0x41, 0x00}, uint16(5), uint16(9))
	f.Fuzz(func(t *testing.T, b []byte, c1, c2 uint16) {
		orig := string(b)
		x := min(int(c1), len(b))
		y := min(max(int(c2), x), len(b))
		a := NewAssembler(Options{})
		for _, d := range [][]byte{b[:x], b[x:y], b[y:]} {
			if len(d) > 0 {
				a.Add(d)
			}
		}
		checkInfo(t, a)
		if string(b) != orig {
			t.Fatal("entrada alterada")
		}
	})
}

// FuzzInitialFrames: frames arbitrários dentro de Initials bem cifrados (para passar do AEAD), em dois
// datagramas.
func FuzzInitialFrames(f *testing.F) {
	f.Add(rfcCrypto, uint16(60))
	f.Add([]byte{FramePing, FrameACK, 1, 0, 1, 0, 0, 1, 0, FrameCrypto, 0, 1, 1}, uint16(3))
	f.Add([]byte{FrameConnectionClose, 1, 0, 0, FrameCrypto, 0x40, 0x10, 4}, uint16(0))
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	k, err := NewInitialKeys(Version1, dcid, false)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, p []byte, cut uint16) {
		if len(p) > 4000 {
			return
		}
		c := min(int(cut), len(p))
		a := NewAssembler(Options{})
		a.Add(buildInitial(t, k, Version1, dcid, nil, nil, 0, p[:c], 20))
		a.Add(buildInitial(t, k, Version1, dcid, nil, nil, 1, p[c:], 20))
		checkInfo(t, a)
	})
}

// FuzzQPACK: blocos arbitrários; os campos lidos têm representação válida e os índices estáticos existem.
func FuzzQPACK(f *testing.F) {
	f.Add(unhex("0000510b2f696e6465782e68746d6c"))
	f.Add(unhex("050080c181"))
	f.Add(unhex("03811011"))
	if b, err := os.ReadFile("testdata/h3-chrome-foxio-headers.hex"); err == nil {
		f.Add(unhexFile(b))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, fs, _ := DecodeFieldSection(b, 64)
		if len(fs) > 64 {
			t.Fatalf("%d campos", len(fs))
		}
		for _, x := range fs {
			switch x.Repr {
			case ReprIndexed, ReprLiteralNameRef:
				if *x.Static {
					if _, _, ok := QPACKStatic(*x.Index); !ok {
						t.Fatalf("índice estático %d", *x.Index)
					}
				}
			case ReprIndexedPostBase, ReprLiteralPostBaseNameRef, ReprLiteral:
			default:
				t.Fatalf("repr %q", x.Repr)
			}
		}
		if _, err := json.Marshal(fs); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzH3Streams: bytes arbitrários em pedaços nos leitores de stream de controle e de requisição.
func FuzzH3Streams(f *testing.F) {
	if b, err := os.ReadFile("testdata/h3-curl-request.hex"); err == nil {
		f.Add(unhexFile(b), uint16(7))
	}
	if b, err := os.ReadFile("testdata/h3-curl-control.hex"); err == nil {
		f.Add(unhexFile(b), uint16(1))
	}
	f.Add([]byte{0x00, 0x04, 0x02, 0x01, 0x00, 0x07, 0x01, 0x08}, uint16(2))
	f.Fuzz(func(t *testing.T, b []byte, cut uint16) {
		c := min(int(cut), len(b))
		r := NewRequestStream(0, 32)
		r.Feed(b[:c])
		r.Feed(b[c:])
		if len(r.Request.Fields) > 32 || len(r.Request.Frames) > MaxStreamFrames || r.Request.BodyLen > int64(len(b)) {
			t.Fatalf("teto violado: %+v", r.Request)
		}
		u := NewUniStream()
		u.Feed(b[:c])
		u.Feed(b[c:])
		if len(u.Settings) > DefaultMaxSettings || len(u.Frames) > MaxStreamFrames || u.Bytes != int64(len(b)) {
			t.Fatalf("teto violado: %+v", u)
		}
		if _, err := json.Marshal(r.Request); err != nil {
			t.Fatal(err)
		}
	})
}

func unhexFile(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return unhex(string(b))
}
