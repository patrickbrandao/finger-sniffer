package quicparse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func readHex(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// rfcCrypto é o frame CRYPTO do Initial do cliente da RFC 9001 apêndice A.2 (igual na RFC 9369).
var rfcCrypto = unhex("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c" +
	"00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005" +
	"04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74" +
	"d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff" +
	"05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")

// rfcServerPayload é o payload do Initial do servidor da RFC 9001 apêndice A.3 (igual na RFC 9369).
var rfcServerPayload = unhex("02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b" +
	"9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b0002" +
	"0304")

var rfcDCID = unhex("8394c8f03e515708")

// TestRFCClientInitial: o Initial do cliente das RFCs 9001 e 9369 é reproduzido byte a byte pelo Seal com as
// chaves derivadas e aberto de volta pelo Assembler.
func TestRFCClientInitial(t *testing.T) {
	for _, c := range []struct {
		file    string
		version uint32
		header  string
	}{
		{"rfc9001-client-initial.hex", Version1, "c300000001088394c8f03e5157080000449e00000002"},
		{"rfc9369-client-initial.hex", Version2, "d36b3343cf088394c8f03e5157080000449e00000002"},
	} {
		t.Run(c.file, func(t *testing.T) {
			want := readHex(t, c.file)
			k, err := NewInitialKeys(c.version, rfcDCID, false)
			if err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 1162)
			copy(payload, rfcCrypto)
			got := k.Seal(unhex(c.header), 18, 2, payload)
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal difere do pacote da RFC\n got %x\nwant %x", got[:64], want[:64])
			}
			h, err := ParseLongHeader(want)
			if err != nil {
				t.Fatal(err)
			}
			if h.Type != PacketInitial || h.Length != 1182 || h.Size != 1200 || !bytes.Equal(h.DCID, rfcDCID) {
				t.Fatalf("cabeçalho %+v", h)
			}
			o, err := k.Open(want, h, -1)
			if err != nil {
				t.Fatal(err)
			}
			if o.PacketNumber != 2 || o.PNLen != 4 || !bytes.Equal(o.Payload, payload) ||
				!bytes.Equal(o.Header, unhex(c.header)) {
				t.Fatalf("aberto: pn=%d pnlen=%d header=%x", o.PacketNumber, o.PNLen, o.Header)
			}

			a := Analyze([][]byte{want}, Options{})
			if !a.Complete() || a.Err() != nil {
				t.Fatalf("incompleto: %v", a.Err())
			}
			in := a.Info()
			if in.Version != hexVersion(c.version) || in.DCIDHex != "8394c8f03e515708" || in.SCIDHex != "" ||
				in.InitialLength != 1182 || in.InitialPacketNumber != 2 || in.InitialDatagramSize != 1200 ||
				!in.PaddedTo1200 || in.CoalescedPackets != 1 || in.ClientHelloDatagrams != 1 {
				t.Fatalf("info %+v", in)
			}
			if !slices.Equal(in.InitialFrames, []string{"CRYPTO", "PADDING"}) {
				t.Fatalf("frames %v", in.InitialFrames)
			}
			if in.ClientHello.SNI == nil || *in.ClientHello.SNI != "example.com" ||
				!slices.Equal(in.ClientHello.ALPN, []string{"alpn"}) {
				t.Fatalf("ClientHello %+v", in.ClientHello)
			}
			if !strings.HasPrefix(in.ClientHello.JA4, "q13d") {
				t.Fatalf("ja4 %s", in.ClientHello.JA4)
			}
			var ids []uint64
			for _, p := range in.TransportParams {
				ids = append(ids, p.ID)
			}
			if !slices.Equal(ids, []uint64{4, 5, 7, 8, 1, 9, 0x0f, 6}) ||
				in.TransportParams[6].Name != "initial_source_connection_id" ||
				hex.EncodeToString(in.TransportParams[6].Value) != "8394c8f03e515708" {
				t.Fatalf("transport params %+v", in.TransportParams)
			}
			if !bytes.Equal(a.DCID(), rfcDCID) || a.Version() != c.version || a.Datagrams() != 1 {
				t.Fatal("DCID/versão/datagramas")
			}
			// o datagrama de entrada não pode mudar
			if !bytes.Equal(want, readHex(t, c.file)) {
				t.Fatal("o Assembler alterou o datagrama")
			}
		})
	}
}

func hexVersion(v uint32) string {
	return hex.EncodeToString([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// TestRFCServerInitial: o Initial do servidor das RFCs abre com as chaves do servidor.
func TestRFCServerInitial(t *testing.T) {
	for _, c := range []struct {
		file    string
		version uint32
	}{{"rfc9001-server-initial.hex", Version1}, {"rfc9369-server-initial.hex", Version2}} {
		pkt := readHex(t, c.file)
		h, err := ParseLongHeader(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if h.Type != PacketInitial || hex.EncodeToString(h.SCID) != "f067a5502a4262b5" || len(h.DCID) != 0 {
			t.Fatalf("%s: cabeçalho %+v", c.file, h)
		}
		k, _ := NewInitialKeys(c.version, rfcDCID, true)
		o, err := k.Open(pkt, h, -1)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if o.PacketNumber != 1 || o.PNLen != 2 || !bytes.Equal(o.Payload, rfcServerPayload) {
			t.Fatalf("%s: pn=%d payload=%x", c.file, o.PacketNumber, o.Payload)
		}
		frames, err := ParseFrames(o.Payload)
		if err != nil || len(frames) != 2 || frames[0].Name() != "ACK" || frames[1].Name() != "CRYPTO" ||
			frames[0].LargestAcked != 0 {
			t.Fatalf("%s: frames %+v %v", c.file, frames, err)
		}
		// chaves do cliente não abrem o pacote do servidor
		kc, _ := NewInitialKeys(c.version, rfcDCID, false)
		if _, err := kc.Open(pkt, h, -1); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("%s: chave errada abriu: %v", c.file, err)
		}
	}
}

// buildInitial monta um Initial v1 do cliente com os frames dados, completado com PADDING até padTo bytes
// de payload.
func buildInitial(t testing.TB, k *InitialKeys, version uint32, dcid, scid, token []byte, pn uint64, frames []byte,
	padTo int,
) []byte {
	t.Helper()
	payload := append([]byte(nil), frames...)
	for len(payload) < padTo {
		payload = append(payload, 0)
	}
	typeBits := byte(0)
	if version == Version2 {
		typeBits = 1
	}
	hdr := []byte{0xc0 | typeBits<<4 | 0x01} // número do pacote em 2 bytes
	hdr = append(hdr, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = AppendVarint(hdr, uint64(len(token)))
	hdr = append(hdr, token...)
	length := uint64(2 + len(payload) + 16)
	hdr = append(hdr, byte(length>>8)|0x40, byte(length))
	pnOff := len(hdr)
	hdr = append(hdr, byte(pn>>8), byte(pn))
	return k.Seal(hdr, pnOff, pn, payload)
}

func cryptoFrame(off int, data []byte) []byte {
	b := []byte{FrameCrypto}
	b = AppendVarint(b, uint64(off))
	b = AppendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// TestCryptoReassembly: CRYPTO fora de ordem, duplicado, sobreposto e em dois datagramas (como o Chrome com
// ML-KEM) remonta o mesmo ClientHello de um Initial só.
func TestCryptoReassembly(t *testing.T) {
	msg := rfcCrypto[4:] // mensagem ClientHello (sem o cabeçalho do frame CRYPTO)
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)

	single := Analyze([][]byte{buildInitial(t, k, Version1, dcid, nil, nil, 0, cryptoFrame(0, msg), 1162)}, Options{})
	if !single.Complete() {
		t.Fatal(single.Err())
	}

	// datagrama 1: PING, pedaços 100.. e 0..50 (fora de ordem), com duplicata
	var f1 []byte
	f1 = append(f1, FramePing)
	f1 = append(f1, cryptoFrame(100, msg[100:180])...)
	f1 = append(f1, 0, 0, 0)
	f1 = append(f1, cryptoFrame(0, msg[:50])...)
	f1 = append(f1, cryptoFrame(0, msg[:50])...)
	// datagrama 2: sobreposição 40..110, o resto, e ACK
	var f2 []byte
	f2 = append(f2, cryptoFrame(180, msg[180:])...)
	f2 = append(f2, cryptoFrame(40, msg[40:110])...)
	f2 = append(f2, FrameACK, 0, 0, 0, 0)
	d1 := buildInitial(t, k, Version1, dcid, unhex("aabb"), nil, 0, f1, 1162)
	d2 := buildInitial(t, k, Version1, dcid, unhex("aabb"), nil, 1, f2, 1162)

	a := NewAssembler(Options{})
	if a.Add(d1) {
		t.Fatal("terminou com o primeiro datagrama")
	}
	if a.Complete() {
		t.Fatal("completo cedo")
	}
	if !a.Add(d2) || !a.Complete() || a.Err() != nil {
		t.Fatalf("não completou: %v", a.Err())
	}
	if !bytes.Equal(a.ClientHello().Raw, single.ClientHello().Raw) {
		t.Fatal("ClientHello remontado difere")
	}
	in := a.Info()
	if in.ClientHelloDatagrams != 2 || in.InitialPacketNumber != 0 || in.SCIDHex != "aabb" {
		t.Fatalf("info %+v", in)
	}
	want := []string{"PING", "CRYPTO", "PADDING", "CRYPTO", "CRYPTO", "PADDING", "CRYPTO", "CRYPTO", "ACK", "PADDING"}
	if !slices.Equal(in.InitialFrames, want) {
		t.Fatalf("frames\n got %v\nwant %v", in.InitialFrames, want)
	}
	if in.ClientHello.JA4 != single.Info().ClientHello.JA4 {
		t.Fatal("ja4 difere")
	}
	// Add depois de terminado não faz nada
	if !a.Add(d1) || a.Datagrams() != 2 {
		t.Fatal("Add depois do fim")
	}
}

// TestCoalescedAndOddDatagrams: Initial + Handshake + 1-RTT no mesmo datagrama; Initial com token;
// retransmissão estragada; datagrama sem Initial no meio.
func TestCoalescedAndOddDatagrams(t *testing.T) {
	msg := rfcCrypto[4:]
	dcid := unhex("0102030405060708090a")
	k, _ := NewInitialKeys(Version1, dcid, false)
	ini := buildInitial(t, k, Version1, dcid, nil, unhex("feedbeef"), 0, cryptoFrame(0, msg[:60]), 0)
	// Handshake (tipo 2) com Length 20 e um pacote de cabeçalho curto
	hs := append([]byte{0xe0, 0, 0, 0, 1, 0, 0, 0x14}, make([]byte, 20)...)
	short := append([]byte{0x40}, make([]byte, 30)...)
	d1 := slices.Concat(ini, hs, short)
	bad := buildInitial(t, k, Version1, dcid, nil, nil, 1, cryptoFrame(60, msg[60:]), 1000)
	bad[len(bad)-1] ^= 0xff // etiqueta inválida
	d3 := buildInitial(t, k, Version1, dcid, nil, nil, 2, cryptoFrame(60, msg[60:]), 1000)

	a := NewAssembler(Options{})
	a.Add(d1)
	a.Add(bad)
	if a.Done() || !errors.Is(a.Err(), ErrDecrypt) {
		t.Fatalf("depois do pacote estragado: done=%v err=%v", a.Done(), a.Err())
	}
	a.Add(short) // 1-RTT solto: não conta como Initial
	if !a.Add(d3) || !a.Complete() || a.Err() != nil {
		t.Fatalf("não completou: %v", a.Err())
	}
	in := a.Info()
	if in.CoalescedPackets != 3 || in.TokenLen != 4 || in.TokenHex != "feedbeef" || in.PaddedTo1200 ||
		in.ClientHelloDatagrams != 2 || a.Datagrams() != 4 {
		t.Fatalf("info %+v datagramas %d", in, a.Datagrams())
	}
}

func TestUnknownVersionAndErrors(t *testing.T) {
	// versão desconhecida: só o cabeçalho
	d := []byte{0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 2, 0xaa, 0xbb, 1, 0xcc, 0, 0x40, 0x10}
	d = append(d, make([]byte, 1200)...)
	a := Analyze([][]byte{d}, Options{})
	if !a.Done() || a.Complete() || !errors.Is(a.Err(), ErrUnknownVersion) {
		t.Fatalf("done=%v err=%v", a.Done(), a.Err())
	}
	in := a.Info()
	if in.Version != "1a2a3a4a" || in.DCIDHex != "aabb" || in.SCIDHex != "cc" || in.ClientHello != nil ||
		in.InitialDatagramSize != len(d) {
		t.Fatalf("info %+v", in)
	}
	if _, err := json.Marshal(in); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		d   []byte
		err error
	}{
		"curto":       {[]byte{0x40, 1, 2}, ErrNotLongHeader},
		"vazio-vn":    {[]byte{0xc0, 0, 0}, ErrHeader},
		"handshake":   {append([]byte{0xe0, 0, 0, 0, 1, 0, 0, 1}, 0), ErrNotInitial},
		"length-alto": {[]byte{0xc0, 0, 0, 0, 1, 0, 0, 0, 0x50, 0}, ErrHeader},
		"cid-grande":  {append(append([]byte{0xc0, 0, 0, 0, 1, 21}, make([]byte, 21)...), 0, 0, 0), ErrHeader},
	} {
		a := Analyze([][]byte{c.d}, Options{})
		if !a.Done() || !errors.Is(a.Err(), c.err) {
			t.Errorf("%s: done=%v err=%v", name, a.Done(), a.Err())
		}
	}

	// teto de datagramas sem completar
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)
	a = NewAssembler(Options{MaxDatagrams: 3})
	for i := range 3 {
		a.Add(buildInitial(t, k, Version1, dcid, nil, nil, uint64(i), cryptoFrame(0, rfcCrypto[4:20]), 1162))
	}
	if !a.Done() || a.Complete() || !errors.Is(a.Err(), ErrIncomplete) {
		t.Fatalf("teto: done=%v err=%v", a.Done(), a.Err())
	}

	// CRYPTO acima do teto
	a = Analyze([][]byte{buildInitial(t, k, Version1, dcid, nil, nil, 0, cryptoFrame(MaxCryptoLen, []byte{1}), 100)},
		Options{})
	if !errors.Is(a.Err(), ErrCryptoTooLarge) {
		t.Fatalf("teto do CRYPTO: %v", a.Err())
	}

	// v2 com Initial sintético
	k2, _ := NewInitialKeys(Version2, dcid, false)
	a = Analyze([][]byte{buildInitial(t, k2, Version2, dcid, nil, nil, 0, cryptoFrame(0, rfcCrypto[4:]), 1162)},
		Options{})
	if !a.Complete() || a.Info().Version != "6b3343cf" {
		t.Fatalf("v2: %v", a.Err())
	}
	if _, err := NewInitialKeys(0xbabababa, dcid, false); !errors.Is(err, ErrUnknownVersion) {
		t.Fatal(err)
	}
}

func TestInitialFramesCap(t *testing.T) {
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)
	var f []byte
	for range 300 {
		f = append(f, FramePing)
	}
	f = append(f, cryptoFrame(0, rfcCrypto[4:])...)
	a := Analyze([][]byte{buildInitial(t, k, Version1, dcid, nil, nil, 0, f, 1162)}, Options{})
	in := a.Info()
	if !a.Complete() || len(in.InitialFrames) != MaxInitialFrames || !in.InitialFramesTruncated {
		t.Fatalf("frames=%d truncated=%v err=%v", len(in.InitialFrames), in.InitialFramesTruncated, a.Err())
	}
}

func TestParseFrames(t *testing.T) {
	p := []byte{
		0, 0, FramePing, FrameACKECN, 5, 0, 1, 0, 1, 0, 1, 2, 3, FrameConnectionClose, 0x0a, 0x06, 2, 'h', 'i',
		FrameConnectionCloseApp, 1, 0,
	}
	fs, err := ParseFrames(p)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range fs {
		names = append(names, f.Name())
	}
	if !slices.Equal(names, []string{"PADDING", "PING", "ACK_ECN", "CONNECTION_CLOSE", "CONNECTION_CLOSE_APP"}) ||
		fs[0].PaddingLen != 2 || fs[2].LargestAcked != 5 || fs[3].ErrorCode != 10 || fs[3].FrameType != 6 ||
		string(fs[3].Reason) != "hi" {
		t.Fatalf("%v %+v", names, fs)
	}
	fs, err = ParseFrames([]byte{FramePing, 0x08, 1, 2})
	if !errors.Is(err, ErrFrame) || len(fs) != 2 || fs[1].Name() != "STREAM" {
		t.Fatalf("STREAM no Initial: %+v %v", fs, err)
	}
	fs, err = ParseFrames([]byte{FrameCrypto, 0, 9, 1})
	if !errors.Is(err, ErrFrame) || len(fs) != 1 || fs[0].Name() != "CRYPTO" {
		t.Fatalf("CRYPTO truncado: %+v %v", fs, err)
	}
	if _, err = ParseFrames([]byte{0x40}); !errors.Is(err, ErrFrame) {
		t.Fatal(err)
	}
	if FrameName(0x99) != "0x99" || FrameName(0x30) != "DATAGRAM" {
		t.Fatal(FrameName(0x99))
	}
}

func TestVarintAndPacketNumber(t *testing.T) {
	for _, v := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, MaxVarint, MaxVarint + 5} {
		b := AppendVarint(nil, v)
		got, n, ok := ReadVarint(b)
		if !ok || n != len(b) || got != min(v, MaxVarint) {
			t.Fatalf("%d: %x → %d", v, b, got)
		}
		if _, _, ok := ReadVarint(b[:len(b)-1]); ok {
			t.Fatalf("%d: aceitou varint cortado", v)
		}
	}
	// RFC 9000 seção 16: exemplos
	for hx, want := range map[string]uint64{"c2197c5eff14e88c": 151288809941952652, "9d7f3e7d": 494878333, "7bbd": 15293, "25": 37} {
		if v, _, _ := ReadVarint(unhex(hx)); v != want {
			t.Fatalf("%s = %d", hx, v)
		}
	}
	// RFC 9000 apêndice A.3
	if got := DecodePacketNumber(0xa82f30ea, 0x9b32, 16); got != 0xa82f9b32 {
		t.Fatalf("%x", got)
	}
	if DecodePacketNumber(-1, 0, 8) != 0 || DecodePacketNumber(250, 2, 8) != 258 || DecodePacketNumber(300, 255, 8) != 255 {
		t.Fatal("decodificação do número do pacote")
	}
}

func TestTransportParams(t *testing.T) {
	var b []byte
	for _, p := range [][2]uint64{{0x01, 2}, {27, 0}, {0x3127, 1}, {0x7777777, 1}, {0x2ab2, 0}, {0x0f739bbc1b666d05, 1}} {
		b = AppendVarint(b, p[0])
		b = AppendVarint(b, p[1])
		b = append(b, make([]byte, p[1])...)
	}
	ps, trunc, err := ParseTransportParams(b)
	if err != nil || trunc {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{
		"max_idle_timeout", "GREASE", "google_initial_rtt", "unknown", "grease_quic_bit",
		"enable_multipath",
	}) {
		t.Fatal(names)
	}
	j, _ := json.Marshal(ps[0])
	if string(j) != `[1,"max_idle_timeout","0000"]` {
		t.Fatal(string(j))
	}
	var back TransportParam
	if err := json.Unmarshal(j, &back); err != nil || back.ID != 1 || len(back.Value) != 2 {
		t.Fatal(err, back)
	}
	for _, bad := range []string{`1`, `["x","a","00"]`, `[1,2,"00"]`, `[1,"a",3]`, `[1,"a","zz"]`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Fatalf("aceitou %s", bad)
		}
	}
	if _, _, err := ParseTransportParams(b[:len(b)-1]); !errors.Is(err, ErrTransportParams) {
		t.Fatal(err)
	}
	var many []byte
	for range MaxTransportParams + 3 {
		many = append(many, 0x01, 0)
	}
	ps, trunc, _ = ParseTransportParams(many)
	if !trunc || len(ps) != MaxTransportParams {
		t.Fatal(len(ps), trunc)
	}
	if !IsGREASEParam(31*5+27) || IsGREASEParam(1) {
		t.Fatal("GREASE")
	}
}

func TestCryptoStreamEdges(t *testing.T) {
	var c CryptoStream
	c.Add(5, nil)
	c.Add(2, []byte("cde"))
	if len(c.Prefix()) != 0 {
		t.Fatal("prefixo sem o offset 0")
	}
	c.Add(0, []byte("ab"))
	if string(c.Prefix()) != "abcde" {
		t.Fatal(string(c.Prefix()))
	}
	c.Add(1, []byte("bc")) // já coberto
	c.Add(4, []byte("eXYZ"))
	if string(c.Prefix()) != "abcdeXYZ" || c.Err() != nil {
		t.Fatal(string(c.Prefix()))
	}
	if _, ok := c.HandshakeMessage(); ok {
		t.Fatal("mensagem inteira com tamanho errado")
	}
	var d CryptoStream
	for i := range 2*MaxCryptoLen/1000 + 2 {
		d.Add(uint64(10+i%5), make([]byte, 1000)) // nunca encosta no offset 0
	}
	if !errors.Is(d.Err(), ErrCryptoTooLarge) {
		t.Fatal("teto de bytes guardados")
	}
}
