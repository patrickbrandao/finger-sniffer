package quicparse

import (
	"bytes"
	"errors"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// rfcClientHello é a mensagem ClientHello do Initial da RFC 9001 (sem o cabeçalho do frame CRYPTO).
func rfcClientHello() []byte { return append([]byte(nil), rfcCrypto[4:]...) }

// analyzeCH monta Initials com msg em frames CRYPTO de até 1000 bytes (um por datagrama) e analisa.
func analyzeCH(t *testing.T, msg []byte) *Assembler {
	t.Helper()
	dcid := unhex("0011223344556677")
	k, _ := NewInitialKeys(Version1, dcid, false)
	var dgs [][]byte
	for off, pn := 0, uint64(0); off < len(msg); off, pn = off+1000, pn+1 {
		end := min(off+1000, len(msg))
		dgs = append(dgs, buildInitial(t, k, Version1, dcid, nil, nil, pn, cryptoFrame(off, msg[off:end]), 1162))
	}
	return Analyze(dgs, Options{})
}

func checkNoFingerprints(t *testing.T, a *Assembler) {
	t.Helper()
	ch := a.Info().ClientHello
	if ch == nil {
		t.Fatal("sem client_hello")
	}
	if ch.JA3 != "" || ch.JA3MD5 != "" || ch.JA3N != "" || ch.JA4 != "" || ch.JA4R != "" || ch.JA4O != "" ||
		ch.JA4Stable != "" {
		t.Fatalf("fingerprints com erro de parse: ja3=%q ja4=%q", ch.JA3, ch.JA4)
	}
}

// TestAssemblerFingerprintsOnlyWithoutParseError: ClientHello completo pelo tamanho mas com a lista de
// extensões cortada, ou mensagem CRYPTO que não é ClientHello, não gera JA3/JA4 e o erro fica em Err()
// (spec 008 RF-03, task 167); o ClientHello válido continua com JA4 q.
func TestAssemblerFingerprintsOnlyWithoutParseError(t *testing.T) {
	ok := analyzeCH(t, rfcClientHello())
	if !ok.Complete() || ok.Err() != nil || ok.Info().ClientHello.JA4 == "" || ok.Info().ClientHello.JA4[0] != 'q' {
		t.Fatalf("válido: err=%v", ok.Err())
	}

	// comprimento das extensões (offset 47 da mensagem) maior que o que resta
	bad := rfcClientHello()
	bad[47], bad[48] = 0x00, 0xff
	a := analyzeCH(t, bad)
	var pe *tlsparse.ParseError
	if !a.Done() || !errors.As(a.Err(), &pe) {
		t.Fatalf("extensões cortadas: err=%v", a.Err())
	}
	checkNoFingerprints(t, a)

	// mensagem de handshake que não é ClientHello
	other := rfcClientHello()
	other[0] = 0x02
	a = analyzeCH(t, other)
	if !a.Done() || !errors.Is(a.Err(), tlsparse.ErrNotClientHello) {
		t.Fatalf("não ClientHello: err=%v", a.Err())
	}
	checkNoFingerprints(t, a)
}

// withTransportParams troca a extensão quic_transport_parameters (a última do ClientHello da RFC) por tp e
// acerta os comprimentos.
func withTransportParams(t *testing.T, tp []byte) []byte {
	t.Helper()
	msg := rfcClientHello()
	i := bytes.Index(msg, []byte{0x00, 0x39, 0x00, 0x32})
	if i < 0 || i+4+0x32 != len(msg) {
		t.Fatal("extensão 0x39 não é a última")
	}
	out := append(msg[:i:i], 0x00, 0x39, byte(len(tp)>>8), byte(len(tp)))
	out = append(out, tp...)
	ext := len(out) - 49
	out[47], out[48] = byte(ext>>8), byte(ext)
	hs := len(out) - 4
	out[1], out[2], out[3] = byte(hs>>16), byte(hs>>8), byte(hs)
	return out
}

// TestAssemblerTransportParamsTruncated: mais de MaxTransportParams parâmetros → lista no teto e
// transport_params_truncated (task 171); abaixo do teto a marca fica desligada.
func TestAssemblerTransportParamsTruncated(t *testing.T) {
	var tp []byte
	for i := range 2000 {
		tp = append(tp, byte(i%60), 0) // id de 1 byte, valor vazio
	}
	a := analyzeCH(t, withTransportParams(t, tp))
	in := a.Info()
	if !a.Complete() || a.Err() != nil || len(in.TransportParams) != MaxTransportParams || !in.TransportParamsTruncated {
		t.Fatalf("err=%v params=%d truncated=%v", a.Err(), len(in.TransportParams), in.TransportParamsTruncated)
	}
	small := analyzeCH(t, withTransportParams(t, tp[:20]))
	if len(small.Info().TransportParams) != 10 || small.Info().TransportParamsTruncated {
		t.Fatalf("pequeno: %d truncated=%v", len(small.Info().TransportParams), small.Info().TransportParamsTruncated)
	}
}
