// Package ja4 calcula o JA4 do ClientHello: JA4, JA4_r, JA4_o (e JA4_ro) e o JA4 stable (spec 008 RF-03).
//
// JA4 (só o fingerprint do cliente TLS) é da FoxIO sob BSD 3-Clause (LICENSE-FoxIO-BSD3 neste diretório);
// os demais métodos JA4+ ficam em pkg/fingerprint/ja4plus (FoxIO License 1.1, ADR 0010). A estrutura vem do
// fingerproxy (Apache-2.0); o comportamento segue a ferramenta oficial `ja4` (Rust, 0.18.6), conferida nos
// pcaps de pkg/fingerprint/internal/pcaptest/testdata/tls:
//
//   - versão: maior valor não GREASE do supported_versions, se a extensão existir; senão o legacy_version;
//   - contagens de cifras e extensões sem GREASE, com teto 99 (SNI e ALPN contam);
//   - ALPN: primeiro e último caractere do primeiro protocolo do ALPN, como o tshark exibe a string; um
//     caractere fora do ASCII vira '9'; sem ALPN ou protocolo vazio, "00";
//   - algoritmos de assinatura só da primeira extensão signature_algorithms, sem GREASE e na ordem recebida;
//   - lista vazia vira "000000000000" no lugar do hash.
//
// JA4 stable (do fingerproxy) é o JA4 ordenado sem as extensões que mudam entre a conexão nova e a
// retomada (padding, session_ticket e pre_shared_key), fora da contagem e da lista.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/patrickbrandao/finger-sniffer/pkg/iana"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Transport é o primeiro caractere do JA4.
type Transport byte

// Transportes.
const (
	// TCP: TLS sobre TCP.
	TCP Transport = 't'
	// QUIC: ClientHello do QUIC Initial (spec 011).
	QUIC Transport = 'q'
	// DTLS: TLS sobre datagrama.
	DTLS Transport = 'd'
)

// Fingerprint reúne as variantes do JA4.
type Fingerprint struct {
	// JA4 ordenado e com hashes.
	JA4 string
	// JA4R: ordenado, sem hash (JA4_r).
	JA4R string
	// JA4O: ordem original, com hashes (JA4_o).
	JA4O string
	// JA4RO: ordem original, sem hash (JA4_ro).
	JA4RO string
	// Stable: JA4 sem extensões dependentes de estado.
	Stable string
}

const (
	extSNI                 uint16 = 0x0000
	extALPN                uint16 = 0x0010
	extSignatureAlgorithms uint16 = 0x000d
	extPadding             uint16 = 0x0015
	extSessionTicket       uint16 = 0x0023
	extPreSharedKey        uint16 = 0x0029
	extSupportedVersions   uint16 = 0x002b
)

// Compute calcula as variantes do JA4 para o transporte dado.
func Compute(ch *tlsparse.ClientHello, t Transport) Fingerprint {
	var ciphers []uint16
	for _, c := range ch.CipherSuites {
		if !iana.IsGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	var exts []uint16
	for _, e := range ch.Extensions {
		if !iana.IsGREASE(e.Type) {
			exts = append(exts, e.Type)
		}
	}
	head := func(nExts int) string {
		sni := 'i'
		if slices.Contains(exts, extSNI) {
			sni = 'd'
		}
		return fmt.Sprintf("%c%s%c%02d%02d%s", t, version(ch, exts), sni, min(len(ciphers), 99), min(nExts, 99),
			alpn(ch))
	}
	sigs := hexList(signatureAlgorithms(ch))

	sortedCiphers := slices.Clone(ciphers)
	slices.Sort(sortedCiphers)
	var sortedExts, stableExts []uint16
	for _, e := range exts {
		if e == extSNI || e == extALPN {
			continue
		}
		sortedExts = append(sortedExts, e)
		if !ephemeral(e) {
			stableExts = append(stableExts, e)
		}
	}
	slices.Sort(sortedExts)
	slices.Sort(stableExts)
	nStable := 0
	for _, e := range exts {
		if !ephemeral(e) {
			nStable++
		}
	}

	var f Fingerprint
	a := head(len(exts))
	f.JA4, f.JA4R = assemble(a, hexList(sortedCiphers), hexList(sortedExts), sigs)
	f.JA4O, f.JA4RO = assemble(a, hexList(ciphers), hexList(exts), sigs)
	f.Stable, _ = assemble(head(nStable), hexList(sortedCiphers), hexList(stableExts), sigs)
	return f
}

// Fill preenche os campos ja4* do Info.
func Fill(info *tlsparse.Info, ch *tlsparse.ClientHello, t Transport) {
	f := Compute(ch, t)
	info.JA4, info.JA4R, info.JA4O, info.JA4Stable = f.JA4, f.JA4R, f.JA4O, f.Stable
}

// assemble monta o fingerprint com hashes e o cru: a_b_c, com c = extensões[_assinaturas].
func assemble(a, ciphers, exts, sigs string) (hashed, raw string) {
	c := exts
	if sigs != "" {
		c += "_" + sigs
	}
	return a + "_" + hash12(ciphers) + "_" + hash12(c), a + "_" + ciphers + "_" + c
}

func ephemeral(e uint16) bool {
	return e == extPadding || e == extSessionTicket || e == extPreSharedKey
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func hexList(vs []uint16) string {
	var b strings.Builder
	for i, v := range vs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", v)
	}
	return b.String()
}

func version(ch *tlsparse.ClientHello, exts []uint16) string {
	v := ch.HandshakeVersion
	if slices.Contains(exts, extSupportedVersions) {
		v = 0
		for _, sv := range ch.SupportedVersions {
			if !iana.IsGREASE(sv) && sv > v {
				v = sv
			}
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// alpn devolve o primeiro e o último caractere do primeiro protocolo do ALPN. Os bytes são lidos como o
// tshark exibe a string: UTF-8 válido vira o caractere, cada byte inválido vira um caractere de troca; o
// ja4 oficial troca qualquer caractere fora do ASCII por '9'.
func alpn(ch *tlsparse.ClientHello) string {
	if len(ch.ALPN) == 0 || ch.ALPN[0] == "" {
		return "00"
	}
	s := ch.ALPN[0]
	first, n := utf8.DecodeRuneInString(s)
	last, m := utf8.DecodeLastRuneInString(s)
	if n == len(s) || m == len(s) {
		// um só caractere: vale como primeiro e último
		last = first
	}
	return string([]rune{ascii9(first), ascii9(last)})
}

func ascii9(r rune) rune {
	if r >= utf8.RuneSelf {
		return '9'
	}
	return r
}

// signatureAlgorithms lê a primeira extensão signature_algorithms, sem GREASE.
func signatureAlgorithms(ch *tlsparse.ClientHello) []uint16 {
	for _, e := range ch.Extensions {
		if e.Type != extSignatureAlgorithms {
			continue
		}
		d := e.Data
		if len(d) < 2 {
			return nil
		}
		n := int(d[0])<<8 | int(d[1])
		d = d[2:]
		if n < len(d) {
			d = d[:n]
		}
		var out []uint16
		for i := 0; i+1 < len(d); i += 2 {
			v := uint16(d[i])<<8 | uint16(d[i+1])
			if !iana.IsGREASE(v) {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}
