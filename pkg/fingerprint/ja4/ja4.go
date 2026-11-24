// Package ja4 calcula o JA4 do ClientHello: JA4, JA4_r, JA4_o (e JA4_ro) e o JA4 stable (spec 008 RF-03).
//
// JA4 (só o fingerprint do cliente TLS) é da FoxIO sob BSD 3-Clause (LICENSE-FoxIO-BSD3 neste diretório);
// os demais métodos JA4+ ficam em pkg/fingerprint/ja4plus (FoxIO License 1.1, ADR 0010). A estrutura vem do
// fingerproxy (Apache-2.0); o comportamento segue a ferramenta oficial `ja4` (Rust, 0.18.6), conferida nos
// pcaps de pkg/fingerprint/internal/pcaptest/testdata/tls, exceto no trecho ALPN, que segue a definição publicada
// (technical_details/JA4.md da FoxIO, igual ao tshark 4.4; spec 008 RF-03):
//
//   - versão: maior valor não GREASE do supported_versions, se a extensão existir; senão o legacy_version;
//   - contagens de cifras e extensões sem GREASE, com teto 99 (SNI e ALPN contam);
//   - ALPN: primeiro e último byte do primeiro protocolo do ALPN; se algum dos dois não for [0-9A-Za-z], o
//     primeiro e o último caractere do hex minúsculo do protocolo; sem ALPN ou protocolo vazio, "00". Aqui o
//     `ja4` 0.18.6 diverge da definição: troca só o byte não ASCII por '9' e deixa o ASCII cru;
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

// FromRaw recalcula o JA4 e o JA4 stable a partir do JA4_r (`a_cifras_extensões[_assinaturas]`, cifras e
// extensões já ordenadas, sem GREASE e as extensões sem SNI e ALPN), com as mesmas regras de Compute (ADR 0072
// item 1.2). O stable tira padding, session_ticket e pre_shared_key da lista e desconta da contagem de extensões
// da parte a quantas tirou. ok=false quando o texto não tem o formato, quando a contagem de extensões é 99 (o
// teto: a contagem real não se recupera) ou quando a contagem ficaria negativa.
func FromRaw(raw string) (ja4, stable string, ok bool) {
	parts := strings.Split(raw, "_")
	if len(parts) != 3 && len(parts) != 4 {
		return "", "", false
	}
	a, ciphers, exts := parts[0], parts[1], parts[2]
	sigs := ""
	if len(parts) == 4 {
		sigs = parts[3]
		if sigs == "" {
			// assemble só põe o separador das assinaturas quando há assinaturas
			return "", "", false
		}
	}
	if !rawHead(a) || !rawList(ciphers) || !rawList(exts) || !rawList(sigs) {
		return "", "", false
	}
	nExts := int(a[6]-'0')*10 + int(a[7]-'0')
	if nExts == 99 {
		return "", "", false
	}
	var kept []string
	removed := 0
	if exts != "" {
		for _, e := range strings.Split(exts, ",") {
			switch e {
			case "0015", "0023", "0029":
				removed++
			default:
				kept = append(kept, e)
			}
		}
	}
	nStable := nExts - removed
	if nStable < 0 {
		return "", "", false
	}
	ja4, _ = assemble(a, ciphers, exts, sigs)
	stable, _ = assemble(fmt.Sprintf("%s%02d%s", a[:6], nStable, a[8:]), ciphers, strings.Join(kept, ","), sigs)
	return ja4, stable, true
}

// rawHead confere a parte a do JA4 (transporte, versão, SNI, duas contagens de dois dígitos e o ALPN).
func rawHead(a string) bool {
	if len(a) != 10 || (a[0] != byte(TCP) && a[0] != byte(QUIC) && a[0] != byte(DTLS)) || (a[3] != 'd' && a[3] != 'i') {
		return false
	}
	for i := 4; i < 8; i++ {
		if a[i] < '0' || a[i] > '9' {
			return false
		}
	}
	return true
}

// rawList confere uma lista do JA4_r: vazia ou valores de 4 dígitos hexadecimais minúsculos separados por vírgula.
func rawList(s string) bool {
	if s == "" {
		return true
	}
	for _, v := range strings.Split(s, ",") {
		if len(v) != 4 {
			return false
		}
		for i := range 4 {
			c := v[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
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

// alpn devolve o trecho ALPN da parte a pela definição publicada da FoxIO (spec 008 RF-03): primeiro e último
// byte do primeiro protocolo do ALPN; se algum dos dois não for [0-9A-Za-z], o primeiro e o último caractere do
// hex minúsculo dos bytes do protocolo; sem ALPN ou protocolo vazio, "00".
func alpn(ch *tlsparse.ClientHello) string {
	if len(ch.ALPN) == 0 || ch.ALPN[0] == "" {
		return "00"
	}
	s := ch.ALPN[0]
	first, last := s[0], s[len(s)-1]
	if alnum(first) && alnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(s))
	return string([]byte{h[0], h[len(h)-1]})
}

func alnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
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
