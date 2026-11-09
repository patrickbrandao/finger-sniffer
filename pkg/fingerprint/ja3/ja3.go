// Package ja3 calcula o JA3 e o JA3N do ClientHello (spec 008 RF-03).
//
// JA3 é da Salesforce (BSD 3-Clause, https://github.com/salesforce/ja3); a montagem segue a do fingerproxy
// (Apache-2.0), portada para o tlsparse.ClientHello. Créditos em NOTICE.
//
// Texto JA3: "versão,cifras,extensões,grupos,formatos de ponto", cada lista em decimal separada por "-",
// GREASE removido de cifras, extensões e grupos. A versão é o legacy_version do ClientHello. O JA3N
// (JA3 normalizado) é o mesmo texto com as extensões em ordem crescente, imune à permutação de extensões
// dos navegadores atuais. Os dois MD5 vêm em hexadecimal minúsculo.
package ja3

import (
	"crypto/md5" //nolint:gosec // MD5 faz parte da definição do JA3
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/patrickbrandao/finger-sniffer/pkg/iana"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Fingerprint reúne o JA3 e o JA3N, em texto e MD5.
type Fingerprint struct {
	JA3     string
	JA3MD5  string
	JA3N    string
	JA3NMD5 string
}

// Compute calcula o JA3 e o JA3N do ClientHello.
func Compute(ch *tlsparse.ClientHello) Fingerprint {
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if !iana.IsGREASE(e.Type) {
			exts = append(exts, e.Type)
		}
	}
	var f Fingerprint
	f.JA3 = build(ch, exts)
	sorted := slices.Clone(exts)
	slices.Sort(sorted)
	f.JA3N = build(ch, sorted)
	f.JA3MD5 = digest(f.JA3)
	f.JA3NMD5 = digest(f.JA3N)
	return f
}

// Fill preenche os campos ja3* do Info.
func Fill(info *tlsparse.Info, ch *tlsparse.ClientHello) {
	f := Compute(ch)
	info.JA3, info.JA3MD5, info.JA3N, info.JA3NMD5 = f.JA3, f.JA3MD5, f.JA3N, f.JA3NMD5
}

func build(ch *tlsparse.ClientHello, exts []uint16) string {
	b := make([]byte, 0, 256)
	b = strconv.AppendUint(b, uint64(ch.HandshakeVersion), 10)
	b = append(b, ',')
	b = appendList(b, ch.CipherSuites, true)
	b = append(b, ',')
	b = appendList(b, exts, false)
	b = append(b, ',')
	b = appendList(b, ch.SupportedGroups, true)
	b = append(b, ',')
	for i, p := range ch.ECPointFormats {
		if i > 0 {
			b = append(b, '-')
		}
		b = strconv.AppendUint(b, uint64(p), 10)
	}
	return string(b)
}

func appendList(b []byte, vs []uint16, skipGREASE bool) []byte {
	first := true
	for _, v := range vs {
		if skipGREASE && iana.IsGREASE(v) {
			continue
		}
		if !first {
			b = append(b, '-')
		}
		first = false
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	return b
}

func digest(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // MD5 faz parte da definição do JA3
	return hex.EncodeToString(sum[:])
}
