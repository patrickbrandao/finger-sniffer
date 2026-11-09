// Package akamai calcula o fingerprint HTTP/2 da Akamai (Shuster e Gazit, Black Hat EU 2017) no formato
// `S[;]|WU|P[,]|PS[,]` usado pelo fingerproxy, pelo tls.peet.ws e pela scrapfly:
//
//   - S: pares `id:valor` do primeiro SETTINGS do cliente, na ordem recebida (ids repetidos inclusive),
//     separados por `;`;
//   - WU: incremento do WINDOW_UPDATE do stream 0 antes do primeiro HEADERS, ou `00` se não houve;
//   - P: frames PRIORITY antes do primeiro HEADERS como `stream:exclusivo:dependência:peso` (peso real,
//     1..256), separados por `,`, ou `0` se não houve;
//   - PS: primeira letra de cada pseudo-cabeçalho do primeiro HEADERS, na ordem, separadas por `,`.
package akamai

import (
	"strconv"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// Input são as partes do fingerprint, para quem não parte de um HTTP2Info.
type Input struct {
	Settings     [][2]uint32
	WindowUpdate *uint32
	Priorities   []h2passive.Priority
	PseudoOrder  []string
}

// FromInfo calcula o fingerprint a partir do resultado do parser passivo do sentido do cliente.
func FromInfo(info *h2passive.HTTP2Info) string {
	if info == nil {
		return ""
	}
	in := Input{Settings: info.Settings, WindowUpdate: info.WindowUpdate}
	n := min(info.PrioritiesBeforeHeaders, len(info.Priorities))
	in.Priorities = info.Priorities[:n]
	for _, s := range info.Streams {
		if s.StreamID == info.FirstHeadersStream {
			in.PseudoOrder = s.PseudoOrder
			break
		}
	}
	return Fingerprint(in)
}

// Fingerprint monta a cadeia `S|WU|P|PS`.
func Fingerprint(in Input) string {
	var b strings.Builder
	for i, s := range in.Settings {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(strconv.FormatUint(uint64(s[0]), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(s[1]), 10))
	}
	b.WriteByte('|')
	if in.WindowUpdate == nil || *in.WindowUpdate == 0 {
		b.WriteString("00")
	} else {
		b.WriteString(strconv.FormatUint(uint64(*in.WindowUpdate), 10))
	}
	b.WriteByte('|')
	if len(in.Priorities) == 0 {
		b.WriteByte('0')
	}
	for i, p := range in.Priorities {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(p.StreamID), 10))
		b.WriteByte(':')
		if p.Exclusive {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(p.DependsOn), 10))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(p.Weight))
	}
	b.WriteByte('|')
	n := 0
	for _, ps := range in.PseudoOrder {
		if len(ps) < 2 || ps[0] != ':' {
			continue
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteByte(ps[1])
		n++
	}
	return b.String()
}
