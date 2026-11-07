// Package ja4plus implementa métodos da família JA4+ da FoxIO usados pelo finger-sniffer.
//
// Por enquanto só o JA4T (fingerprint TCP do cliente, a partir do SYN). O JA4H entra com o HTTP/1 e o h2.
//
// Licença: os métodos JA4+ (JA4T, JA4H, JA4S, JA4X…) estão sob a FoxIO License 1.1, que restringe o uso
// comercial; o texto está em LICENSE-FoxIO-1.1 neste diretório (ADR 0010). O resto do finger-sniffer é
// Apache-2.0. Por isso este pacote fica isolado e não deve ser importado por código que precise ficar livre
// dessa restrição.
//
// Referência de comportamento: a ferramenta oficial `ja4` (Rust) da FoxIO, que lê os campos do tshark
// (`tcp.window_size_value`, `tcp.option_kind`, `tcp.options.mss_val`, `tcp.options.wscale.shift`). As regras de
// leitura das opções abaixo reproduzem o tshark 4.4, inclusive com opções malformadas, e foram conferidas
// contra o `ja4` nos pcaps de pkg/fingerprint/testdata.
package ja4plus

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// Flags TCP usadas aqui.
const (
	flagSYN = 0x02
	flagACK = 0x10
)

// Tipos de opção TCP com tratamento especial.
const (
	optEOL    = 0
	optNOP    = 1
	optMSS    = 2
	optWScale = 3
)

// Erros devolvidos por JA4T.
var (
	// ErrShortHeader: menos de 20 bytes ou data offset menor que 5.
	ErrShortHeader = errors.New("ja4plus: cabeçalho TCP curto")
	// ErrNotSYN: o segmento não é um SYN inicial (SYN sem ACK).
	ErrNotSYN = errors.New("ja4plus: não é um SYN inicial")
)

// TCPSYN guarda os campos do SYN que compõem o JA4T.
type TCPSYN struct {
	// Window é a janela anunciada, crua (sem escala).
	Window uint16
	// Kinds são os tipos das opções, na ordem em que aparecem.
	Kinds []uint8
	// MSS é o valor da última opção MSS válida; -1 quando não há.
	MSS int
	// WScale é o shift da última opção window scale válida; -1 quando não há.
	WScale int
}

// IsInitialSYN diz se as flags TCP são de um SYN inicial (SYN ligado e ACK desligado; ECE/CWR não importam).
func IsInitialSYN(flags uint8) bool {
	return flags&flagSYN != 0 && flags&flagACK == 0
}

// ParseSYN lê janela e opções de um cabeçalho TCP (a partir da porta de origem, com as opções).
// Não confere as flags: serve também para o SYN-ACK.
func ParseSYN(tcp []byte) (TCPSYN, error) {
	if len(tcp) < 20 {
		return TCPSYN{}, ErrShortHeader
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 {
		return TCPSYN{}, ErrShortHeader
	}
	s := TCPSYN{Window: binary.BigEndian.Uint16(tcp[14:16]), MSS: -1, WScale: -1}
	s.Kinds = parseOptions(tcp, doff, &s)
	return s, nil
}

// parseOptions percorre as opções como o tshark: end é o fim lógico pelo data offset; quando os bytes
// capturados acabam antes, a leitura para no ponto em que o tshark lançaria exceção.
func parseOptions(tcp []byte, end int, s *TCPSYN) []uint8 {
	have := len(tcp)
	var kinds []uint8
	i := 20
	for i < end && i < have {
		k := tcp[i]
		switch k {
		case optEOL:
			// EOL: o tshark lista o EOL e cada byte zero seguinte como mais um EOL, parando no primeiro
			// byte não nulo (que não é lido como opção).
			kinds = append(kinds, optEOL)
			i++
			for i < end && i < have && tcp[i] == 0 {
				kinds = append(kinds, optEOL)
				i++
			}
			return kinds
		case optNOP:
			kinds = append(kinds, optNOP)
			i++
			continue
		}
		// Opções com tamanho: sem byte de tamanho, tamanho < 2 ou passando do fim das opções, o tshark
		// para sem listar a opção.
		if i+1 >= end || i+1 >= have {
			return kinds
		}
		l := int(tcp[i+1])
		if l < 2 || i+l > end {
			return kinds
		}
		kinds = append(kinds, k)
		// Valor só existe com o tamanho exato (4 no MSS, 3 no window scale) e os bytes capturados.
		if i+l > have {
			return kinds
		}
		switch {
		case k == optMSS && l == 4:
			s.MSS = int(binary.BigEndian.Uint16(tcp[i+2 : i+4]))
		case k == optWScale && l == 3:
			s.WScale = int(tcp[i+2])
		}
		i += l
	}
	return kinds
}

// JA4T calcula o fingerprint JA4T de um SYN inicial a partir do cabeçalho TCP com opções.
// Formato: <janela>_<tipos das opções separados por "-">_<mss>_<window scale>, por exemplo
// 64240_2-1-3-1-1-4_1460_8.
func JA4T(tcp []byte) (string, error) {
	if len(tcp) < 20 {
		return "", ErrShortHeader
	}
	if !IsInitialSYN(tcp[13]) {
		return "", ErrNotSYN
	}
	s, err := ParseSYN(tcp)
	if err != nil {
		return "", err
	}
	return s.String(), nil
}

// String formata o JA4T como a ferramenta da FoxIO: sem opções vira "00"; MSS com pelo menos dois dígitos;
// window scale ausente ou zero vira "00".
func (s TCPSYN) String() string {
	var b strings.Builder
	b.Grow(32)
	b.WriteString(strconv.Itoa(int(s.Window)))
	b.WriteByte('_')
	if len(s.Kinds) == 0 {
		b.WriteString("00")
	}
	for i, k := range s.Kinds {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(k)))
	}
	b.WriteByte('_')
	mss := max(s.MSS, 0)
	if mss < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.Itoa(mss))
	b.WriteByte('_')
	if s.WScale <= 0 {
		b.WriteString("00")
	} else {
		b.WriteString(strconv.Itoa(s.WScale))
	}
	return b.String()
}
