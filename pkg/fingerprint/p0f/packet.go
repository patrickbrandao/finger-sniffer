// Package p0f calcula a assinatura TCP no formato do p0f v3 e o palpite de sistema operacional pelo banco
// p0f.fp (spec 013 RF-07).
//
// É uma reimplementação em Go do comportamento do p0f 3.09b (process.c, fp_tcp.c e readfp.c), incluindo as
// esquisitices que mudam a saída — a meta é a mesma assinatura e o mesmo palpite do `p0f -r` sobre o mesmo
// pacote. Nenhum código do p0f foi copiado; o banco p0f.fp (LGPL-2.1) é um arquivo de dados externo, lido em
// tempo de execução (FS_P0F_DB) e não embutido no binário (ADR 0010).
//
// Fluxo: Parse(pacote IP) → Packet; LoadDB/ParseDB → DB; DB.Fingerprint(Packet) → Observation.
package p0f

import (
	"encoding/binary"
	"errors"
)

// Quirks do p0f (mesmos bits de process.h; a ordem dos nomes na assinatura segue a de dump_sig).
const (
	QuirkECN      uint32 = 0x00000001 // ecn
	QuirkDF       uint32 = 0x00000002 // df
	QuirkNZID     uint32 = 0x00000004 // id+
	QuirkZeroID   uint32 = 0x00000008 // id-
	QuirkNZMBZ    uint32 = 0x00000010 // 0+
	QuirkFlow     uint32 = 0x00000020 // flow
	QuirkZeroSeq  uint32 = 0x00001000 // seq-
	QuirkNZAck    uint32 = 0x00002000 // ack+
	QuirkZeroAck  uint32 = 0x00004000 // ack-
	QuirkNZURG    uint32 = 0x00008000 // uptr+
	QuirkURG      uint32 = 0x00010000 // urgf+
	QuirkPush     uint32 = 0x00020000 // pushf+
	QuirkZeroTS1  uint32 = 0x01000000 // ts1-
	QuirkNZTS2    uint32 = 0x02000000 // ts2+
	QuirkOptEOLNZ uint32 = 0x04000000 // opt+
	QuirkOptExWS  uint32 = 0x08000000 // exws
	QuirkOptBad   uint32 = 0x10000000 // bad
)

// quirkNames na ordem em que o p0f escreve a assinatura.
var quirkNames = []struct {
	bit  uint32
	name string
}{
	{QuirkDF, "df"},
	{QuirkNZID, "id+"},
	{QuirkZeroID, "id-"},
	{QuirkECN, "ecn"},
	{QuirkNZMBZ, "0+"},
	{QuirkFlow, "flow"},
	{QuirkZeroSeq, "seq-"},
	{QuirkNZAck, "ack+"},
	{QuirkZeroAck, "ack-"},
	{QuirkNZURG, "uptr+"},
	{QuirkURG, "urgf+"},
	{QuirkPush, "pushf+"},
	{QuirkZeroTS1, "ts1-"},
	{QuirkNZTS2, "ts2+"},
	{QuirkOptEOLNZ, "opt+"},
	{QuirkOptExWS, "exws"},
	{QuirkOptBad, "bad"},
}

// Tipos de opção TCP com nome na assinatura.
const (
	optEOL    = 0
	optNOP    = 1
	optMSS    = 2
	optWScale = 3
	optSACKOK = 4
	optSACK   = 5
	optTS     = 8
)

// Flags TCP.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20
	tcpECE = 0x40
	tcpCWR = 0x80
)

// Limites do p0f (config.h e tcp.h).
const (
	maxTCPOpt  = 24
	maxDist    = 35
	minTCP4    = 40 // IPv4 + TCP sem opções
	minTCP6    = 60 // IPv6 + TCP sem opções
	specialMSS = 1331
	specialWin = 1337
)

// Erros de Parse: o p0f simplesmente ignora esses pacotes.
var (
	ErrShort    = errors.New("p0f: pacote curto ou comprimentos inconsistentes")
	ErrNotTCP   = errors.New("p0f: não é TCP")
	ErrFragment = errors.New("p0f: fragmento IPv4")
	ErrFlags    = errors.New("p0f: combinação de flags TCP sem sentido")
	ErrVersion  = errors.New("p0f: versão de IP desconhecida")
)

// Packet são os campos do pacote que o p0f usa (struct packet_data).
type Packet struct {
	IPVersion uint8 // 4 ou 6
	TTL       uint8
	TOS       uint8 // DSCP (TOS >> 2)
	IPOptLen  uint8
	TotHdr    uint16 // cabeçalho IP + TCP
	Quirks    uint32
	Flags     uint8 // flags TCP completas
	Type      uint8 // flags & (SYN|ACK|FIN|RST)
	Window    uint16
	Seq       uint32
	Layout    []uint8 // tipos das opções na ordem (até 24)
	EOLPad    uint8
	MSS       uint16
	WScale    uint8
	TS1       uint32
	PayLen    int
}

// IsSYN diz se é um SYN inicial (o p0f só fingerprinta SYN e SYN+ACK).
func (p *Packet) IsSYN() bool { return p.Type == tcpSYN }

// IsSYNACK diz se é um SYN+ACK.
func (p *Packet) IsSYNACK() bool { return p.Type == tcpSYN|tcpACK }

// Parse lê um pacote a partir do cabeçalho IP, como parse_packet do p0f. ip são os bytes capturados (podem
// incluir padding do Ethernet depois do pacote; o comprimento declarado no IP manda).
func Parse(ip []byte) (*Packet, error) {
	n := min(len(ip), 65535)
	if n < minTCP4 {
		return nil, ErrShort
	}
	p := &Packet{}
	var tcp []byte
	switch ip[0] >> 4 {
	case 4:
		hl := int(ip[0]&0x0f) * 4
		flagsOff := binary.BigEndian.Uint16(ip[6:8])
		tot := int(binary.BigEndian.Uint16(ip[2:4]))
		n = min(n, tot)
		if n < minTCP4 || hl < 20 || tot > n || hl+20 > n {
			return nil, ErrShort
		}
		if ip[9] != 6 {
			return nil, ErrNotTCP
		}
		if flagsOff&^(0x4000|0x8000) != 0 {
			return nil, ErrFragment
		}
		p.IPVersion = 4
		p.IPOptLen = uint8(hl - 20)
		p.TOS = ip[1] >> 2
		p.TTL = ip[8]
		if ip[1]&0x03 != 0 {
			p.Quirks |= QuirkECN
		}
		if flagsOff&0x8000 != 0 {
			p.Quirks |= QuirkNZMBZ
		}
		id := binary.BigEndian.Uint16(ip[4:6])
		if flagsOff&0x4000 != 0 {
			p.Quirks |= QuirkDF
			if id != 0 {
				p.Quirks |= QuirkNZID
			}
		} else if id == 0 {
			p.Quirks |= QuirkZeroID
		}
		p.TotHdr = uint16(hl)
		tcp = ip[hl:n]
	case 6:
		verTOS := binary.BigEndian.Uint32(ip[0:4])
		tot := int(binary.BigEndian.Uint16(ip[4:6])) + 40
		n = min(n, tot)
		if n < minTCP6 || tot > n {
			return nil, ErrShort
		}
		// como o p0f, não percorre cabeçalhos de extensão
		if ip[6] != 6 {
			return nil, ErrNotTCP
		}
		p.IPVersion = 6
		p.TOS = uint8((verTOS >> 22) & 0x3f) //nolint:gosec // 6 bits
		p.TTL = ip[7]
		if verTOS&0xfffff != 0 {
			p.Quirks |= QuirkFlow
		}
		if (verTOS>>20)&0x03 != 0 {
			p.Quirks |= QuirkECN
		}
		p.TotHdr = 40
		tcp = ip[40:n]
	default:
		return nil, ErrVersion
	}
	return p, parseTCP(p, tcp)
}

func parseTCP(p *Packet, tcp []byte) error {
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return ErrShort
	}
	p.TotHdr += uint16(doff)
	flags := tcp[13]
	p.Flags = flags
	p.Type = flags & (tcpSYN | tcpACK | tcpFIN | tcpRST)
	if (flags&tcpSYN != 0 && flags&(tcpFIN|tcpRST) != 0) || (flags&tcpFIN != 0 && flags&tcpRST != 0) || p.Type == 0 {
		return ErrFlags
	}
	p.Window = binary.BigEndian.Uint16(tcp[14:16])
	p.Seq = binary.BigEndian.Uint32(tcp[4:8])
	if flags&(tcpECE|tcpCWR) != 0 || tcp[12]&0x01 != 0 {
		p.Quirks |= QuirkECN
	}
	if p.Seq == 0 {
		p.Quirks |= QuirkZeroSeq
	}
	ack := tcp[8:12]
	if flags&tcpACK != 0 {
		if binary.BigEndian.Uint32(ack) == 0 {
			p.Quirks |= QuirkZeroAck
		}
	} else if ack[0]&0x01 != 0 && flags&tcpRST == 0 {
		// O p0f testa `RD32(tcp->ack) & !(flags & RST)`: um E bit a bit com 0/1, ou seja, só o bit menos
		// significativo do valor lido em ordem de máquina (x86, little-endian) — o bit 0 do primeiro byte do
		// campo. Reproduzido de propósito para dar a mesma assinatura do p0f.
		p.Quirks |= QuirkNZAck
	}
	if flags&tcpURG != 0 {
		p.Quirks |= QuirkURG
	} else if binary.BigEndian.Uint16(tcp[18:20]) != 0 {
		p.Quirks |= QuirkNZURG
	}
	if flags&tcpPSH != 0 {
		p.Quirks |= QuirkPush
	}
	p.PayLen = len(tcp) - doff
	parseOptions(p, tcp[20:doff])
	return nil
}

// parseOptions segue o laço de opções do p0f, inclusive os casos que marcam "bad" ou "opt+".
func parseOptions(p *Packet, opt []byte) {
	end := len(opt)
	i := 0
	for i < end && len(p.Layout) < maxTCPOpt {
		k := opt[i]
		p.Layout = append(p.Layout, k)
		i++
		switch k {
		case optEOL:
			// Conta o que sobra depois do EOL e procura byte não nulo. Como no p0f (`while (d < end &&
			// !*d++)`), o ponteiro avança também sobre o primeiro byte não nulo; se ele for o último byte,
			// o "opt+" não aparece.
			p.EOLPad = uint8(end - i) //nolint:gosec // no máximo 40 bytes de opções
			for i < end {
				b := opt[i]
				i++
				if b != 0 {
					break
				}
			}
			if i != end {
				p.Quirks |= QuirkOptEOLNZ
				i = end
			}
		case optNOP:
		case optMSS:
			if i+3 > end {
				p.Quirks |= QuirkOptBad
				return
			}
			if opt[i] != 4 {
				p.Quirks |= QuirkOptBad
			}
			p.MSS = binary.BigEndian.Uint16(opt[i+1 : i+3])
			i += 3
		case optWScale:
			if i+2 > end {
				p.Quirks |= QuirkOptBad
				return
			}
			if opt[i] != 3 {
				p.Quirks |= QuirkOptBad
			}
			p.WScale = opt[i+1]
			if p.WScale > 14 {
				p.Quirks |= QuirkOptExWS
			}
			i += 2
		case optSACKOK:
			if i+1 > end {
				p.Quirks |= QuirkOptBad
				return
			}
			if opt[i] != 2 {
				p.Quirks |= QuirkOptBad
			}
			i++
		case optSACK:
			if i == end || opt[i] < 10 || opt[i] > 34 || i-1+int(opt[i]) > end {
				p.Quirks |= QuirkOptBad
				return
			}
			i += int(opt[i]) - 1
		case optTS:
			if i+9 > end {
				p.Quirks |= QuirkOptBad
				return
			}
			if opt[i] != 10 {
				p.Quirks |= QuirkOptBad
			}
			p.TS1 = binary.BigEndian.Uint32(opt[i+1 : i+5])
			if p.TS1 == 0 {
				p.Quirks |= QuirkZeroTS1
			}
			if p.Type == tcpSYN && binary.BigEndian.Uint32(opt[i+5:i+9]) != 0 {
				p.Quirks |= QuirkNZTS2
			}
			i += 9
		default:
			if i == end || opt[i] < 2 || opt[i] > 40 || i-1+int(opt[i]) > end {
				p.Quirks |= QuirkOptBad
				return
			}
			i += int(opt[i]) - 1
		}
	}
	if i != end {
		p.Quirks |= QuirkOptBad
	}
}
