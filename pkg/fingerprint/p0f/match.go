package p0f

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

// ErrNotSYN indica pacote que não é SYN nem SYN+ACK (o p0f só fingerprinta esses dois).
var ErrNotSYN = errors.New("p0f: só SYN e SYN+ACK têm assinatura")

// Observation é o resultado de um SYN ou SYN+ACK, com os mesmos campos da observação do p0f -r.
type Observation struct {
	// Mod é "syn", "syn+ack" ou "sendsyn probe" (SYN do p0f-sendsyn).
	Mod string
	// OS é o palpite (nome e sabor, por exemplo "Linux 3.11 and newer"); "???" sem correspondência.
	OS string
	// App: a assinatura é de uma ferramenta (classe "!"), e o p0f escreve "app" no lugar de "os".
	App bool
	// Dist é a distância como o p0f escreve: "12", ou "<= 12" com TTL aleatório.
	Dist string
	// Params são as flags da correspondência: "generic", "fuzzy", "random_ttl", "excess_dist", "tos:0x..";
	// "none" quando não há nenhuma.
	Params string
	// RawSig é a assinatura do pacote no formato do p0f.fp.
	RawSig string

	// Detalhes da correspondência (vazios sem correspondência).
	Label     string // linha label do p0f.fp, ex. "s:unix:Linux:3.11 and newer"
	Class     string // "win", "unix", "other" ou "!"
	Name      string
	Flavor    string
	Line      int // linha da assinatura no p0f.fp
	Generic   bool
	Fuzzy     bool
	RandomTTL bool
	Distance  uint8
	Matched   bool
}

type match struct {
	rec   *Record
	fuzzy bool
	dist  uint8
}

// Fingerprint calcula a assinatura e o palpite de SO de um SYN ou SYN+ACK. synMSS é o MSS do SYN do mesmo
// fluxo, usado só no SYN+ACK (o p0f compara a janela com o MSS do outro lado); no SYN é ignorado.
func (db *DB) Fingerprint(p *Packet, synMSS uint16) (Observation, error) {
	var toServer bool
	switch {
	case p.IsSYN():
		toServer = true
		synMSS = 0
	case p.IsSYNACK():
	default:
		return Observation{}, ErrNotSYN
	}
	ts := packetSig(p)
	m, win := db.find(toServer, &ts, false, synMSS)

	sendsyn := toServer && p.Window == specialWin && p.MSS == specialMSS
	o := Observation{Mod: "syn+ack", OS: "???", Distance: m.dist}
	switch {
	case sendsyn:
		o.Mod = "sendsyn probe"
	case toServer:
		o.Mod = "syn"
	}
	if r := m.rec; r != nil {
		o.Matched = true
		o.App = r.ClassID == -1 || sendsyn
		o.OS = db.Name(r)
		if r.Flavor != "" {
			o.OS += " " + r.Flavor
		}
		o.Label = r.Label
		o.Class = db.Class(r)
		o.Name = db.Name(r)
		o.Flavor = r.Flavor
		o.Line = r.Line
		o.Generic = r.Generic
		o.Fuzzy = m.fuzzy
		o.RandomTTL = r.BadTTL
	}
	if o.RandomTTL {
		o.Dist = "<= " + strconv.Itoa(int(m.dist))
	} else {
		o.Dist = strconv.Itoa(int(m.dist))
	}
	o.Params = flags(p, o)
	o.RawSig = rawSig(p, win)
	return o, nil
}

// packetSig converte o pacote para a forma de comparação (packet_to_sig).
func packetSig(p *Packet) tsig {
	pay := int8(0)
	if p.PayLen > 0 {
		pay = 1
	}
	ver := int8(4)
	if p.IPVersion == 6 {
		ver = 6
	}
	return tsig{
		layout: p.Layout, quirks: p.Quirks, eolPad: p.EOLPad, ipOptLen: p.IPOptLen, ipVer: ver,
		ttl: p.TTL, mss: int32(p.MSS), win: p.Window, winType: winNormal, wscale: int16(p.WScale),
		payClass: pay, totHdr: p.TotHdr, ts1: p.TS1,
	}
}

// guessDist estima a distância pelo TTL inicial mais próximo (32, 64, 128 ou 255).
func guessDist(ttl uint8) uint8 {
	switch {
	case ttl <= 32:
		return 32 - ttl
	case ttl <= 64:
		return 64 - ttl
	case ttl <= 128:
		return 128 - ttl
	}
	return 255 - ttl
}

// winMultiple diz se a janela é múltiplo do MSS ou do MTU (detect_win_multi); -1 quando não é.
func winMultiple(ts *tsig, synMSS uint16) (multi int16, useMTU bool) {
	win := int(ts.win)
	mss := int(ts.mss)
	if win == 0 || mss < 100 || ts.winType != winNormal {
		return -1, false
	}
	try := func(div int, mtu bool) bool {
		if div != 0 && win%div == 0 {
			// como no C, o quociente é convertido para s16
			multi, useMTU = int16(win/div), mtu //nolint:gosec // conversão intencional, igual ao p0f
			return true
		}
		return false
	}
	switch {
	case try(mss, false):
	case ts.ts1 != 0 && try(mss-12, false):
	case try(1500-minTCP4, false):
	case try(1500-minTCP4-12, false):
	case ts.ipVer == 6 && try(1500-minTCP6, false):
	case ts.ipVer == 6 && try(1500-minTCP6-12, false):
	case try(mss+minTCP4, true):
	case try(mss+int(ts.totHdr), true):
	case ts.ipVer == 6 && try(mss+minTCP6, true):
	case try(1500, true):
	case synMSS != 0 && try(int(synMSS), false):
	case synMSS != 0 && try(int(synMSS)-12, false):
	default:
		return -1, false
	}
	return multi, useMTU
}

// winInfo é o resultado de winMultiple, usado na comparação e na assinatura crua.
type winInfo struct {
	multi int16
	mtu   bool
}

// find procura a assinatura do p0f.fp que corresponde a ts (tcp_find_match). dupe é a verificação de
// assinatura repetida feita na carga do banco. Devolve também o multiplicador da janela, que a assinatura
// crua usa.
func (db *DB) find(toServer bool, ts *tsig, dupe bool, synMSS uint16) (match, winInfo) {
	var fmatch, gmatch *Record
	winMulti, useMTU := winMultiple(ts, synMSS)
	wi := winInfo{winMulti, useMTU}
	var out match
	for _, ref := range db.tcp[b2i(toServer)] {
		refs := &ref.sig
		fuzzy := false
		refQuirks := refs.quirks
		if !slices.Equal(refs.layout, ts.layout) {
			continue
		}
		// assinatura sem versão de IP: tira os quirks que só existem na outra versão
		if refs.ipVer == -1 {
			if ts.ipVer == 4 {
				refQuirks &^= QuirkFlow
			} else {
				refQuirks &^= QuirkDF | QuirkNZID | QuirkZeroID
			}
		}
		if refQuirks != ts.quirks {
			deleted := (refQuirks ^ ts.quirks) & refQuirks
			added := (refQuirks ^ ts.quirks) & ts.quirks
			// diferença aceita como fuzzy: "df" ou "id+" sumindo, "id-" ou "ecn" aparecendo
			if fmatch != nil || deleted&^(QuirkDF|QuirkNZID) != 0 || added&^(QuirkZeroID|QuirkECN) != 0 {
				continue
			}
			fuzzy = true
		}
		if refs.eolPad != ts.eolPad || refs.ipOptLen != ts.ipOptLen {
			continue
		}
		if ref.BadTTL {
			if refs.ttl < ts.ttl {
				continue
			}
		} else if refs.ttl < ts.ttl || refs.ttl-ts.ttl > maxDist {
			fuzzy = true
		}
		if refs.mss != -1 && refs.mss != ts.mss {
			continue
		}
		if refs.wscale != -1 && refs.wscale != ts.wscale {
			continue
		}
		if refs.payClass != -1 && refs.payClass != ts.payClass {
			continue
		}
		if ts.winType != winNormal {
			// comparando duas assinaturas do p0f.fp
			if refs.winType != ts.winType || refs.win != ts.win {
				continue
			}
		} else {
			switch refs.winType {
			case winNormal:
				if refs.win != ts.win {
					continue
				}
			case winMod:
				if ts.win%refs.win != 0 {
					continue
				}
			case winMSS:
				if useMTU || int(refs.win) != int(winMulti) {
					continue
				}
			case winMTU:
				if !useMTU || int(refs.win) != int(winMulti) {
					continue
				}
			}
		}
		if !fuzzy {
			if !ref.Generic {
				return match{rec: ref, dist: refs.ttl - ts.ttl}, wi
			}
			if gmatch == nil {
				gmatch = ref
			}
		} else if fmatch == nil {
			fmatch = ref
		}
	}
	if dupe {
		return out, wi
	}
	if gmatch != nil {
		return match{rec: gmatch, dist: gmatch.sig.ttl - ts.ttl}, wi
	}
	// sem fuzzy para ferramentas (e a distância fica 0, como no p0f)
	if fmatch != nil && fmatch.ClassID == -1 {
		return out, wi
	}
	if fmatch == nil || fmatch.sig.ttl < ts.ttl || (!fmatch.BadTTL && fmatch.sig.ttl-ts.ttl > maxDist) {
		out.dist = guessDist(ts.ttl)
	} else {
		out.dist = fmatch.sig.ttl - ts.ttl
	}
	if fmatch != nil {
		out.rec = fmatch
		out.fuzzy = true
	}
	return out, wi
}

// flags monta o campo params (dump_flags).
func flags(p *Packet, o Observation) string {
	var parts []string
	if o.Matched {
		if o.Generic {
			parts = append(parts, "generic")
		}
		if o.Fuzzy {
			parts = append(parts, "fuzzy")
		}
		if o.RandomTTL {
			parts = append(parts, "random_ttl")
		}
	}
	if o.Distance > maxDist {
		parts = append(parts, "excess_dist")
	}
	if p.TOS != 0 {
		parts = append(parts, "tos:0x"+hex2(p.TOS))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func hex2(b uint8) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

// rawSig escreve a assinatura do pacote no formato do p0f.fp (dump_sig).
func rawSig(p *Packet, w winInfo) string {
	var b strings.Builder
	b.Grow(96)
	u := func(v int) { b.WriteString(strconv.Itoa(v)) }
	u(int(p.IPVersion))
	b.WriteByte(':')
	u(int(p.TTL))
	b.WriteByte('+')
	if d := guessDist(p.TTL); d > maxDist {
		b.WriteByte('?')
	} else {
		u(int(d))
	}
	b.WriteByte(':')
	u(int(p.IPOptLen))
	b.WriteByte(':')
	if p.MSS == specialMSS && p.Type == tcpSYN|tcpACK {
		b.WriteByte('*')
	} else {
		u(int(p.MSS))
	}
	b.WriteByte(':')
	if w.multi > 0 {
		if w.mtu {
			b.WriteString("mtu*")
		} else {
			b.WriteString("mss*")
		}
		u(int(w.multi))
	} else {
		u(int(p.Window))
	}
	b.WriteByte(',')
	u(int(p.WScale))
	b.WriteByte(':')
	for i, k := range p.Layout {
		if i > 0 {
			b.WriteByte(',')
		}
		switch k {
		case optEOL:
			b.WriteString("eol+")
			u(int(p.EOLPad))
		case optNOP:
			b.WriteString("nop")
		case optMSS:
			b.WriteString("mss")
		case optWScale:
			b.WriteString("ws")
		case optSACKOK:
			b.WriteString("sok")
		case optSACK:
			b.WriteString("sack")
		case optTS:
			b.WriteString("ts")
		default:
			b.WriteByte('?')
			u(int(k))
		}
	}
	b.WriteByte(':')
	first := true
	for _, q := range quirkNames {
		if p.Quirks&q.bit == 0 {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(q.name)
	}
	if p.PayLen > 0 {
		b.WriteString(":+")
	} else {
		b.WriteString(":0")
	}
	return b.String()
}
