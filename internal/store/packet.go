package store

import (
	"encoding/binary"
	"net/netip"
)

// Protocolos L4 tratados pela correlação.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// Flags TCP.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// frameInfo é o que a correlação e a análise IP/TCP precisam de um frame. Os slices apontam para o frame.
type frameInfo struct {
	ok       bool // IPv4/IPv6 decodificado
	family   int
	proto    uint8
	src, dst netip.Addr
	ports    bool // TCP/UDP com cabeçalho L4 presente
	sport    uint16
	dport    uint16
	tcpFlags uint8
	payload  int    // bytes de aplicação (TCP/UDP)
	headers  int    // bytes até o fim do cabeçalho L4 (para o pcap truncado)
	frag     bool   // IPv4 com MF ligado ou deslocamento de fragmento; IPv6 com cabeçalho Fragment
	l3       []byte // do cabeçalho IP até o fim declarado do pacote
	l4       []byte // do cabeçalho L4 até o fim do pacote (TCP: cabeçalho, opções e dados)
	tcpDoff  int    // tamanho do cabeçalho TCP com opções
}

// Cabeçalhos de extensão IPv6 (spec 013 RF-05).
const (
	ipv6HopByHop = 0
	ipv6Routing  = 43
	ipv6Fragment = 44
	ipv6AH       = 51
	ipv6DstOpts  = 60
	v6ExtMax     = 16 // limite do percurso, o mesmo do capture
)

// v6Upper atravessa os cabeçalhos de extensão IPv6 e devolve o protocolo de transporte, o que vem depois dele,
// quantos bytes de extensão havia e se havia cabeçalho Fragment. Fragmento não inicial, cabeçalho truncado ou
// extensões demais devolvem l4 nil (sem análise L4), como no capture.
func v6Upper(next byte, p []byte) (proto byte, l4 []byte, ext int, frag bool) {
	for range v6ExtMax {
		switch next {
		case ipv6HopByHop, ipv6Routing, ipv6DstOpts, ipv6AH:
			if len(p) < 8 {
				return next, nil, ext, frag
			}
			n := (int(p[1]) + 1) * 8
			if next == ipv6AH {
				n = (int(p[1]) + 2) * 4
			}
			if len(p) < n {
				return next, nil, ext, frag
			}
			next, p, ext = p[0], p[n:], ext+n
		case ipv6Fragment:
			if len(p) < 8 {
				return next, nil, ext, true
			}
			frag = true
			if binary.BigEndian.Uint16(p[2:4])&0xfff8 != 0 {
				return p[0], nil, ext + 8, true // não inicial: sem cabeçalho L4
			}
			next, p, ext = p[0], p[8:], ext+8
		default:
			return next, p, ext, frag
		}
	}
	switch next {
	case ipv6HopByHop, ipv6Routing, ipv6DstOpts, ipv6AH, ipv6Fragment:
		return next, nil, ext, frag
	}
	return next, p, ext, frag
}

// parseFrame decodifica Ethernet (VLAN opcional), IPv4/IPv6 e TCP/UDP sem alocar.
func parseFrame(f []byte) frameInfo {
	if len(f) < 14 {
		return frameInfo{}
	}
	off := 14
	eth := binary.BigEndian.Uint16(f[12:14])
	if eth == 0x8100 {
		if len(f) < 18 {
			return frameInfo{}
		}
		eth, off = binary.BigEndian.Uint16(f[16:18]), 18
	}
	var r frameInfo
	var l4 []byte
	var l4off int
	switch eth {
	case 0x0800:
		p := f[off:]
		if len(p) < 20 {
			return frameInfo{}
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return frameInfo{}
		}
		r.family, r.proto = 4, p[9]
		r.src, r.dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		total := int(binary.BigEndian.Uint16(p[2:4]))
		end := min(len(p), max(total, ihl))
		fo := binary.BigEndian.Uint16(p[6:8])
		if fo&0x1fff == 0 {
			l4, l4off = p[ihl:end], off+ihl
		}
		r.frag = fo&0x3fff != 0
		r.l3 = p[:end]
		r.headers = off + ihl
	case 0x86dd:
		p := f[off:]
		if len(p) < 40 {
			return frameInfo{}
		}
		r.family = 6
		r.src, r.dst = netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
		end := min(len(p), 40+int(binary.BigEndian.Uint16(p[4:6])))
		var ext int
		r.proto, l4, ext, r.frag = v6Upper(p[6], p[40:end])
		l4off = off + 40 + ext
		r.l3 = p[:end]
		r.headers = l4off
	default:
		return frameInfo{}
	}
	r.ok = true
	switch r.proto {
	case protoTCP:
		if len(l4) >= 20 {
			doff := int(l4[12]>>4) * 4
			if doff >= 20 && doff <= len(l4) {
				r.ports = true
				r.sport, r.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
				r.tcpFlags = l4[13]
				r.payload = len(l4) - doff
				r.headers = l4off + doff
				r.l4, r.tcpDoff = l4, doff
			}
		}
	case protoUDP:
		if len(l4) >= 8 {
			r.ports = true
			r.sport, r.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			r.payload = len(l4) - 8
			r.headers = l4off + 8
			r.l4 = l4
		}
	}
	return r
}

func (f frameInfo) srcAP() netip.AddrPort { return netip.AddrPortFrom(f.src, f.sport) }
func (f frameInfo) dstAP() netip.AddrPort { return netip.AddrPortFrom(f.dst, f.dport) }

func l4Name(p uint8) string {
	switch p {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	case protoICMPv6:
		return "icmpv6"
	default:
		return "other"
	}
}

// tcpFlagsString usa as letras do openapi (S, A, F, R, P, U, E, C).
func tcpFlagsString(fl uint8) string {
	out := make([]byte, 0, 8)
	for _, x := range []struct {
		bit uint8
		c   byte
	}{{tcpSYN, 'S'}, {tcpACK, 'A'}, {tcpFIN, 'F'}, {tcpRST, 'R'}, {tcpPSH, 'P'}, {0x20, 'U'}, {0x40, 'E'}, {0x80, 'C'}} {
		if fl&x.bit != 0 {
			out = append(out, x.c)
		}
	}
	return string(out)
}
