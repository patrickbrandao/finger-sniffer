package capture

import (
	"encoding/binary"
	"net/netip"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// l3l4 é o mínimo que o capture precisa de um frame: endereços e portas (para direção e conferência do filtro).
type l3l4 struct {
	ok       bool
	src, dst netip.Addr
	ports    bool
	sport    uint16
	dport    uint16
}

// parseFrame decodifica Ethernet (VLAN opcional), IPv4/IPv6 e as portas TCP/UDP, sem alocar.
func parseFrame(f []byte) l3l4 {
	if len(f) < 14 {
		return l3l4{}
	}
	eth := binary.BigEndian.Uint16(f[12:14])
	p := f[14:]
	if eth == 0x8100 {
		if len(p) < 4 {
			return l3l4{}
		}
		eth, p = binary.BigEndian.Uint16(p[2:4]), p[4:]
	}
	var r l3l4
	var proto byte
	var l4 []byte
	switch eth {
	case 0x0800:
		if len(p) < 20 {
			return l3l4{}
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return l3l4{}
		}
		r.src, r.dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		proto = p[9]
		if binary.BigEndian.Uint16(p[6:8])&0x1fff == 0 {
			l4 = p[ihl:]
		}
	case 0x86dd:
		if len(p) < 40 {
			return l3l4{}
		}
		r.src, r.dst = netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
		proto, l4 = p[6], p[40:]
	default:
		return l3l4{}
	}
	r.ok = true
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		r.ports = true
		r.sport, r.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	}
	return r
}

// classifier decide direção e flags de cada pacote.
type classifier struct {
	local    map[netip.Addr]bool
	excluded map[uint16]bool
	mtu      int
}

// direction devolve DirOut quando a origem é um IP local; DirIn nos demais casos.
func (c *classifier) direction(fr l3l4) uint8 {
	if fr.ok && c.local[fr.src] {
		return event.DirOut
	}
	return event.DirIn
}

// excludedPort confere, em espaço de usuário, o que o BPF já deveria ter descartado (defesa contra pacotes que
// entraram no anel antes de o filtro ser instalado).
func (c *classifier) excludedPort(fr l3l4) bool {
	return fr.ports && (c.excluded[fr.sport] || c.excluded[fr.dport])
}

// flags marca offload suspeito (frame > MTU + 14 + VLAN) e truncamento pelo snaplen.
func (c *classifier) flags(wireLen, capLen int) uint8 {
	var f uint8
	if c.mtu > 0 && wireLen > c.mtu+18 {
		f |= event.FlagOffloadSuspect
	}
	if capLen < wireLen {
		f |= event.FlagTruncated
	}
	return f
}

// toSet monta o conjunto de portas excluídas.
func toSet(ports []uint16) map[uint16]bool {
	s := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		s[p] = true
	}
	return s
}
