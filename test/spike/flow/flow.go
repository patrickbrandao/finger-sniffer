// Package flow extrai a 5-tupla e as flags TCP de um frame Ethernet sem alocar (spike da task 006).
package flow

import (
	"encoding/binary"
	"net/netip"
)

// Info é o que o spike precisa de cada frame.
type Info struct {
	OK       bool
	L4       uint8 // 6 = TCP, 17 = UDP
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
}

// Flags TCP.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	ACK = 0x10
)

// Parse decodifica Ethernet (com VLAN opcional), IPv4/IPv6 e TCP/UDP.
func Parse(frame []byte) Info {
	if len(frame) < 14 {
		return Info{}
	}
	eth := binary.BigEndian.Uint16(frame[12:14])
	p := frame[14:]
	if eth == 0x8100 && len(p) >= 4 {
		eth = binary.BigEndian.Uint16(p[2:4])
		p = p[4:]
	}
	var info Info
	var l4 []byte
	switch eth {
	case 0x0800:
		if len(p) < 20 {
			return Info{}
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return Info{}
		}
		// Fragmentos que não são o primeiro não têm cabeçalho L4.
		if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return Info{}
		}
		info.L4 = p[9]
		info.Src = netip.AddrFrom4([4]byte(p[12:16]))
		info.Dst = netip.AddrFrom4([4]byte(p[16:20]))
		l4 = p[ihl:]
	case 0x86dd:
		if len(p) < 40 {
			return Info{}
		}
		info.L4 = p[6]
		info.Src = netip.AddrFrom16([16]byte(p[8:24]))
		info.Dst = netip.AddrFrom16([16]byte(p[24:40]))
		l4 = p[40:]
	default:
		return Info{}
	}
	switch info.L4 {
	case 6:
		if len(l4) < 14 {
			return Info{}
		}
		info.TCPFlags = l4[13]
	case 17:
		if len(l4) < 8 {
			return Info{}
		}
	default:
		return Info{}
	}
	info.SrcPort = binary.BigEndian.Uint16(l4[0:2])
	info.DstPort = binary.BigEndian.Uint16(l4[2:4])
	info.OK = true
	return info
}
