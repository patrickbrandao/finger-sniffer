package capture

import "encoding/binary"

// Construtores de frames para os testes.

type frameOpt struct {
	vlan     bool
	v6       bool
	proto    byte
	sport    uint16
	dport    uint16
	fragOff  uint16 // IPv4: offset do fragmento (em unidades de 8 bytes)
	ihlWords int    // IPv4: tamanho do cabeçalho em palavras de 32 bits (padrão 5)
	src, dst []byte
	tcpFlags byte
	payload  int
	// v6ext são os cabeçalhos de extensão IPv6, em ordem, entre o fixo e o de transporte.
	v6ext []byte
	// v6fragOff é o offset (em unidades de 8 bytes) gravado no cabeçalho Fragment, quando há um em v6ext.
	v6fragOff uint16
}

// v6ExtHeader monta um cabeçalho de extensão do tipo kind com next como próximo.
func v6ExtHeader(kind, next byte, fragOff uint16) []byte {
	switch kind {
	case ipv6Fragment:
		h := make([]byte, 8)
		h[0] = next
		binary.BigEndian.PutUint16(h[2:4], fragOff<<3)
		return h
	case ipv6AH:
		h := make([]byte, 16) // (2 + 2) * 4
		h[0], h[1] = next, 2
		return h
	default:
		h := make([]byte, 16) // (1 + 1) * 8
		h[0], h[1] = next, 1
		return h
	}
}

func buildFrame(o frameOpt) []byte {
	var f []byte
	f = append(f, make([]byte, 12)...) // MACs
	if o.vlan {
		f = binary.BigEndian.AppendUint16(f, 0x8100)
		f = binary.BigEndian.AppendUint16(f, 100)
	}
	if o.v6 {
		f = binary.BigEndian.AppendUint16(f, 0x86dd)
		ip := make([]byte, 40)
		ip[0] = 0x60
		ip[6] = o.proto
		if len(o.v6ext) > 0 {
			ip[6] = o.v6ext[0]
		}
		ip[7] = 64
		src, dst := o.src, o.dst
		if src == nil {
			src = make([]byte, 16)
			src[15] = 1
		}
		if dst == nil {
			dst = make([]byte, 16)
			dst[15] = 2
		}
		copy(ip[8:24], src)
		copy(ip[24:40], dst)
		f = append(f, ip...)
		for i, kind := range o.v6ext {
			next := o.proto
			if i+1 < len(o.v6ext) {
				next = o.v6ext[i+1]
			}
			f = append(f, v6ExtHeader(kind, next, o.v6fragOff)...)
		}
	} else {
		f = binary.BigEndian.AppendUint16(f, 0x0800)
		ihl := o.ihlWords
		if ihl == 0 {
			ihl = 5
		}
		ip := make([]byte, ihl*4)
		ip[0] = 0x40 | byte(ihl) //nolint:gosec // teste
		ip[8] = 64
		ip[9] = o.proto
		binary.BigEndian.PutUint16(ip[6:8], o.fragOff)
		src, dst := o.src, o.dst
		if src == nil {
			src = []byte{192, 0, 2, 1}
		}
		if dst == nil {
			dst = []byte{172, 233, 24, 85}
		}
		copy(ip[12:16], src)
		copy(ip[16:20], dst)
		f = append(f, ip...)
	}
	switch o.proto {
	case 6:
		l4 := make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], o.sport)
		binary.BigEndian.PutUint16(l4[2:4], o.dport)
		l4[12] = 5 << 4
		l4[13] = o.tcpFlags
		f = append(f, l4...)
	case 17:
		l4 := make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:2], o.sport)
		binary.BigEndian.PutUint16(l4[2:4], o.dport)
		f = append(f, l4...)
	default:
		f = append(f, make([]byte, 8)...)
	}
	return append(f, make([]byte, o.payload)...)
}
