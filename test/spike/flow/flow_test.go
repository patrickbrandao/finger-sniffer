package flow

import (
	"encoding/binary"
	"testing"
)

func frame4(proto byte, sport, dport uint16, flags byte) []byte {
	f := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	ip[9] = proto
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{172, 233, 24, 85})
	l4 := ip[20:]
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	l4[13] = flags
	return f
}

func TestParseIPv4TCP(t *testing.T) {
	i := Parse(frame4(6, 41234, 443, SYN))
	if !i.OK || i.L4 != 6 || i.SrcPort != 41234 || i.DstPort != 443 || i.TCPFlags != SYN ||
		i.Src.String() != "192.0.2.1" || i.Dst.String() != "172.233.24.85" {
		t.Fatalf("%+v", i)
	}
}

func TestParseRejects(t *testing.T) {
	short := frame4(6, 1, 2, 0)[:30]
	icmp := frame4(1, 0, 0, 0)
	frag := frame4(6, 1, 2, 0)
	binary.BigEndian.PutUint16(frag[14+6:14+8], 10)
	for name, f := range map[string][]byte{"short": short, "icmp": icmp, "frag": frag, "tiny": {1, 2}} {
		if Parse(f).OK {
			t.Errorf("%s: expected not OK", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(frame4(6, 1, 2, 3))
	f.Fuzz(func(t *testing.T, b []byte) { _ = Parse(b) })
}
