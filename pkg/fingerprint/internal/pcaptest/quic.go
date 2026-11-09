package pcaptest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Datagram é um datagrama UDP de um pcap.
type Datagram struct {
	// Index é a posição do frame no arquivo, a partir de 1.
	Index    int
	Src, Dst netip.AddrPort
	Payload  []byte
}

// QUICFiles lista os pcaps de testdata/quic (Initials do cliente) em ordem alfabética.
func QUICFiles() ([]string, error) {
	return glob("testdata/quic/*.pcapng")
}

// Datagrams devolve os datagramas UDP de um pcap, na ordem do arquivo.
func Datagrams(file string) ([]Datagram, error) {
	src, closeFn, err := open(file)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	var out []Datagram
	for n := 1; ; n++ {
		data, _, err := src.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s frame %d: %w", file, n, err)
		}
		pkt := gopacket.NewPacket(data, src.LinkType(), gopacket.Default)
		var s, d netip.Addr
		if l, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			s, _ = netip.AddrFromSlice(l.SrcIP.To4())
			d, _ = netip.AddrFromSlice(l.DstIP.To4())
		} else if l, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			s, _ = netip.AddrFromSlice(l.SrcIP)
			d, _ = netip.AddrFromSlice(l.DstIP)
		}
		u, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			continue
		}
		out = append(out, Datagram{
			Index:   n,
			Src:     netip.AddrPortFrom(s, uint16(u.SrcPort)),
			Dst:     netip.AddrPortFrom(d, uint16(u.DstPort)),
			Payload: append([]byte(nil), u.Payload...),
		})
	}
}

// QUICPacket é o que o tshark mostrou de um datagrama Initial do cliente (testdata/quic/tshark.golden.json).
type QUICPacket struct {
	Frame        int
	SrcPort      uint16
	UDPLength    int
	Version      string // hex sem 0x, 8 dígitos
	DCIDHex      string
	SCIDHex      string
	TokenLen     int
	Length       int
	PacketNumber int64
	// FrameTypes são os tipos dos frames na ordem (sequências de PADDING já juntas, como o tshark faz).
	FrameTypes []uint64
	// CryptoOffsets e CryptoLengths dos frames CRYPTO, na ordem.
	CryptoOffsets []uint64
	CryptoLengths []int
	// Params são os parâmetros de transporte [id, valor_hex] na ordem.
	Params [][2]string
	JA3    string
	JA3MD5 string
}

// QUICGolden lê os gabaritos de testdata/quic: nome do pcap → datagramas do tshark e o fluxo do ja4
// oficial (JA4, JA4_r, JA4_o, JA4_ro).
func QUICGolden() (map[string][]QUICPacket, map[string]TLSStream, error) {
	var raw map[string][]struct {
		Source struct {
			Layers map[string][]string `json:"layers"`
		} `json:"_source"`
	}
	if err := readJSON("testdata/quic/tshark.golden.json", &raw); err != nil {
		return nil, nil, err
	}
	pkts := map[string][]QUICPacket{}
	for file, list := range raw {
		for _, e := range list {
			p, err := quicPacket(e.Source.Layers)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", file, err)
			}
			pkts["testdata/quic/"+path.Base(file)] = append(pkts["testdata/quic/"+path.Base(file)], p)
		}
	}
	var ja4 map[string]struct {
		Sorted   []TLSStream `json:"sorted"`
		Original []TLSStream `json:"original"`
	}
	if err := readJSON("testdata/quic/ja4.golden.json", &ja4); err != nil {
		return nil, nil, err
	}
	streams := map[string]TLSStream{}
	for file, g := range ja4 {
		if len(g.Sorted) != 1 || len(g.Original) != 1 {
			return nil, nil, fmt.Errorf("%s: esperado um fluxo QUIC no gabarito do ja4", file)
		}
		s := g.Sorted[0]
		s.JA4O, s.JA4RO = g.Original[0].JA4O, g.Original[0].JA4RO
		streams["testdata/quic/"+path.Base(file)] = s
	}
	return pkts, streams, nil
}

func quicPacket(l map[string][]string) (QUICPacket, error) {
	one := func(k string) string {
		if v := l[k]; len(v) > 0 && v[0] != "<MISSING>" {
			return v[0]
		}
		return ""
	}
	num := func(k string) int64 {
		n, _ := strconv.ParseInt(one(k), 10, 64)
		return n
	}
	p := QUICPacket{
		Frame:        int(num("frame.number")),
		SrcPort:      uint16(num("udp.srcport")), //nolint:gosec // porta
		UDPLength:    int(num("udp.length")),
		Version:      strings.TrimPrefix(one("quic.version"), "0x"),
		DCIDHex:      one("quic.dcid"),
		SCIDHex:      one("quic.scid"),
		TokenLen:     int(num("quic.token_length")),
		Length:       int(num("quic.length")),
		PacketNumber: num("quic.packet_number"),
		JA3:          one("tls.handshake.ja3_full"),
		JA3MD5:       one("tls.handshake.ja3"),
	}
	for _, t := range l["quic.frame_type"] {
		v, err := strconv.ParseUint(strings.TrimPrefix(t, "0x"), 16, 64)
		if err != nil {
			return p, err
		}
		p.FrameTypes = append(p.FrameTypes, v)
	}
	for i, o := range l["quic.crypto.offset"] {
		v, _ := strconv.ParseUint(o, 10, 64)
		p.CryptoOffsets = append(p.CryptoOffsets, v)
		if i < len(l["quic.crypto.length"]) {
			n, _ := strconv.Atoi(l["quic.crypto.length"][i])
			p.CryptoLengths = append(p.CryptoLengths, n)
		}
	}
	types, values := l["tls.quic.parameter.type"], l["tls.quic.parameter.value"]
	if len(types) != len(values) {
		return p, fmt.Errorf("frame %d: %d tipos e %d valores de parâmetros", p.Frame, len(types), len(values))
	}
	for i, t := range types {
		v := strings.ReplaceAll(values[i], ":", "")
		if v == "<MISSING>" {
			v = ""
		}
		if _, err := hex.DecodeString(v); err != nil {
			return p, fmt.Errorf("frame %d: valor %q", p.Frame, values[i])
		}
		p.Params = append(p.Params, [2]string{t, v})
	}
	return p, nil
}
