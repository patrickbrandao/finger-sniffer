package pcaptest

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"path"
	"sort"

	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Hello é o primeiro ClientHello de um fluxo TCP de um pcap.
type Hello struct {
	Src, Dst netip.AddrPort
	// Occurrence conta os fluxos anteriores com a mesma 4-tupla no arquivo (reuso de portas).
	Occurrence int
	// Records são os bytes do(s) registro(s) TLS do ClientHello, remontados do fluxo TCP.
	Records []byte
}

// Key identifica o fluxo: 4-tupla e ocorrência.
func (h Hello) Key() string {
	return flowOccKey(FlowKey(h.Src, h.Dst), h.Occurrence)
}

func flowOccKey(k string, occ int) string {
	b, _ := json.Marshal([]any{k, occ})
	return string(b)
}

type segment struct {
	seq  uint32
	data []byte
}

type flow struct {
	src, dst netip.AddrPort
	occ      int
	isn      uint32
	hasISN   bool
	segs     []segment
}

// ClientHellos remonta cada sentido de cada fluxo TCP do pcap e devolve o primeiro ClientHello de cada
// fluxo que tenha um (mesmo depois de CONNECT ou SOCKS no mesmo fluxo).
func ClientHellos(file string) ([]Hello, error) {
	pkts, err := Read(file)
	if err != nil {
		return nil, err
	}
	var flows []*flow
	current := map[string]*flow{}
	seen := map[string]int{}
	for _, p := range pkts {
		k := FlowKey(p.Src, p.Dst)
		syn := p.Flags&0x02 != 0
		f := current[k]
		if f == nil || syn && p.Flags&0x10 == 0 && f.hasISN && len(f.segs) > 0 {
			f = &flow{src: p.Src, dst: p.Dst, occ: seen[k]}
			seen[k]++
			current[k] = f
			flows = append(flows, f)
		}
		seq, payload, ok := tcpPayload(p)
		if !ok {
			continue
		}
		if syn {
			f.isn, f.hasISN = seq+1, true
			continue
		}
		if len(payload) == 0 {
			continue
		}
		if !f.hasISN {
			f.isn, f.hasISN = seq, true
		}
		f.segs = append(f.segs, segment{seq: seq, data: payload})
	}
	var out []Hello
	for _, f := range flows {
		data := f.assemble()
		if rec := findClientHello(data); rec != nil {
			out = append(out, Hello{Src: f.src, Dst: f.dst, Occurrence: f.occ, Records: rec})
		}
	}
	return out, nil
}

// tcpPayload devolve o número de sequência e os dados do segmento, sem o padding do Ethernet.
func tcpPayload(p Packet) (uint32, []byte, bool) {
	if len(p.TCP) < 20 {
		return 0, nil, false
	}
	var ipLen int
	switch p.Version {
	case 4:
		if len(p.IP) < 4 {
			return 0, nil, false
		}
		ipLen = int(binary.BigEndian.Uint16(p.IP[2:4]))
	case 6:
		if len(p.IP) < 6 {
			return 0, nil, false
		}
		ipLen = 40 + int(binary.BigEndian.Uint16(p.IP[4:6]))
	}
	tcpOff := len(p.IP) - len(p.TCP)
	end := min(ipLen, len(p.IP)) - tcpOff
	hl := int(p.TCP[12]>>4) * 4
	seq := binary.BigEndian.Uint32(p.TCP[4:8])
	if hl < 20 || end < hl {
		return seq, nil, true
	}
	return seq, p.TCP[hl:end], true
}

// assemble junta os segmentos na ordem da sequência a partir do ISN, até o primeiro buraco.
func (f *flow) assemble() []byte {
	segs := append([]segment(nil), f.segs...)
	sort.SliceStable(segs, func(i, j int) bool { return rel(segs[i].seq, f.isn) < rel(segs[j].seq, f.isn) })
	var out []byte
	for _, s := range segs {
		off := rel(s.seq, f.isn)
		if off < 0 {
			continue
		}
		if off > len(out) {
			break
		}
		if end := off + len(s.data); end > len(out) {
			out = append(out, s.data[len(out)-off:]...)
		}
	}
	return out
}

// rel é a posição relativa ao ISN na aritmética de sequência do TCP (com volta em 2^32).
func rel(seq, isn uint32) int {
	return int(int32(seq - isn)) //nolint:gosec // a volta é intencional (RFC 9293 §3.4)
}

// findClientHello procura o primeiro registro de handshake TLS com um ClientHello completo.
func findClientHello(data []byte) []byte {
	for i := 0; i+6 <= len(data); i++ {
		if data[i] != tlsparse.RecordTypeHandshake || data[i+1] != 0x03 || data[i+5] != tlsparse.HandshakeTypeClientHello {
			continue
		}
		r, err := tlsparse.Reassemble(data[i:])
		if err == nil {
			return data[i : i+r.Consumed]
		}
	}
	return nil
}

// TLSStream é uma linha dos gabaritos de TLS (um fluxo TCP com ClientHello).
type TLSStream struct {
	Stream  int    `json:"stream"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	// do ja4 oficial
	JA4   string `json:"ja4"`
	JA4R  string `json:"ja4_r"`
	JA4O  string `json:"ja4_o"`
	JA4RO string `json:"ja4_ro"`
	// do tshark
	JA3       string `json:"ja3"`
	JA3MD5    string `json:"ja3_md5"`
	TsharkJA4 string `json:"tshark_ja4"`
}

func (s TLSStream) flowKey() string {
	src, _ := netip.ParseAddr(s.Src)
	dst, _ := netip.ParseAddr(s.Dst)
	return FlowKey(netip.AddrPortFrom(src, s.SrcPort), netip.AddrPortFrom(dst, s.DstPort))
}

// keyed indexa os fluxos de um arquivo por 4-tupla e ocorrência (ordem do número do fluxo no tshark);
// fluxos repetidos (mais de um ClientHello no mesmo fluxo) ficam com o primeiro.
func keyed(streams []TLSStream) map[string]TLSStream {
	sort.SliceStable(streams, func(i, j int) bool { return streams[i].Stream < streams[j].Stream })
	out := map[string]TLSStream{}
	occ := map[string]int{}
	last := map[string]int{}
	for _, s := range streams {
		k := s.flowKey()
		if n, ok := last[k]; ok && n == s.Stream {
			continue
		}
		last[k] = s.Stream
		out[flowOccKey(k, occ[k])] = s
		occ[k]++
	}
	return out
}

// TLSGolden lê os gabaritos de testdata/tls: nome do pcap → chave do fluxo (Hello.Key) → valores do ja4
// oficial (ordenado e na ordem original) e do tshark (JA3).
func TLSGolden() (map[string]map[string]TLSStream, error) {
	var ja4 map[string]struct {
		Sorted   []TLSStream `json:"sorted"`
		Original []TLSStream `json:"original"`
	}
	if err := readJSON("testdata/tls/ja4.golden.json", &ja4); err != nil {
		return nil, err
	}
	var ja3 map[string][]TLSStream
	if err := readJSON("testdata/tls/ja3.golden.json", &ja3); err != nil {
		return nil, err
	}
	out := map[string]map[string]TLSStream{}
	for file, g := range ja4 {
		var sorted []TLSStream
		for _, s := range g.Sorted {
			if s.JA4 != "" {
				sorted = append(sorted, s)
			}
		}
		m := keyed(sorted)
		var orig []TLSStream
		for _, s := range g.Original {
			if s.JA4O != "" {
				orig = append(orig, s)
			}
		}
		for k, o := range keyed(orig) {
			s := m[k]
			s.JA4O, s.JA4RO = o.JA4O, o.JA4RO
			m[k] = s
		}
		for k, t := range keyed(ja3[file]) {
			s, ok := m[k]
			if !ok {
				s = TLSStream{Stream: t.Stream, Src: t.Src, Dst: t.Dst, SrcPort: t.SrcPort, DstPort: t.DstPort}
			}
			s.JA3, s.JA3MD5, s.TsharkJA4 = t.JA3, t.JA3MD5, t.TsharkJA4
			m[k] = s
		}
		out["testdata/tls/"+path.Base(file)] = m
	}
	return out, nil
}

func readJSON(name string, v any) error {
	b, err := files.ReadFile(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
