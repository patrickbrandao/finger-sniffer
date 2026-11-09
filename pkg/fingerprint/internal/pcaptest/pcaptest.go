// Package pcaptest lê os pcaps de teste (testdata/syn) e os gabaritos gerados pelas ferramentas oficiais
// (ja4 da FoxIO e p0f -r). Usado só pelos testes dos pacotes de fingerprint; os arquivos vão embutidos para
// que o binário de teste rode fora do repositório (testes linux_priv na vps602).
package pcaptest

import (
	"bufio"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Packet é um segmento TCP encontrado num pcap (a camada IP mais interna, para pcaps com túnel).
type Packet struct {
	// Index é a posição do frame no arquivo, a partir de 1.
	Index int
	// IP vai do início do cabeçalho IP até o fim do frame capturado (inclui o padding do Ethernet).
	IP []byte
	// TCP vai do início do cabeçalho TCP até o fim do frame capturado.
	TCP     []byte
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Flags   uint8
	Version int
	// Tunneled: o TCP está dentro de um túnel (GRE, VXLAN, Geneve…); o p0f não olha esses pacotes.
	Tunneled bool
}

//go:embed testdata/syn/*.pcap testdata/syn/*.pcapng testdata/ja4t.golden.json testdata/p0f.golden.log
//go:embed testdata/tls/*.pcap testdata/tls/*.pcapng testdata/tls/*.json
var files embed.FS

// Files lista os pcaps de testdata/syn em ordem alfabética (caminhos dentro do embed).
func Files() ([]string, error) {
	return glob("testdata/syn/*.pcap", "testdata/syn/*.pcapng")
}

// TLSFiles lista os pcaps de testdata/tls (fluxos com ClientHello) em ordem alfabética.
func TLSFiles() ([]string, error) {
	return glob("testdata/tls/*.pcap", "testdata/tls/*.pcapng")
}

func glob(pats ...string) ([]string, error) {
	var out []string
	for _, pat := range pats {
		m, err := fs.Glob(files, pat)
		if err != nil {
			return nil, err
		}
		out = append(out, m...)
	}
	sort.Strings(out)
	return out, nil
}

type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// Read devolve os segmentos TCP de um pcap ou pcapng, na ordem do arquivo.
func Read(path string) ([]Packet, error) {
	f, err := files.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // só leitura
	// o formato vem do número mágico, não da extensão (alguns .pcap da FoxIO são pcapng)
	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, err
	}
	var src packetSource
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, err
		}
		src = r
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			return nil, err
		}
		src = r
	}
	return readAll(path, src)
}

func readAll(path string, src packetSource) ([]Packet, error) {
	var out []Packet
	for n := 1; ; n++ {
		data, _, err := src.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s frame %d: %w", path, n, err)
		}
		if p, ok := decode(data, src.LinkType()); ok {
			p.Index = n
			out = append(out, p)
		}
	}
}

// decode acha a camada IP mais interna seguida de TCP. Os slices IP e TCP apontam para o próprio frame
// (NoCopy), e a posição deles no frame vem da diferença de capacidade.
func decode(data []byte, lt layers.LinkType) (Packet, bool) {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{NoCopy: true, Lazy: false})
	var p Packet
	ipOff := -1
	ipLayers := 0
	var src, dst netip.Addr
	for _, l := range pkt.Layers() {
		switch v := l.(type) {
		case *layers.IPv4:
			ipLayers++
			ipOff = cap(data) - cap(v.Contents)
			src, _ = netip.AddrFromSlice(v.SrcIP.To4())
			dst, _ = netip.AddrFromSlice(v.DstIP.To4())
			p.Version = 4
		case *layers.IPv6:
			ipLayers++
			ipOff = cap(data) - cap(v.Contents)
			src, _ = netip.AddrFromSlice(v.SrcIP)
			dst, _ = netip.AddrFromSlice(v.DstIP)
			p.Version = 6
		case *layers.TCP:
			if ipOff < 0 {
				return p, false
			}
			tcpOff := cap(data) - cap(v.Contents)
			p.IP = data[ipOff:]
			p.TCP = data[tcpOff:]
			p.Src = netip.AddrPortFrom(src, uint16(v.SrcPort))
			p.Dst = netip.AddrPortFrom(dst, uint16(v.DstPort))
			p.Flags = data[tcpOff+13]
			p.Tunneled = ipLayers > 1
			return p, true
		}
	}
	// TCP truncado (o gopacket não decodifica a camada): procura o cabeçalho logo depois do IP.
	if ipOff >= 0 {
		if dl := pkt.Layer(gopacket.LayerTypeDecodeFailure); dl != nil {
			return truncated(data, ipOff, src, dst, p.Version)
		}
	}
	return p, false
}

func truncated(data []byte, ipOff int, src, dst netip.Addr, ver int) (Packet, bool) {
	ip := data[ipOff:]
	var hl int
	switch {
	case ver == 4 && len(ip) >= 20 && ip[9] == 6:
		hl = int(ip[0]&0x0f) * 4
	case ver == 6 && len(ip) >= 40 && ip[6] == 6:
		hl = 40
	default:
		return Packet{}, false
	}
	if len(ip) < hl+14 {
		return Packet{}, false
	}
	tcp := ip[hl:]
	return Packet{
		IP:      ip,
		TCP:     tcp,
		Src:     netip.AddrPortFrom(src, uint16(tcp[0])<<8|uint16(tcp[1])),
		Dst:     netip.AddrPortFrom(dst, uint16(tcp[2])<<8|uint16(tcp[3])),
		Flags:   tcp[13],
		Version: ver,
	}, true
}

// JA4TStream é uma linha do gabarito do ja4 (um fluxo TCP).
type JA4TStream struct {
	Stream  int    `json:"stream"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	JA4T    string `json:"ja4t"`
}

// Key identifica o fluxo pela 4-tupla.
func (s JA4TStream) Key() string {
	src, _ := netip.ParseAddr(s.Src)
	dst, _ := netip.ParseAddr(s.Dst)
	return FlowKey(netip.AddrPortFrom(src, s.SrcPort), netip.AddrPortFrom(dst, s.DstPort))
}

// FlowKey formata a 4-tupla do cliente para o servidor.
func FlowKey(src, dst netip.AddrPort) string {
	return src.String() + ">" + dst.String()
}

// JA4TGolden lê ja4t.golden.json: arquivo → fluxos com JA4T.
func JA4TGolden() (map[string][]JA4TStream, error) {
	b, err := files.ReadFile("testdata/ja4t.golden.json")
	if err != nil {
		return nil, err
	}
	var raw map[string][]map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string][]JA4TStream, len(raw))
	for file, streams := range raw {
		for _, m := range streams {
			if _, ok := m["ja4t"]; !ok {
				continue
			}
			one, _ := json.Marshal(m)
			var s JA4TStream
			if err := json.Unmarshal(one, &s); err != nil {
				return nil, err
			}
			out[file] = append(out[file], s)
		}
	}
	return out, nil
}

// P0FObs é uma observação syn ou syn+ack do p0f -r.
type P0FObs struct {
	File   string
	Mod    string
	Cli    netip.AddrPort
	Srv    netip.AddrPort
	Fields map[string]string
}

// P0FGolden lê p0f.golden.log (linhas "<arquivo> [data] mod=...|cli=...|...").
func P0FGolden() ([]P0FObs, error) {
	f, err := files.Open("testdata/p0f.golden.log")
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // só leitura
	var out []P0FObs
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		file, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		_, rest, ok = strings.Cut(rest, "] ")
		if !ok {
			return nil, fmt.Errorf("linha do p0f sem data: %q", line)
		}
		o := P0FObs{File: file, Fields: map[string]string{}}
		for kv := range strings.SplitSeq(rest, "|") {
			k, v, _ := strings.Cut(kv, "=")
			o.Fields[k] = v
		}
		o.Mod = o.Fields["mod"]
		if o.Cli, err = parseP0FAddr(o.Fields["cli"]); err != nil {
			return nil, err
		}
		if o.Srv, err = parseP0FAddr(o.Fields["srv"]); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, sc.Err()
}

// parseP0FAddr lê "ip/porta" (o p0f escreve IPv6 sem compressão).
func parseP0FAddr(s string) (netip.AddrPort, error) {
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		return netip.AddrPort{}, fmt.Errorf("endereço do p0f inválido: %q", s)
	}
	a, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, uint16(port)), nil
}
