package quicgolden_test

// Conferência dos golden de Initials QUIC da task 050. O teste não usa código do projeto: ele garante que os
// arquivos gerados por collect.sh são coerentes entre si antes de servirem de gabarito para pkg/quicparse e para o
// store. Confere:
//   - os quatro clientes da tarefa (curl, Go/quic-go, Chrome e Firefox) estão presentes, com pelo menos um
//     ClientHello em 2 datagramas e um com CRYPTO fora de ordem;
//   - por conexão: JA4 "q" do ja4 da FoxIO igual ao do tshark, também sobre o primeiro voo sozinho; os frames
//     CRYPTO cobrem o ClientHello inteiro sem buracos; datagramas do cliente com pelo menos 1200 bytes; parâmetros
//     de transporte presentes e GREASE só nos ids 31*N+27;
//   - a cópia mínima em initials/ (e em pkg/quicparse/testdata/initials, se existir, idêntica) bate com o
//     ref.json e o pcap do primeiro voo tem os
//     mesmos datagramas (tamanho, versão, DCID e SCID do cabeçalho longo) que o tshark dissecou;
//   - nenhum endereço IP fora do servidor de testes e dos endereços de documentação.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	pcapsDir    = "pcaps"
	initialsDir = "initials"
	pkgInitials = "../../../pkg/quicparse/testdata/initials"
	serverPort  = 7703
	wantSNI     = "vps602.tmsoft.com.br"
)

var cases = []string{"curl", "go", "chrome", "firefox"}

// endereços permitidos nos pcaps: a vps602 e os de documentação que substituem o IP da máquina de teste
var allowedIPs = map[netip.Addr]bool{
	netip.MustParseAddr("172.233.24.85"): true,
	netip.MustParseAddr("198.51.100.10"): true,
	netip.MustParseAddr("2001:db8::10"):  true,
}

type packet struct {
	Type   string `json:"type"`
	DCID   string `json:"dcid"`
	SCID   string `json:"scid"`
	Ver    string `json:"version"`
	Frames []struct {
		Name string `json:"name"`
	} `json:"frames"`
}

type datagram struct {
	Frame   int      `json:"frame"`
	Length  int      `json:"udp_payload_length"`
	Packets []packet `json:"packets"`
}

type conn struct {
	ClientPort  int        `json:"client_port"`
	Version     string     `json:"version"`
	DCID        string     `json:"dcid"`
	SCID        string     `json:"scid"`
	CHDatagrams int        `json:"client_hello_datagrams"`
	Sizes       []int      `json:"datagram_sizes"`
	Crypto      [][2]int   `json:"crypto_frames"`
	OutOfOrder  bool       `json:"crypto_out_of_order"`
	CryptoLen   int        `json:"crypto_length"`
	ClientDgs   []datagram `json:"client_initial_datagrams"`
	ServerDgs   []datagram `json:"server_initial_datagrams"`
	TPs         [][3]any   `json:"transport_parameters"`
	JA4Tool     string     `json:"ja4_tool"`
	ClientHello struct {
		Length     int      `json:"handshake_length"`
		JA4        string   `json:"ja4_tshark"`
		JA3        string   `json:"ja3"`
		SNI        string   `json:"sni"`
		ALPN       []string `json:"alpn"`
		Extensions []int    `json:"extensions"`
	} `json:"client_hello"`
}

type ref struct {
	Case        string `json:"case"`
	Client      string `json:"client"`
	Connections []conn `json:"connections"`
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func loadRef(t *testing.T, name string) ref {
	t.Helper()
	var r ref
	loadJSON(t, filepath.Join(pcapsDir, name+".ref.json"), &r)
	if len(r.Connections) == 0 {
		t.Fatalf("%s: sem conexão QUIC com ClientHello", name)
	}
	return r
}

// ja4 por porta de origem do cliente, de um .ja4.jsonl
func ja4ByPort(t *testing.T, path string) map[int]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[int]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l struct {
			Transport string `json:"transport"`
			SrcPort   int    `json:"src_port"`
			JA4       string `json:"ja4"`
		}
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if l.Transport == "udp" {
			out[l.SrcPort] = l.JA4
		}
	}
	return out
}

func TestCoverage(t *testing.T) {
	multi, ooo := false, false
	for _, name := range cases {
		r := loadRef(t, name)
		if r.Client == "" {
			t.Errorf("%s: ref.json sem descrição do cliente", name)
		}
		for _, c := range r.Connections {
			multi = multi || c.CHDatagrams >= 2
			ooo = ooo || c.OutOfOrder
		}
	}
	if !multi {
		t.Error("nenhum ClientHello em 2 ou mais datagramas")
	}
	if !ooo {
		t.Error("nenhum ClientHello com CRYPTO fora de ordem")
	}
	// o Chrome com ML-KEM é o caso de referência para os 2 datagramas
	if c := loadRef(t, "chrome").Connections[0]; c.CHDatagrams < 2 || !c.OutOfOrder {
		t.Errorf("chrome: client_hello_datagrams=%d fora_de_ordem=%v; esperado 2+ e fora de ordem", c.CHDatagrams, c.OutOfOrder)
	}
}

func TestConnections(t *testing.T) {
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			r := loadRef(t, name)
			full := ja4ByPort(t, filepath.Join(pcapsDir, name+".ja4.jsonl"))
			first := ja4ByPort(t, filepath.Join(pcapsDir, name+".initial.ja4.jsonl"))
			for i, c := range r.Connections {
				checkConn(t, c)
				if full[c.ClientPort] != c.JA4Tool {
					t.Errorf("conexão %d: ja4_tool %q, ja4.jsonl %q", i, c.JA4Tool, full[c.ClientPort])
				}
				if i == 0 && first[c.ClientPort] != c.JA4Tool {
					t.Errorf("ja4 sobre o primeiro voo %q, sobre a captura %q", first[c.ClientPort], c.JA4Tool)
				}
			}
		})
	}
}

func checkConn(t *testing.T, c conn) {
	t.Helper()
	if !strings.HasPrefix(c.JA4Tool, "q13") || c.JA4Tool != c.ClientHello.JA4 {
		t.Errorf("JA4: ja4 %q, tshark %q", c.JA4Tool, c.ClientHello.JA4)
	}
	if c.ClientHello.JA3 == "" {
		t.Error("sem JA3 do tshark")
	}
	if c.ClientHello.SNI != wantSNI {
		t.Errorf("SNI %q", c.ClientHello.SNI)
	}
	if len(c.ClientHello.ALPN) == 0 || c.ClientHello.ALPN[0] != "h3" {
		t.Errorf("ALPN %v", c.ClientHello.ALPN)
	}
	if c.Version != "0x00000001" {
		t.Errorf("versão %s", c.Version)
	}
	if len(c.DCID) < 16 {
		t.Errorf("DCID %q com menos de 8 bytes (RFC 9000 7.2)", c.DCID)
	}

	// CRYPTO: cobre [0, handshake+4) sem buraco
	if c.CryptoLen != c.ClientHello.Length+4 {
		t.Errorf("crypto_length %d, ClientHello %d+4", c.CryptoLen, c.ClientHello.Length)
	}
	covered := make([]bool, c.CryptoLen)
	for _, f := range c.Crypto {
		for i := f[0]; i < f[0]+f[1] && i < len(covered); i++ {
			covered[i] = true
		}
	}
	for i, ok := range covered {
		if !ok {
			t.Errorf("CRYPTO sem o byte %d", i)
			break
		}
	}

	// datagramas do cliente: completos até o ClientHello e com padding a 1200 (RFC 9000 14.1)
	if c.CHDatagrams != len(c.ClientDgs) || c.CHDatagrams != len(c.Sizes) {
		t.Errorf("client_hello_datagrams %d, datagramas %d, tamanhos %d", c.CHDatagrams, len(c.ClientDgs), len(c.Sizes))
	}
	for i, s := range c.Sizes {
		if s < 1200 {
			t.Errorf("datagrama %d com %d bytes", i, s)
		}
	}
	if len(c.ServerDgs) == 0 {
		t.Error("sem Initial do servidor")
	}

	// parâmetros de transporte
	hasTP := false
	for _, e := range c.ClientHello.Extensions {
		hasTP = hasTP || e == 57
	}
	if !hasTP || len(c.TPs) == 0 {
		t.Errorf("sem quic_transport_parameters (0x39): extensões %v, %d parâmetros", c.ClientHello.Extensions, len(c.TPs))
	}
	for _, tp := range c.TPs {
		id, _ := tp[0].(float64)
		name, _ := tp[1].(string)
		// float64 perde precisão nos ids GREASE grandes; a regra 31*N+27 é conferida só nos ids exatos
		if name == "GREASE" && id < 1<<53 && (uint64(id)-27)%31 != 0 {
			t.Errorf("GREASE com id %v fora de 31*N+27", id)
		}
		if _, err := hex.DecodeString(tp[2].(string)); err != nil {
			t.Errorf("valor de %s não é hex: %v", name, err)
		}
	}
}

func TestMinimalCopy(t *testing.T) {
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			r := loadRef(t, name)
			var exp map[string]any
			loadJSON(t, filepath.Join(initialsDir, name+".expected.json"), &exp)
			var raw struct {
				Connections []map[string]any `json:"connections"`
			}
			loadJSON(t, filepath.Join(pcapsDir, name+".ref.json"), &raw)
			want := raw.Connections[0]
			want["case"], want["client"] = r.Case, r.Client
			if !reflect.DeepEqual(exp, want) {
				t.Error("expected.json difere da primeira conexão do ref.json")
			}

			c := r.Connections[0]
			dgs := readUDP(t, filepath.Join(initialsDir, name+".initial.pcap"))
			var client [][]byte
			for _, d := range dgs {
				if d.dst == serverPort {
					client = append(client, d.payload)
				}
			}
			if len(client) < c.CHDatagrams {
				t.Fatalf("primeiro voo com %d datagramas do cliente, ClientHello em %d", len(client), c.CHDatagrams)
			}
			for i := 0; i < c.CHDatagrams; i++ {
				checkLongHeader(t, i, client[i], c, c.Sizes[i])
			}
			if len(dgs) == len(client) {
				t.Error("primeiro voo sem datagrama do servidor")
			}
		})
	}
}

// checkLongHeader confere o cabeçalho longo do primeiro pacote do datagrama (RFC 9000 17.2), que não é protegido
// além dos 4 bits baixos do primeiro byte.
func checkLongHeader(t *testing.T, i int, b []byte, c conn, size int) {
	t.Helper()
	if len(b) != size {
		t.Errorf("datagrama %d: %d bytes no pcap, %d no tshark", i, len(b), size)
	}
	if len(b) < 7 || b[0]&0xc0 != 0xc0 || (b[0]>>4)&3 != 0 {
		t.Fatalf("datagrama %d não começa com Initial de cabeçalho longo", i)
	}
	if v := binary.BigEndian.Uint32(b[1:5]); v != 1 {
		t.Errorf("datagrama %d: versão %#x", i, v)
	}
	dl := int(b[5])
	if len(b) < 7+dl {
		t.Fatalf("datagrama %d curto", i)
	}
	dcid := hex.EncodeToString(b[6 : 6+dl])
	sl := int(b[6+dl])
	if len(b) < 7+dl+sl {
		t.Fatalf("datagrama %d curto", i)
	}
	scid := hex.EncodeToString(b[7+dl : 7+dl+sl])
	if dcid != c.DCID || scid != c.SCID {
		t.Errorf("datagrama %d: DCID %s SCID %s; tshark %s %s", i, dcid, scid, c.DCID, c.SCID)
	}
}

// TestPkgCopy confere que a cópia em pkg/quicparse/testdata/initials, quando existe, é a mesma de initials/.
func TestPkgCopy(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(pkgInitials, "*"))
	if len(files) == 0 {
		t.Skip("pkg/quicparse/testdata/initials ainda não existe (task 049)")
	}
	for _, f := range files {
		got, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(initialsDir, filepath.Base(f)))
		if err != nil {
			t.Errorf("%s sem par em initials/: %v", f, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s difere de initials/", f)
		}
	}
}

func TestNoPersonalData(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(pcapsDir, "*.pcap"))
	more, _ := filepath.Glob(filepath.Join(initialsDir, "*.pcap"))
	files = append(files, more...)
	if len(files) < 2*len(cases) {
		t.Fatalf("só %d pcaps", len(files))
	}
	for _, f := range files {
		for _, d := range readUDP(t, f) {
			for _, a := range []netip.Addr{d.src, d.dstIP} {
				if !allowedIPs[a] {
					t.Errorf("%s: endereço %s fora do servidor de testes e da documentação", f, a)
				}
			}
		}
	}
	for _, name := range cases {
		for _, c := range loadRef(t, name).Connections {
			if c.ClientHello.SNI != wantSNI {
				t.Errorf("%s: SNI %q", name, c.ClientHello.SNI)
			}
		}
	}
}

type udpDatagram struct {
	src, dstIP netip.Addr
	dst        int
	payload    []byte
}

// readUDP lê um pcap libpcap (little-endian, Ethernet) e devolve os datagramas UDP em ordem.
func readUDP(t *testing.T, path string) []udpDatagram {
	t.Helper()
	d, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) < 24 || !bytes.Equal(d[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) || binary.LittleEndian.Uint32(d[20:24]) != 1 {
		t.Fatalf("%s: não é pcap libpcap little-endian Ethernet", path)
	}
	var out []udpDatagram
	for o := 24; o+16 <= len(d); {
		cl := int(binary.LittleEndian.Uint32(d[o+8 : o+12]))
		fr := d[o+16 : o+16+cl]
		o += 16 + cl
		if len(fr) < 14 {
			t.Fatalf("%s: quadro curto", path)
		}
		eth, ip := binary.BigEndian.Uint16(fr[12:14]), fr[14:]
		var u udpDatagram
		var l4 []byte
		switch eth {
		case 0x0800:
			ihl := int(ip[0]&15) * 4
			if ip[9] != 17 {
				t.Fatalf("%s: IPv4 sem UDP", path)
			}
			u.src, _ = netip.AddrFromSlice(ip[12:16])
			u.dstIP, _ = netip.AddrFromSlice(ip[16:20])
			l4 = ip[ihl:binary.BigEndian.Uint16(ip[2:4])]
		case 0x86dd:
			if ip[6] != 17 {
				t.Fatalf("%s: IPv6 sem UDP", path)
			}
			u.src, _ = netip.AddrFromSlice(ip[8:24])
			u.dstIP, _ = netip.AddrFromSlice(ip[24:40])
			l4 = ip[40 : 40+binary.BigEndian.Uint16(ip[4:6])]
		default:
			t.Fatalf("%s: ethertype %#x", path, eth)
		}
		u.dst = int(binary.BigEndian.Uint16(l4[2:4]))
		u.payload = l4[8:binary.BigEndian.Uint16(l4[4:6])]
		out = append(out, u)
	}
	return out
}
