package bot

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// Goldens lidos (só leitura) pelos testes da visão TCP e do QUIC do traefix: os SYNs de test/golden/pcaps (os
// mesmos do teste golden do store) e os Initials do pkg/quicparse (os mesmos do web).
const (
	goldenPcapDir     = "../../test/golden/pcaps"
	goldenInitialsDir = "../../pkg/quicparse/testdata/initials"
)

// goldenSYN é um SYN de cliente de um golden pcap, desde o cabeçalho IP, com o que as referências dizem dele.
type goldenSYN struct {
	port   int
	ip     []byte
	ja4t   string // ja4 da FoxIO (.ja4.jsonl)
	p0fSig string // p0f -r (.p0f.txt), raw_sig
	p0fOS  string // p0f -r, os
}

// loadGoldenSYNs lê os SYNs de cliente do pcap e as referências de JA4T e p0f por porta de origem.
func loadGoldenSYNs(t *testing.T, name string) []goldenSYN {
	t.Helper()
	f, err := os.Open(filepath.Join(goldenPcapDir, name+".pcap")) //nolint:gosec // testdata
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // só leitura
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []goldenSYN
	seen := map[int]bool{}
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		nl := pkt.NetworkLayer()
		tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if nl == nil || !ok || !tcp.SYN || tcp.ACK || seen[int(tcp.SrcPort)] {
			continue
		}
		seen[int(tcp.SrcPort)] = true
		ip := append(append([]byte(nil), nl.LayerContents()...), nl.LayerPayload()...)
		out = append(out, goldenSYN{port: int(tcp.SrcPort), ip: ip})
	}
	byPort := map[int]*goldenSYN{}
	for i := range out {
		byPort[out[i].port] = &out[i]
	}
	if fh, err := os.Open(filepath.Join(goldenPcapDir, name+".ja4.jsonl")); err == nil { //nolint:gosec // testdata
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var j struct {
				SrcPort int    `json:"src_port"`
				JA4T    string `json:"ja4t"`
			}
			if json.Unmarshal(sc.Bytes(), &j) == nil {
				if g := byPort[j.SrcPort]; g != nil && g.ja4t == "" {
					g.ja4t = j.JA4T
				}
			}
		}
		_ = fh.Close()
	}
	if raw, err := os.ReadFile(filepath.Join(goldenPcapDir, name+".p0f.txt")); err == nil { //nolint:gosec // testdata
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, " mod=syn|") {
				continue
			}
			kv := map[string]string{}
			for _, part := range strings.Split(line[strings.Index(line, "mod="):], "|") {
				k, v, _ := strings.Cut(part, "=")
				kv[k] = v
			}
			cli := kv["cli"]
			port, _ := strconv.Atoi(cli[strings.LastIndexByte(cli, '/')+1:])
			if g := byPort[port]; g != nil && g.p0fSig == "" {
				g.p0fSig, g.p0fOS = kv["raw_sig"], kv["os"]
			}
		}
	}
	return out
}

// goldenInitial é o ClientHello de um Initial QUIC golden, como mensagem de handshake pura (a forma do traefix),
// e o JA4 que o pkg/quicparse (o web) e o ja4 da FoxIO dão a ele.
type goldenInitial struct {
	name    string
	message []byte
	webJA4  string
	toolJA4 string
}

// loadGoldenInitials remonta os Initials dos goldens do pkg/quicparse.
func loadGoldenInitials(t *testing.T) []goldenInitial {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(goldenInitialsDir, "*.expected.json"))
	if len(files) == 0 {
		t.Fatal("sem Initials golden")
	}
	var out []goldenInitial
	for _, file := range files {
		b, err := os.ReadFile(file) //nolint:gosec // testdata
		if err != nil {
			t.Fatal(err)
		}
		var exp struct {
			Case       string `json:"case"`
			ClientPort int    `json:"client_port"`
			JA4        string `json:"ja4_tool"`
		}
		if err := json.Unmarshal(b, &exp); err != nil {
			t.Fatal(err)
		}
		a := quicparse.Analyze(initialDatagrams(t, strings.Replace(file, ".expected.json", ".initial.pcap", 1), exp.ClientPort),
			quicparse.Options{})
		if !a.Complete() || a.Info().ClientHello == nil {
			t.Fatalf("%s: Initial incompleto: %v", exp.Case, a.Err())
		}
		out = append(out, goldenInitial{
			name: exp.Case, message: a.ClientHello().Raw, webJA4: a.Info().ClientHello.JA4, toolJA4: exp.JA4,
		})
	}
	return out
}

// initialDatagrams lê os datagramas UDP do cliente (porta de origem port) do pcap.
func initialDatagrams(t *testing.T, file string, port int) [][]byte {
	t.Helper()
	f, err := os.Open(file) //nolint:gosec // testdata
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // só leitura
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			return out
		}
		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		if u, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && int(u.SrcPort) == port {
			out = append(out, append([]byte(nil), u.Payload...))
		}
	}
}
