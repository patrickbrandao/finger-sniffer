package quicparse

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// initialsExpected é o que a task 050 gravou de cada cliente (tshark 4.4.19 e ja4 0.18.6).
type initialsExpected struct {
	Case                 string   `json:"case"`
	ClientPort           int      `json:"client_port"`
	Version              string   `json:"version"`
	DCID                 string   `json:"dcid"`
	SCID                 string   `json:"scid"`
	TokenLength          int      `json:"token_length"`
	ClientHelloDatagrams int      `json:"client_hello_datagrams"`
	DatagramSizes        []int    `json:"datagram_sizes"`
	JA4                  string   `json:"ja4_tool"`
	JA4R                 string   `json:"ja4_r_tool"`
	TransportParameters  [][3]any `json:"transport_parameters"`
	ClientHello          struct {
		ALPN    []string `json:"alpn"`
		JA3     string   `json:"ja3"`
		JA3Full string   `json:"ja3_full"`
	} `json:"client_hello"`
	ClientInitialDatagrams []struct {
		Packets []struct {
			Type   string `json:"type"`
			Frames []struct {
				Name string `json:"name"`
			} `json:"frames"`
		} `json:"packets"`
	} `json:"client_initial_datagrams"`
	HTTP3 struct {
		ClientHeaders []struct {
			Fields     [][2]string `json:"fields"`
			QPACKBlock string      `json:"qpack_block"`
		} `json:"client_headers"`
	} `json:"http3"`
}

// clientDatagrams lê os datagramas UDP do cliente (porta de origem port) do pcap.
func clientDatagrams(t *testing.T, file string, port int) [][]byte {
	t.Helper()
	f, err := os.Open(file)
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

// TestGoldenInitials: os Initials reais de curl, Chrome, Firefox e quic-go (task 050, em
// testdata/initials) dão o mesmo JA4 q do ja4 oficial e o mesmo cabeçalho, frames, parâmetros de transporte,
// JA3 e HEADERS QPACK que o tshark.
func TestGoldenInitials(t *testing.T) {
	files, _ := filepath.Glob("testdata/initials/*.expected.json")
	if len(files) < 4 {
		t.Fatalf("só %d casos em testdata/initials", len(files))
	}
	for _, file := range files {
		var want initialsExpected
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		t.Run(want.Case, func(t *testing.T) {
			ds := clientDatagrams(t, strings.Replace(file, ".expected.json", ".initial.pcap", 1), want.ClientPort)
			a := Analyze(ds, Options{})
			if !a.Complete() || a.Err() != nil {
				t.Fatalf("incompleto: %v", a.Err())
			}
			in := a.Info()
			ch := in.ClientHello
			if ch.JA4 != want.JA4 || ch.JA4R != want.JA4R {
				t.Errorf("ja4\n got %s %s\nwant %s %s", ch.JA4, ch.JA4R, want.JA4, want.JA4R)
			}
			if ch.JA3 != want.ClientHello.JA3Full || ch.JA3MD5 != want.ClientHello.JA3 ||
				!slices.Equal(ch.ALPN, want.ClientHello.ALPN) {
				t.Errorf("ja3/alpn: %s %s %v", ch.JA3, ch.JA3MD5, ch.ALPN)
			}
			if "0x"+in.Version != want.Version || in.DCIDHex != want.DCID || in.SCIDHex != want.SCID ||
				in.TokenLen != want.TokenLength || in.InitialDatagramSize != want.DatagramSizes[0] ||
				in.ClientHelloDatagrams != want.ClientHelloDatagrams {
				t.Errorf("cabeçalho %+v", in)
			}
			var frames []string
			for _, d := range want.ClientInitialDatagrams[:want.ClientHelloDatagrams] {
				for _, p := range d.Packets {
					if p.Type != "initial" {
						continue
					}
					for _, f := range p.Frames {
						frames = append(frames, f.Name)
					}
				}
			}
			if !slices.Equal(in.InitialFrames, frames) {
				t.Errorf("initial_frames\n got %v\nwant %v", in.InitialFrames, frames)
			}
			if len(in.TransportParams) != len(want.TransportParameters) {
				t.Fatalf("%d transport params, tshark %d", len(in.TransportParams), len(want.TransportParameters))
			}
			for i, p := range in.TransportParams {
				w := want.TransportParameters[i]
				if float64(p.ID) != w[0].(float64) && p.Name != "GREASE" || hex.EncodeToString(p.Value) != w[2] {
					t.Errorf("param %d: got %d %s %x, tshark %v", i, p.ID, p.Name, p.Value, w)
				}
			}
			for _, hh := range want.HTTP3.ClientHeaders {
				_, fs, err := DecodeFieldSection(unhex(hh.QPACKBlock), 0)
				if err != nil {
					t.Fatal(err)
				}
				var got [][2]string
				for _, f := range fs {
					got = append(got, [2]string{f.Name, f.Value})
				}
				if !slices.Equal(got, hh.Fields) {
					t.Errorf("HEADERS\n got %v\nwant %v", got, hh.Fields)
				}
			}
		})
	}
}
