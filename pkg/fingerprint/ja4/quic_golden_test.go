package ja4_test

import (
	"encoding/hex"
	"slices"
	"strconv"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/internal/pcaptest"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// TestGoldenQUIC: o ClientHello remontado dos Initials do cliente (pkg/quicparse) dá o mesmo JA4 `q` que o
// ja4 oficial 0.18.6, e o cabeçalho, os frames, os parâmetros de transporte e o JA3 batem com o tshark 4.4
// (testdata/quic, regen.sh quic).
func TestGoldenQUIC(t *testing.T) {
	pkts, streams, err := pcaptest.QUICGolden()
	if err != nil {
		t.Fatal(err)
	}
	files, err := pcaptest.QUICFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("só %d pcaps QUIC", len(files))
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			ds, err := pcaptest.Datagrams(file)
			if err != nil {
				t.Fatal(err)
			}
			var payloads [][]byte
			for _, d := range ds {
				payloads = append(payloads, d.Payload)
			}
			a := quicparse.Analyze(payloads, quicparse.Options{})
			if !a.Complete() || a.Err() != nil {
				t.Fatalf("ClientHello incompleto: %v", a.Err())
			}
			info := a.Info()
			ch := info.ClientHello

			want := streams[file]
			f := ja4.Compute(a.ClientHello(), ja4.QUIC)
			for _, c := range [][3]string{
				{"ja4", f.JA4, want.JA4},
				{"ja4_r", f.JA4R, want.JA4R},
				{"ja4_o", f.JA4O, want.JA4O},
				{"ja4_ro", f.JA4RO, want.JA4RO},
				{"info.ja4", ch.JA4, want.JA4},
			} {
				if c[1] != c[2] || c[2] == "" {
					t.Errorf("%s:\n got %s\nwant %s", c[0], c[1], c[2])
				}
			}

			g := pkts[file]
			if len(g) == 0 {
				t.Fatal("sem gabarito do tshark")
			}
			first := g[0]
			if info.Version != first.Version || info.DCIDHex != first.DCIDHex || info.SCIDHex != first.SCIDHex ||
				info.TokenLen != first.TokenLen || info.InitialLength != first.Length ||
				info.InitialPacketNumber != first.PacketNumber || info.InitialDatagramSize != first.UDPLength-8 {
				t.Errorf("cabeçalho: got %s %s %s token=%d len=%d pn=%d size=%d; tshark %+v", info.Version,
					info.DCIDHex, info.SCIDHex, info.TokenLen, info.InitialLength, info.InitialPacketNumber,
					info.InitialDatagramSize, first)
			}
			if info.ClientHelloDatagrams != len(g) {
				t.Errorf("client_hello_datagrams = %d, tshark %d", info.ClientHelloDatagrams, len(g))
			}
			var frames []string
			for _, p := range g {
				for _, ft := range p.FrameTypes {
					frames = append(frames, quicparse.FrameName(ft))
				}
			}
			if !slices.Equal(info.InitialFrames, frames) {
				t.Errorf("initial_frames:\n got %v\nwant %v", info.InitialFrames, frames)
			}
			var params [][2]string
			for _, p := range info.TransportParams {
				params = append(params, [2]string{strconv.FormatUint(p.ID, 10), hex.EncodeToString(p.Value)})
			}
			if !slices.Equal(params, first.Params) {
				t.Errorf("transport_params:\n got %v\nwant %v", params, first.Params)
			}
			if ch.JA3 != first.JA3 || ch.JA3MD5 != first.JA3MD5 {
				t.Errorf("ja3: got %s %s, tshark %s %s", ch.JA3, ch.JA3MD5, first.JA3, first.JA3MD5)
			}
			if ch.SNI == nil || *ch.SNI != want.TLSServerName {
				t.Errorf("sni: got %v, ja4 %q", ch.SNI, want.TLSServerName)
			}
		})
	}
}
