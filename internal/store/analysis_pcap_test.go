package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Pcaps reais gravados pelo próprio store na vps602 (IP do cliente macOS trocado por 198.51.100.10). Os
// valores esperados vêm das ferramentas de referência sobre os mesmos arquivos: tshark 4.4
// (tcp.analysis.ack_rtt do ACK do handshake, tcp.analysis.retransmission), ja4 da FoxIO e p0f -r 3.09b.
var pcapCases = []struct {
	file      string
	rttMs     float64 // tshark tcp.analysis.ack_rtt do frame 3
	ja4t      string
	p0f       string
	segsIn    int
	segsOut   int
	retxOut   int
	family    int
	clientTTL int
}{
	{
		"macos-http-finretx.pcap", 16.205888, "65535_2-1-3-1-1-8-4-0-0_1430_6",
		"4:48+16:0:1430:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0", 7, 7, 2, 4, 48,
	},
	{
		"linux-https-v4.pcap", 0.016441, "64240_2-4-8-1-3_1460_12",
		"4:128+0:0:1460:mss*44,12:mss,sok,ts,nop,ws:df,id+:0", 15, 10, 0, 4, 128,
	},
	{
		"linux-https-v6.pcap", 0.024071, "64800_2-4-8-1-3_1440_12",
		"6:64+0:0:1440:mss*45,12:mss,sok,ts,nop,ws:flow:0", 17, 14, 0, 6, 64,
	},
}

// pcapBatch lê um pcap e monta um lote FSPB (o sentido não importa para a análise).
func pcapBatch(t *testing.T, path string) fakeMsg {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // testdata
	if err != nil {
		t.Fatal(err)
	}
	r, err := pcapgo.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		buf = event.AppendPacket(buf, event.Packet{TsNs: ci.Timestamp.UnixNano(), Dir: event.DirIn, WireLen: uint32(ci.Length), Frame: data}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

func TestAnalysisRealPcaps(t *testing.T) {
	for _, c := range pcapCases {
		t.Run(c.file, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			msg := pcapBatch(t, filepath.Join("testdata", c.file))
			// os pcaps são de 2026-11-08; o relógio do teste fica depois deles
			run(t, in, 0, msg)
			if err := in.Finalize(t.Context(), in.flows.due(1<<62)); err != nil {
				t.Fatal(err)
			}
			_, rec := onlyConn(t, db)
			tc := rec.TCP
			if tc.RTTHandshakeMs == nil || abs(*tc.RTTHandshakeMs-c.rttMs) >= 0.1 {
				t.Errorf("rtt = %v, tshark = %.6f", tc.RTTHandshakeMs, c.rttMs)
			}
			if tc.JA4T == nil || *tc.JA4T != c.ja4t {
				t.Errorf("ja4t = %v, ja4 = %s", tc.JA4T, c.ja4t)
			}
			if tc.P0F == nil || *tc.P0F != c.p0f {
				t.Errorf("p0f = %v, p0f -r = %s", tc.P0F, c.p0f)
			}
			if rec.Totals.In.Segments != c.segsIn || rec.Totals.Out.Segments != c.segsOut || rec.Totals.Out.Retransmits != c.retxOut ||
				rec.Totals.In.Retransmits != 0 {
				t.Errorf("totais = %+v", rec.Totals)
			}
			if rec.Family != c.family || rec.IP.TTL != c.clientTTL {
				t.Errorf("família/ttl = %d/%d", rec.Family, rec.IP.TTL)
			}
		})
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
