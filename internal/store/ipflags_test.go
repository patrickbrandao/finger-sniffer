package store

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Task 081: flags do capture, TOS/ECN do primeiro segmento com dados, IPv6 com extensões e RST que termina um
// meio-fechamento.

// flaggedBatch é segBatch com as flags FSPB por segmento.
func flaggedBatch(cli, srv netip.AddrPort, segs []seg, flags []uint8) fakeMsg {
	var buf []byte
	for i, s := range segs {
		src, dst, dir := cli, srv, event.DirIn
		if !s.fromCli {
			src, dst, dir = srv, cli, event.DirOut
		}
		f := tcpFrame(src, dst, s)
		buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(s.ms*1e6), Dir: dir, Flags: flags[i], WireLen: uint32(len(f)), Frame: f}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

func TestOffloadSuspectAndTruncatedFlags(t *testing.T) {
	for _, c := range []struct {
		name            string
		flag            uint8
		offload, pcapTr bool
	}{
		{"sem flags", 0, false, false},
		{"offload", event.FlagOffloadSuspect, true, false},
		{"truncado", event.FlagTruncated, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			flags := make([]uint8, len(closeSegs))
			flags[4] = c.flag // um segmento de dados do espelho
			run(t, in, 1060, flaggedBatch(client, mirror, closeSegs, flags))
			_, r := onlyConn(t, db)
			if r.OffloadSuspect != c.offload || r.PcapTruncated != c.pcapTr {
				t.Fatalf("offload_suspect=%v pcap_truncated=%v", r.OffloadSuspect, r.PcapTruncated)
			}
		})
	}
}

// ECN negociado: SYN not-ect (RFC 3168 proíbe ECT no SYN) e dados ECT(0); TTL continua o do SYN.
func TestIPInfoFromFirstDataSegment(t *testing.T) {
	segs := append([]seg{}, closeSegs...)
	segs[0].ttl, segs[0].tos = 50, 0x00
	segs[3].ttl, segs[3].tos = 49, 0xb8|0x02 // EF + ECT(0) na requisição
	segs[5].tos = 0x03                       // CE depois: não muda
	in, db := newTestIngestor(t, nil)
	run(t, in, 1060, segBatch(client, mirror, segs))
	_, r := onlyConn(t, db)
	if r.IP.TTL != 50 || r.IP.ECN != "ect0" || r.IP.TOS != 0xba || r.IP.DSCP != 46 {
		t.Fatalf("ip %+v", r.IP)
	}

	// pcap real (curl no macOS com ECN negociado): o frame 4 (ClientHello) vem com dsfield 0x02
	in, db = newTestIngestor(t, nil)
	run(t, in, 0, pcapBatch(t, filepath.Join("testdata", "macos-https-keepalive.pcap")))
	if err := in.Finalize(t.Context(), in.flows.due(1<<62)); err != nil {
		t.Fatal(err)
	}
	_, r = onlyConn(t, db)
	if r.IP.ECN != "ect0" || r.IP.TOS != 2 || r.IP.TTL != 46 {
		t.Fatalf("pcap ip %+v", r.IP)
	}
}

func TestIPv6ExtensionHeaders(t *testing.T) {
	cli6 := netip.MustParseAddrPort("[2001:db8::10]:41234")
	srv6 := netip.MustParseAddrPort("[2001:db8::85]:7700")
	build := func(withFrag bool, fragOff uint16) fakeMsg {
		var buf []byte
		for i, s := range closeSegs {
			src, dst, dir := cli6, srv6, event.DirIn
			if !s.fromCli {
				src, dst, dir = srv6, cli6, event.DirOut
			}
			f := tcpFrame(src, dst, s)
			if s.fromCli && i == 3 {
				// Hop-by-Hop (8 B, PadN) + Fragment (8 B) antes do TCP
				hbh := []byte{protoTCP, 0, 1, 4, 0, 0, 0, 0}
				ext := hbh
				if withFrag {
					hbh[0] = ipv6Fragment
					fr := []byte{protoTCP, 0, 0, 0, 0, 0, 0, 42}
					binary.BigEndian.PutUint16(fr[2:4], fragOff)
					ext = append(append([]byte{}, hbh...), fr...)
				}
				ip := f[14:54]
				ip[6] = ipv6HopByHop
				binary.BigEndian.PutUint16(ip[4:6], binary.BigEndian.Uint16(ip[4:6])+uint16(len(ext))) //nolint:gosec // teste
				f = append(append(append([]byte{}, f[:54]...), ext...), f[54:]...)
			}
			buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(s.ms*1e6), Dir: dir, WireLen: uint32(len(f)), Frame: f}) //nolint:gosec // teste
		}
		return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
	}
	for _, c := range []struct {
		name     string
		frag     bool
		off      uint16
		fragment bool
		inBytes  int64
	}{
		{"hop-by-hop", false, 0, false, 100},
		{"fragmento inicial", true, 1, true, 100}, // M=1, deslocamento 0
		// sem cabeçalho L4 não há como achar a conexão (como no IPv4): vira avulso
		{"fragmento não inicial", true, 8 << 3, false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			run(t, in, 1060, build(c.frag, c.off))
			_, r := onlyConn(t, db)
			if r.IP.Fragmented != c.fragment || r.Totals.In.AppBytes != c.inBytes || r.Totals.In.Segments != 6-boolToInt(c.inBytes == 0) ||
				count(t, db, "SELECT count(*) FROM stray_packets") != boolToInt(c.inBytes == 0) {
				t.Fatalf("fragmented=%v in=%+v", r.IP.Fragmented, r.Totals.In)
			}
		})
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Cliente raw faz close() sem shutdown: FIN, o espelho manda os dados do meio-fechamento, o cliente responde RST e
// o espelho nunca manda FIN. Pcap real da vps602 (IP do cliente trocado por 198.51.100.10).
func TestCloseRSTEndsHalfClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 0, pcapBatch(t, filepath.Join("testdata", "raw-close-rst.pcap")))
	if err := in.Finalize(t.Context(), in.flows.due(1<<62)); err != nil {
		t.Fatal(err)
	}
	_, r := onlyConn(t, db)
	if r.Close.By != "client" || r.Close.How != "rst" || !r.Close.HalfClose || r.Times.ClientRst == nil || r.Times.ServerFin != nil {
		t.Fatalf("close %+v times %+v", r.Close, r.Times)
	}
	// os dois lados mandaram FIN e o RST veio depois: continua fin (TestLatePacketsAfterClose)
}
