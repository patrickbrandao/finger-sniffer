package store

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// fuzzMaxFrame limita cada frame ao snaplen do capture (o lote real nunca traz frame maior).
const fuzzMaxFrame = 65535

// pcapSeeds lê os três primeiros pacotes (handshake, quase sempre) de cada pcap de testdata/ e de
// test/golden/pcaps, com a direção pelo IP de origem do primeiro pacote (cliente = DirIn).
func pcapSeeds(f *testing.F) [][3][]byte {
	f.Helper()
	var files []string
	for _, dir := range []string{"testdata", filepath.Join("..", "..", "test", "golden", "pcaps")} {
		m, err := filepath.Glob(filepath.Join(dir, "*.pcap"))
		if err != nil {
			f.Fatal(err)
		}
		files = append(files, m...)
	}
	var out [][3][]byte
	for _, file := range files {
		data, err := os.ReadFile(file) //nolint:gosec // pcap de teste do repositório
		if err != nil {
			f.Fatal(err)
		}
		r, err := pcapgo.NewReader(bytes.NewReader(data))
		if err != nil {
			f.Fatalf("%s: %v", file, err)
		}
		var seed [3][]byte
		for i := range seed {
			b, _, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Fatalf("%s: %v", file, err)
			}
			seed[i] = b
		}
		out = append(out, seed)
	}
	return out
}

// FuzzIngestFrame: um lote do capture com 1 a 3 frames arbitrários passa pelo ingest inteiro — parseFrame, tabela
// de fluxos, (*conn).analyze com parseOpts das opções TCP, relógio de timestamps, segmentação, MSS, RTT, pcap e
// gravação no SQLite — e pela finalização, sem pânico nem erro de banco diferente de SQLITE_FULL (task 398).
// dirs escolhe a direção de cada frame (bit i: 1 = saída do espelho) e gapMs o intervalo entre eles.
//
// Um Ingestor novo por execução (o estado em memória de uma entrada não vaza para a seguinte) sobre um banco só,
// aberto uma vez por processo do fuzz: a migração (ou a cópia do banco-modelo) não é paga a cada execução, e os
// conn_id são ULIDs, sem colisão entre execuções.
func FuzzIngestFrame(f *testing.F) {
	cli, srv := client, mirror
	add := func(segs []seg) {
		m := segBatch(cli, srv, segs)
		var frames [3][]byte
		var dirs uint8
		i := 0
		_, _ = event.DecodePackets(m.data, func(p event.Packet) error {
			if i < 3 {
				frames[i] = append([]byte(nil), p.Frame...)
				if p.Dir == event.DirOut {
					dirs |= 1 << i
				}
			}
			i++
			return nil
		})
		f.Add(frames[0], frames[1], frames[2], dirs, uint16(50))
	}
	// Handshake do Linux com opções completas (MSS, SACK, TS, WS), dados com TS e o fechamento, em janelas de 3.
	s := newSession(1000, 5000, 100)
	s.handshake(64)
	s.cliData(200, 300, 64, 102)
	s.srvData(250, 1400)
	s.cliAck(300, 64, 103)
	s.fin(400, 64, 104)
	for i := 0; i < len(s.segs); i += 3 {
		add(s.segs[i:min(i+3, len(s.segs))])
	}
	// Opções estranhas: comprimento 0, opção cortada, EOL com lixo, TS curto, MSS de 1 byte.
	for _, opts := range [][]byte{
		{2, 0}, {8, 10, 0, 0}, {0, 0, 0, 1}, {8, 6, 0, 0, 0, 0}, {2, 3, 5}, {3, 3, 14, 1}, {1, 1, 1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2},
	} {
		add([]seg{{fromCli: true, flags: tcpSYN, seq: 1, win: 1024, opts: opts, ttl: 64, id: 1}})
	}
	// UDP (QUIC sem Initial válido) e IPv6.
	f.Add(frame(cli, srv, protoUDP, 0, 40), frame(srv, cli, protoUDP, 0, 20), []byte(nil), uint8(0b10), uint16(1))
	v6c, v6s := netip.MustParseAddrPort("[2001:db8::1]:40000"), netip.MustParseAddrPort("[2001:db8::2]:8443")
	f.Add(frame(v6c, v6s, protoTCP, tcpSYN, 0), frame(v6s, v6c, protoTCP, tcpSYN|tcpACK, 0), frame(v6c, v6s, protoTCP, tcpACK, 10), uint8(0b010), uint16(10))
	for _, p := range pcapSeeds(f) {
		f.Add(p[0], p[1], p[2], uint8(0b010), uint16(20))
	}

	db, _ := testDB(f)
	cfg := IngestConfig{
		PcapMax: 16 << 20, TCPIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: time.Second,
		MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.Fuzz(func(t *testing.T, a, b, c []byte, dirs uint8, gapMs uint16) {
		in := NewIngestor(db, cfg, log, service.NewMetrics())
		in.now = func() time.Time { return time.Unix(0, base) }
		var buf []byte
		for i, fr := range [][]byte{a, b, c} {
			if i > 0 && len(fr) == 0 {
				continue // 1 a 3 frames: o primeiro sempre vai (mesmo vazio), os outros só se houver bytes
			}
			if len(fr) > fuzzMaxFrame {
				fr = fr[:fuzzMaxFrame]
			}
			dir := event.DirIn
			if dirs&(1<<i) != 0 {
				dir = event.DirOut
			}
			ts := base + int64(i)*int64(gapMs)*int64(time.Millisecond)
			buf = event.AppendPacket(buf, event.Packet{TsNs: ts, Dir: dir, WireLen: uint32(len(fr)), Frame: fr}) //nolint:gosec // ≤ 64 KiB
		}
		ctx := context.Background()
		msg := fakeMsg{subject: event.SubjectCapturePacket, data: buf}
		if err := in.process(ctx, []msgSource{msg}); err != nil && !isDBFull(err) {
			t.Fatalf("process: %v", err)
		}
		// Depois de todo prazo (TCP ocioso, UDP, fechamento): tudo o que abriu é finalizado.
		if err := in.Finalize(ctx, in.flows.due(base+int64(time.Hour))); err != nil && !isDBFull(err) {
			t.Fatalf("finalize: %v", err)
		}
	})
}
