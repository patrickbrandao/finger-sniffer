package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// dataBurst são n segmentos de dados do espelho, de 1000 bytes, a partir de ms.
func dataBurst(ms, n int) []pkt {
	out := make([]pkt, n)
	for i := range out {
		out[i] = pkt{ms + i/100, false, tcpACK | tcpPSH, 1000}
	}
	return out
}

// pcapStats conta os registros do pcap e quantos vieram cortados.
func pcapStats(t *testing.T, data []byte) (n, cut int) {
	t.Helper()
	pr, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, ci, err := pr.ReadPacketData()
		if err != nil {
			return n, cut
		}
		n++
		if ci.CaptureLength < ci.Length {
			cut++
		}
	}
}

// TestIngestPcapHeaderBudget: uma conexão com muito mais pacotes que o teto guarda frames inteiros até PcapMax,
// depois só cabeçalhos até mais PcapMax, e o resto fica fora de packets; o BLOB não passa de ~2×PcapMax,
// pcap_truncated fica true e os contadores do registro contam todos os pacotes (task 137, ADR 0034).
func TestIngestPcapHeaderBudget(t *testing.T) {
	const pcapMax, n = 20000, 3000
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.PcapMax = pcapMax })
	// handshake e rajada (até 60 ms); o fechamento de fullTCP vem depois, a partir de 1040 ms
	run(t, in, 0, batch(client, mirror, protoTCP, append(append([]pkt(nil), fullTCP[:3]...), dataBurst(30, n)...)))
	// com a conexão aberta: linhas de packets limitadas pelo orçamento (frames inteiros + só cabeçalhos)
	rows := count(t, db, "SELECT count(*) FROM packets")
	if maxRows := pcapMax/(1054+16) + pcapMax/(54+16) + 8; rows > maxRows {
		t.Fatalf("%d linhas em packets, teto ~%d", rows, maxRows)
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[6:]))
	id, r := onlyConn(t, db)
	var data []byte
	if err := db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if len(data) > 2*pcapMax+24 {
		t.Fatalf("pcap de %d bytes, teto ~%d", len(data), 2*pcapMax+24)
	}
	recs, cut := pcapStats(t, data)
	if cut == 0 || recs >= n || !r.PcapTruncated || count(t, db, "SELECT pcap_truncated FROM connections") != 1 ||
		count(t, db, "SELECT truncated FROM pcaps") != 1 {
		t.Fatalf("registros=%d cortados=%d pcap_truncated=%v", recs, cut, r.PcapTruncated)
	}
	if r.Totals.Out.Segments != n+2 || r.Totals.Out.DataSegments != n || r.Totals.Out.AppBytes != n*1000 || r.Close.How != "fin" {
		t.Fatalf("contadores: %+v close=%+v", r.Totals.Out, r.Close)
	}
}

// TestRecoverOrphansPcapBudget: uma órfã com mais linhas em packets que o orçamento (ex.: gravadas antes do teto)
// é recuperada com o pcap limitado e a marca de truncamento no pcap, na coluna e no registro (task 137).
func TestRecoverOrphansPcapBudget(t *testing.T) {
	const pcapMax = 20000
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.PcapMax = pcapMax })
	run(t, in, 500, batch(client, mirror, protoTCP, append(append([]pkt(nil), fullTCP[:3]...), dataBurst(30, 10)...)))
	id, _ := onlyConn(t, db)
	// 2000 frames inteiros de ~1 KiB a mais, direto no banco: muito além de 2×PcapMax
	if _, err := db.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 1999)
		INSERT INTO packets (conn_id, ts_ns, dir, wire_len, frame) SELECT ?, ? + i, 1, 1054, zeroblob(1054) FROM n`, id, base+int64(1e9)); err != nil {
		t.Fatal(err)
	}
	in2 := NewIngestor(db, in.cfg, in.log, in.metrics)
	if err := in2.recoverOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, r := onlyConn(t, db)
	var data []byte
	_ = db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data)
	if len(data) > 2*pcapMax+24 || !r.PcapTruncated || r.Ended == nil ||
		count(t, db, "SELECT pcap_truncated FROM connections") != 1 || count(t, db, "SELECT truncated FROM pcaps") != 1 {
		t.Fatalf("pcap=%d pcap_truncated=%v", len(data), r.PcapTruncated)
	}
	// órfã pequena, sem corte: a marca continua false
	in3, db3 := newTestIngestor(t, nil)
	run(t, in3, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	if err := NewIngestor(db3, in3.cfg, in3.log, in3.metrics).recoverOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, r := onlyConn(t, db3); r.PcapTruncated || count(t, db3, "SELECT truncated FROM pcaps") != 0 {
		t.Fatal("órfã sem corte marcada como truncada")
	}
}

// capFlagBatch é um lote com os pacotes de batch e as flags do capture em todos.
func capFlagBatch(cli, srv netip.AddrPort, pkts []pkt, flags uint8) fakeMsg {
	var buf []byte
	for _, p := range pkts {
		src, dst, dir := cli, srv, event.DirIn
		if !p.fromCli {
			src, dst, dir = srv, cli, event.DirOut
		}
		f := frame(src, dst, protoTCP, p.flags, p.payload)
		buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(p.ms)*1e6, Dir: dir, Flags: flags, WireLen: uint32(len(f)), Frame: f})
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

// TestFlagsRaceWithLive: o ingest liga truncated/offloadSuspect (flags do capture e teto do pcap) enquanto a API
// lê o registro ao vivo; com -race não há corrida (task 158).
func TestFlagsRaceWithLive(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.PcapMax = 3000 })
	run(t, in, 0, batch(client, mirror, protoTCP, fullTCP[:3]))
	id, _ := onlyConn(t, db)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if r, ok := in.flows.live(id); ok {
				_, _ = json.Marshal(r)
			}
		}
	})
	for i := range 20 {
		run(t, in, 0, capFlagBatch(client, mirror, dataBurst(30+i, 5), event.FlagTruncated|event.FlagOffloadSuspect))
	}
	close(stop)
	wg.Wait()
	r, ok := in.flows.live(id)
	if !ok || !r.PcapTruncated || !r.OffloadSuspect {
		t.Fatalf("live: ok=%v pcap_truncated=%v offload_suspect=%v", ok, r.PcapTruncated, r.OffloadSuspect)
	}
}
