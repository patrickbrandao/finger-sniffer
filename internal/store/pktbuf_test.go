package store

import (
	"context"
	"database/sql"
	"net/netip"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// pktCount soma os pacotes guardados das conexões: os que estão na tabela packets e os do buffer em memória
// (task 248).
func pktCount(t *testing.T, in *Ingestor, db *sql.DB) int {
	t.Helper()
	n := count(t, db, "SELECT count(*) FROM packets")
	for _, c := range in.flows.memConns(in.toFinalize) {
		n += len(c.buf.pkts)
	}
	return n
}

// frameBytes é o tamanho dos frames de uma conversa client <-> mirror.
func frameBytes(pkts []pkt) int64 {
	var n int64
	for _, p := range pkts {
		n += int64(len(frame(client, mirror, protoTCP, p.flags, p.payload)))
	}
	return n
}

func pcapOf(t *testing.T, db *sql.DB, id string) []byte {
	t.Helper()
	var data []byte
	if err := db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err != nil {
		t.Fatal(err)
	}
	return data
}

// TestPacketsStayInMemory: os pacotes da conexão aberta não passam pela tabela packets; a finalização grava o
// pcap direto do buffer e devolve a memória (task 248).
func TestPacketsStayInMemory(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	if count(t, db, "SELECT count(*) FROM packets") != 0 || pktCount(t, in, db) != 6 ||
		in.pktMem != 6*pktOverhead+frameBytes(fullTCP[:6]) {
		t.Fatalf("packets must stay in memory: %d buffered, %d bytes", pktCount(t, in, db), in.pktMem)
	}
	id, _ := onlyConn(t, db)
	// pcap parcial pela API, da memória
	q := NewQueries(db, in.flows.live, 65535).WithLivePcap(in.flows.livePcap)
	part, err := q.Pcap(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	checkPcap(t, part, 6)
	run(t, in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	checkPcap(t, pcapOf(t, db, id), len(fullTCP))
	if in.pktMem != 0 || pktCount(t, in, db) != 0 {
		t.Fatalf("memory must be released after finalize: %d bytes", in.pktMem)
	}
}

// TestPacketsSpillToTable: a conexão que passa do teto do buffer vai para a tabela packets (os pacotes já em
// memória e os seguintes) e o pcap final sai completo e em ordem; o lote desfeito desfaz a cópia.
func TestPacketsSpillToTable(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.pktConnMax = 3*pktOverhead + frameBytes(fullTCP[:3]) // cabem os 3 primeiros
	run(t, in, 30, batch(client, mirror, protoTCP, fullTCP[:3]))
	if count(t, db, "SELECT count(*) FROM packets") != 0 {
		t.Fatal("must still be in memory")
	}
	// lote desfeito: a cópia para a tabela sai com a transação e o buffer volta ao que era
	m := batch(client, mirror, protoTCP, fullTCP[3:5])
	m2 := batch(client2, mirror, protoTCP, fullTCP[:1])
	m.data = append(m.data, m2.data...)
	drop := failOn(t, db, "connections")
	if err := processErr(in, m); err == nil {
		t.Fatal("want error")
	}
	c := in.flows.connByID(func() string { id, _ := onlyConn(t, db); return id }())
	if count(t, db, "SELECT count(*) FROM packets") != 0 || c.buf.spill != spillNone || len(c.buf.pkts) != 3 {
		t.Fatalf("rollback must undo the spill: table %d, state %d, buffered %d", count(t, db, "SELECT count(*) FROM packets"), c.buf.spill, len(c.buf.pkts))
	}
	drop()
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[3:6]))
	if count(t, db, "SELECT count(*) FROM packets") != 6 || c.buf.spill != spillDone || in.pktMem != 0 ||
		in.metrics.Get("store_packet_spills_total") != 1 {
		t.Fatalf("spill: table %d, state %d, mem %d", count(t, db, "SELECT count(*) FROM packets"), c.buf.spill, in.pktMem)
	}
	q := NewQueries(db, in.flows.live, 65535).WithLivePcap(in.flows.livePcap)
	part, err := q.Pcap(t.Context(), c.id)
	if err != nil {
		t.Fatal(err)
	}
	checkPcap(t, part, 6)
	run(t, in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))
	checkPcap(t, pcapOf(t, db, c.id), len(fullTCP))
	if count(t, db, "SELECT count(*) FROM packets") != 0 {
		t.Fatal("packets must be deleted after pcap")
	}
}

// TestPacketsGlobalCap: passado o teto somado, a conexão que chega nele passa para a tabela.
func TestPacketsGlobalCap(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.pktMemMax = 3*pktOverhead + frameBytes(fullTCP[:3])
	run(t, in, 30, batch(client, mirror, protoTCP, fullTCP[:3]), batch(client2, mirror, protoTCP, fullTCP[:3]))
	if count(t, db, "SELECT count(*) FROM packets") != 3 || pktCount(t, in, db) != 6 || in.pktMem > in.pktMemMax {
		t.Fatalf("second connection must spill: table %d, mem %d", count(t, db, "SELECT count(*) FROM packets"), in.pktMem)
	}
}

// TestPacketsSpillOnShutdown: no desligamento, os buffers vão para packets e a recuperação de órfãs do reinício
// monta o pcap com eles.
func TestPacketsSpillOnShutdown(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	in.spillAll()
	if count(t, db, "SELECT count(*) FROM packets") != 6 || in.pktMem != 0 {
		t.Fatal("shutdown must spill the buffers")
	}
	in2 := NewIngestor(db, in.cfg, in.log, service.NewMetrics())
	if err := in2.recoverOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, r := onlyConn(t, db)
	if r.Ended == nil || count(t, db, "SELECT count(*) FROM packets") != 0 {
		t.Fatalf("%+v", r)
	}
	checkPcap(t, pcapOf(t, db, id), 6)
}

// connOf devolve o conn_id da conexão aberta pelo cliente dado.
func connOf(t *testing.T, db *sql.DB, cli netip.AddrPort) string {
	t.Helper()
	var id string
	if err := db.QueryRow("SELECT conn_id FROM connections WHERE src_ip = ? AND src_port = ?", cli.Addr().String(), int(cli.Port())).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// deleteProbeOf põe a conexão no probe e apaga o probe pelo DELETE da API, com o ingest avisado (hide).
func deleteProbeOf(t *testing.T, in *Ingestor, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec("INSERT OR IGNORE INTO probes (probe_id, first_seen, last_seen) VALUES (?, 0, 0)", probeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, id); err != nil {
		t.Fatal(err)
	}
	q := NewQueries(db, in.flows.live, 65535)
	q.SetHideOpen(in.flows.hide, in.flows.unhide)
	if err := q.DeleteProbe(context.Background(), db, probeID); err != nil {
		t.Fatal(err)
	}
	if !in.flows.isHidden(id) {
		t.Fatal("open connection must be hidden")
	}
}

// recoveredPcap reinicia o ingest sobre o banco e devolve o pcap que recoverOrphans montou para a conexão.
func recoveredPcap(t *testing.T, in *Ingestor, db *sql.DB, id string) []byte {
	t.Helper()
	in2 := NewIngestor(db, in.cfg, in.log, service.NewMetrics())
	if err := in2.recoverOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	return pcapOf(t, db, id)
}

// TestSpillAllSkipsDeletedProbe: no desligamento, a conexão aberta de um probe apagado (sem linha em connections)
// não leva junto os pacotes das outras conexões abertas (task 342).
func TestSpillAllSkipsDeletedProbe(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]), batch(client2, mirror, protoTCP, fullTCP[:6]))
	hidden, kept := connOf(t, db, client), connOf(t, db, client2)
	deleteProbeOf(t, in, db, hidden)
	drainDeleted(t, db) // as linhas do probe saem em lotes pelo laço de retenção (ADR 0068)
	if count(t, db, "SELECT count(*) FROM connections WHERE conn_id = ?", hidden) != 0 {
		t.Fatal("hidden connection row must be gone")
	}
	in.spillAll()
	if n := count(t, db, "SELECT count(*) FROM packets WHERE conn_id = ?", kept); n != 6 {
		t.Fatalf("other connection must be spilled: %d packets", n)
	}
	checkPcap(t, recoveredPcap(t, in, db, kept), 6)
}

// TestSpillAllSavepointPerConn: uma conexão que não pode ser gravada no desligamento (linha sumida, FK) fica de
// fora sem desfazer a cópia das outras (task 342).
func TestSpillAllSavepointPerConn(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]), batch(client2, mirror, protoTCP, fullTCP[:6]))
	gone, kept := connOf(t, db, client), connOf(t, db, client2)
	if _, err := db.Exec("DELETE FROM connections WHERE conn_id = ?", gone); err != nil {
		t.Fatal(err)
	}
	in.spillAll()
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 6 {
		t.Fatalf("only the stored connection must be spilled: %d packets", n)
	}
	checkPcap(t, recoveredPcap(t, in, db, kept), 6)
}

// TestHiddenBufferReleased: o buffer da conexão aberta de um probe apagado é liberado no fim do lote seguinte, e
// pktMem volta ao que era antes dela (task 342).
func TestHiddenBufferReleased(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client2, mirror, protoTCP, fullTCP[:6]))
	before := in.pktMem
	run(t, in, 600, batch(client, mirror, protoTCP, fullTCP[:6]))
	if in.pktMem <= before {
		t.Fatal("second connection must be buffered")
	}
	deleteProbeOf(t, in, db, connOf(t, db, client))
	run(t, in, 700, batch(client, mirror, protoTCP, fullTCP[5:6])) // descartado (oculta), fecha o lote
	if in.pktMem != before {
		t.Fatalf("hidden buffer must be released: %d bytes, want %d", in.pktMem, before)
	}
	in.spillAll()
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 6 {
		t.Fatalf("shutdown spill: %d packets", n)
	}
}
