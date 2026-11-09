package store

import (
	"net/netip"
	"testing"
	"time"
)

// Spec 004 RNF-01 / spec 000 RNF-04 (task 077): o registro TCP sai em ≤ 500 ms do último pacote do fechamento,
// com a folga de produção, e pacotes tardios vão para o registro já gravado.

// closeSegs é uma conexão com seq/ack reais: ISN do cliente 1000, do espelho 5000.
var closeSegs = []seg{
	{ms: 0, fromCli: true, flags: tcpSYN, seq: 1000},
	{ms: 10, flags: tcpSYN | tcpACK, seq: 5000, ack: 1001},
	{ms: 20, fromCli: true, flags: tcpACK, seq: 1001, ack: 5001},
	{ms: 25, fromCli: true, flags: tcpACK | tcpPSH, seq: 1001, ack: 5001, payload: 100},
	{ms: 35, flags: tcpACK | tcpPSH, seq: 5001, ack: 1101, payload: 1000},
	{ms: 40, fromCli: true, flags: tcpACK, seq: 1101, ack: 6001},
	{ms: 1040, fromCli: true, flags: tcpFIN | tcpACK, seq: 1101, ack: 6001},
	{ms: 1050, flags: tcpFIN | tcpACK, seq: 6001, ack: 1102},
	{ms: 1060, fromCli: true, flags: tcpACK, seq: 1102, ack: 6002}, // ACK final
}

func prodGrace(t *testing.T) time.Duration {
	t.Helper()
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return c.Ingest.CloseGrace
}

func TestCloseGraceConfig(t *testing.T) {
	if g := prodGrace(t); g != DefaultCloseGrace || g > 200*time.Millisecond {
		t.Fatalf("CloseGrace de produção = %v", g)
	}
	t.Setenv("FS_TCP_CLOSE_GRACE", "50ms")
	if g := prodGrace(t); g != 50*time.Millisecond {
		t.Fatalf("FS_TCP_CLOSE_GRACE = %v", g)
	}
	t.Setenv("FS_TCP_CLOSE_GRACE", "1s")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("folga acima de 500 ms deveria falhar")
	}
}

// readyAt processa os segmentos com o relógio em atMs e diz se o registro já está fechado e consultável.
func readyAt(t *testing.T, segs []seg, atMs float64) bool {
	t.Helper()
	grace := prodGrace(t)
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.CloseGrace = grace })
	at := base + int64(atMs*1e6)
	in.now = func() time.Time { return time.Unix(0, at) }
	start := time.Now()
	if err := in.process(t.Context(), []msgSource{segBatch(client, mirror, segs)}); err != nil {
		t.Fatal(err)
	}
	if err := in.Finalize(t.Context(), in.flows.due(at)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("process+finalize levou %v", d)
	}
	return count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") == 1
}

func TestRecordReadyAfterClose(t *testing.T) {
	grace := float64(prodGrace(t)) / 1e6
	// ACK final visto: fecha no próprio pacote
	if !readyAt(t, closeSegs, 1060) {
		t.Fatal("com o ACK final o registro sai na hora")
	}
	// sem o ACK final: só depois da folga de produção, bem dentro de 500 ms
	noAck := closeSegs[:len(closeSegs)-1]
	if readyAt(t, noAck, 1050+grace-1) {
		t.Fatal("antes da folga")
	}
	if !readyAt(t, noAck, 1050+grace) || 1050+grace-1050 > 500 {
		t.Fatal("depois da folga")
	}
	// RST: na hora
	rst := append(append([]seg{}, closeSegs[:6]...), seg{ms: 2000, fromCli: true, flags: tcpRST | tcpACK, seq: 1101, ack: 6001})
	if !readyAt(t, rst, 2000) {
		t.Fatal("RST fecha na hora")
	}
}

// Pacotes depois do fechamento (ACK repetido, RST depois do FIN) entram no pcap e no registro gravados, sem
// conexão nova nem pacote avulso; depois da janela voltam a ser tratados como fluxo novo.
func TestLatePacketsAfterClose(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.CloseGrace = prodGrace(t) })
	run(t, in, 1060, segBatch(client, mirror, closeSegs))
	id, r := onlyConn(t, db)
	if r.Ended == nil {
		t.Fatal("registro não fechou")
	}
	late := []seg{
		{ms: 1100, fromCli: true, flags: tcpACK, seq: 1102, ack: 6002},
		{ms: 1200, fromCli: true, flags: tcpRST, seq: 1102},
	}
	run(t, in, 1300, segBatch(client, mirror, late))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("%d conexões", n)
	}
	if n := count(t, db, "SELECT count(*) FROM stray_packets"); n != 0 {
		t.Fatalf("%d avulsos", n)
	}
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 0 {
		t.Fatalf("%d pacotes soltos", n)
	}
	var data []byte
	if err := db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err != nil {
		t.Fatal(err)
	}
	checkPcap(t, data, len(closeSegs)+len(late))
	_, r = onlyConn(t, db)
	if r.Times.ClientRst == nil || r.Totals.In.Segments != 8 || r.Close.By != "client" || r.Close.How != "fin" {
		t.Fatalf("registro não refeito: times %+v totals %+v close %+v", r.Times, r.Totals, r.Close)
	}
	if v := in.metrics.Get("store_late_packets_total"); v != 2 {
		t.Fatalf("store_late_packets_total = %v", v)
	}
}

// Regressão (deploy da 077): SYN recusado com RST vira pacotes avulsos e sai do banco; um RST/ACK tardio na
// mesma 5-tupla não pode derrubar o lote (FOREIGN KEY), nem uma conexão apagada pela retenção.
func TestLatePacketsWithoutStoredConnection(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.CloseGrace = prodGrace(t) })
	refused := []seg{
		{ms: 0, fromCli: true, flags: tcpSYN, seq: 1000},
		{ms: 1, flags: tcpRST | tcpACK, ack: 1001},
	}
	run(t, in, 1, segBatch(client, mirror, refused))
	run(t, in, 100, segBatch(client, mirror, []seg{{ms: 50, flags: tcpRST | tcpACK, ack: 1001}}))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 0 {
		t.Fatalf("%d conexões", n)
	}
	if n := count(t, db, "SELECT count(*) FROM stray_packets"); n != 3 {
		t.Fatalf("%d avulsos", n)
	}

	other := netip.AddrPortFrom(mirror.Addr(), 7701)
	run(t, in, 1060, segBatch(client, other, closeSegs))
	if _, err := db.Exec("DELETE FROM connections"); err != nil {
		t.Fatal(err)
	}
	run(t, in, 1200, segBatch(client, other, []seg{{ms: 1100, fromCli: true, flags: tcpRST, seq: 1102}}))
	if n := count(t, db, "SELECT count(*) FROM connections") + count(t, db, "SELECT count(*) FROM packets"); n != 0 {
		t.Fatalf("%d linhas", n)
	}
	if v := in.metrics.Get("store_late_packets_total"); v != 1 {
		t.Fatalf("store_late_packets_total = %v", v)
	}
}
