package store

import (
	"context"
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Falhas de transação no ingest (ADR 0034 itens 6 e 10; tasks 139, 157 e 182).

var client2 = netip.MustParseAddrPort("192.0.2.11:41235")

// failOn cria um gatilho que aborta todo INSERT na tabela (falha de SQL injetada); devolve o que o remove.
func failOn(t *testing.T, db *sql.DB, table string) func() {
	t.Helper()
	name := "fail_" + table
	if _, err := db.Exec("CREATE TRIGGER " + name + " BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	return func() {
		if _, err := db.Exec("DROP TRIGGER " + name); err != nil {
			t.Fatal(err)
		}
	}
}

func processErr(in *Ingestor, msgs ...fakeMsg) error {
	src := make([]msgSource, len(msgs))
	for i, m := range msgs {
		src[i] = m
	}
	return in.process(context.Background(), src)
}

// TestPacketSQLErrorAbortsBatch: erro de SQL de um pacote não é "lote ruim": a transação inteira é desfeita
// (Nak), a conexão seguinte do mesmo lote não fica gravada pela metade e os pacotes do lote saem do buffer em
// memória (task 248).
func TestPacketSQLErrorAbortsBatch(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 30, batch(client, mirror, protoTCP, fullTCP[:3]))
	m := batch(client, mirror, protoTCP, fullTCP[3:4])
	m2 := batch(client2, mirror, protoTCP, fullTCP[:3])
	m.data = append(m.data, m2.data...)
	drop := failOn(t, db, "connections") // o INSERT da conexão nova falha depois do pacote da primeira
	if err := processErr(in, m); err == nil {
		t.Fatal("SQL error must abort the batch")
	}
	if in.metrics.Get("store_bad_batches_total") != 0 {
		t.Fatal("SQL error counted as bad batch")
	}
	if count(t, db, "SELECT count(*) FROM connections") != 1 || pktCount(t, in, db) != 3 || in.pktMem != 3*pktOverhead+frameBytes(fullTCP[:3]) {
		t.Fatalf("rolled back batch left rows or buffered packets: %d packets, %d bytes", pktCount(t, in, db), in.pktMem)
	}
	drop()
	if err := processErr(in, m); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections") != 2 || pktCount(t, in, db) != 7 {
		t.Fatalf("redelivery: %d packets", pktCount(t, in, db))
	}
}

// TestRollbackReinsertsConnection: o lote que criou a conexão falha depois do INSERT dela; a reentrega do mesmo
// lote grava a linha e os pacotes (sem violar a FK) e não conta a conexão duas vezes.
func TestRollbackReinsertsConnection(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	m := batch(client, mirror, protoTCP, fullTCP[:3])
	// RST sem conexão vira avulso: o INSERT em stray_packets falha depois do da conexão.
	rst := batch(netip.MustParseAddrPort("192.0.2.77:4000"), mirror, protoTCP, []pkt{{30, true, tcpRST, 0}})
	drop := failOn(t, db, "stray_packets")
	if err := processErr(in, m, rst); err == nil {
		t.Fatal("want error")
	}
	if count(t, db, "SELECT count(*) FROM connections") != 0 || in.flows.open() != 0 || in.flows.reservations() != 1 {
		t.Fatal("rollback must undo the flow, keep its ID reserved and drop the row")
	}
	var id string
	for _, r := range in.flows.reserved {
		id = r.id
	}
	drop()
	if err := processErr(in, m, rst); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if got, _ := onlyConn(t, db); got != id {
		t.Fatalf("conn_id %s, want the one from the failed batch %s", got, id)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL") != 1 || pktCount(t, in, db) != 3 {
		t.Fatalf("connections %d packets %d", count(t, db, "SELECT count(*) FROM connections"), pktCount(t, in, db))
	}
	if in.metrics.Get("store_connections_total") != 1 {
		t.Fatalf("connections_total %v", in.metrics.Get("store_connections_total"))
	}
	// O resto da conversa chega e a conexão fecha normalmente.
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[3:]))
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") != 1 || count(t, db, "SELECT count(*) FROM pcaps") != 1 {
		t.Fatal("connection not finalized")
	}
}

// TestRollbackUndoesEventOnly: a conexão só de eventos criada pelo lote desfeito some da memória; a reentrega a
// cria de novo (sem isso, o evento iria para um conn_id sem linha e o lote falharia em laço).
func TestRollbackUndoesEventOnly(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	ev := appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 0, "", http1Payload(0, "HTTP/1.1"))
	processAt(t, in, 0, ev) // sem conexão: fica pendente
	drop := failOn(t, db, "stray_packets")
	rst := batch(netip.MustParseAddrPort("192.0.2.77:4000"), mirror, protoTCP, []pkt{{2500, true, tcpRST, 0}})
	in.now = func() time.Time { return time.Unix(0, base+2500e6) }
	if err := processErr(in, rst); err == nil {
		t.Fatal("want error")
	}
	if len(in.eventOnly) != 0 || len(in.pending) != 1 {
		t.Fatalf("eventOnly %d pending %d", len(in.eventOnly), len(in.pending))
	}
	drop()
	processAt(t, in, 2500, rst)
	if count(t, db, "SELECT count(*) FROM connections") != 1 || count(t, db, "SELECT count(*) FROM app_events") != 1 {
		t.Fatal("event-only connection not recreated once")
	}
}

// TestRollbackReloadsOpenAppState: eventos aplicados a uma conexão aberta num lote desfeito não contam duas vezes
// depois da reentrega.
func TestRollbackReloadsOpenAppState(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 30, batch(client, mirror, protoTCP, fullTCP[:3]))
	req := appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 25, "", http1Payload(0, "HTTP/1.1"))
	rst := batch(netip.MustParseAddrPort("192.0.2.77:4000"), mirror, protoTCP, []pkt{{30, true, tcpRST, 0}})
	drop := failOn(t, db, "stray_packets")
	if err := processErr(in, req, rst); err == nil {
		t.Fatal("want error")
	}
	drop()
	if err := processErr(in, req, rst); err != nil {
		t.Fatal(err)
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP[3:]))
	_, r := onlyConn(t, db)
	if len(r.HTTP) != 1 {
		t.Fatalf("http requests %d, want 1", len(r.HTTP))
	}
}

// TestFinalizeRetriedOneByOne: a finalização que falha não perde as conexões; na nova tentativa cada uma vai
// numa transação, e a que continua falhando não impede as outras.
func TestFinalizeRetriedOneByOne(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	if err := processErr(in, batch(client, mirror, protoTCP, fullTCP), batch(client2, mirror, protoTCP, fullTCP)); err != nil {
		t.Fatal(err)
	}
	var bad string
	if err := db.QueryRow("SELECT conn_id FROM connections WHERE src_port = ?", int(client.Port())).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_one BEFORE INSERT ON pcaps WHEN NEW.conn_id = '" + bad + "' BEGIN SELECT RAISE(ABORT, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if err := in.Finalize(t.Context(), in.flows.due(base+5000e6)); err == nil {
		t.Fatal("want error")
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL") != 2 || len(in.toFinalize) != 2 {
		t.Fatal("both must stay queued and open")
	}
	if !in.flows.tracked(bad) {
		t.Fatal("queued connection must stay tracked (no orphan purge)")
	}
	// Nova tentativa, uma a uma: a outra passa, a ruim volta para a fila.
	if err := in.finalizeQueued(t.Context()); err == nil {
		t.Fatal("want error")
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") != 1 || len(in.toFinalize) != 1 {
		t.Fatal("the good one must be finalized")
	}
	if in.metrics.Get("store_finalize_retries_total") != 2 || in.metrics.Get("store_ingest_errors_total") != 2 {
		t.Fatalf("retries %v errors %v", in.metrics.Get("store_finalize_retries_total"), in.metrics.Get("store_ingest_errors_total"))
	}
	if _, err := db.Exec("DROP TRIGGER fail_one"); err != nil {
		t.Fatal(err)
	}
	if err := in.finalizeQueued(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL") != 0 || count(t, db, "SELECT count(*) FROM packets") != 0 ||
		count(t, db, "SELECT count(*) FROM pcaps") != 2 || len(in.toFinalize) != 0 || in.flows.tracked(bad) {
		t.Fatal("retry must finalize the connection")
	}
}

// TestFinalizeGivesUp: depois de maxFinalizeTries, a linha é fechada com ended_ns (sem pcap) e sai da fila.
func TestFinalizeGivesUp(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	if err := processErr(in, batch(client, mirror, protoTCP, fullTCP)); err != nil {
		t.Fatal(err)
	}
	failOn(t, db, "pcaps")
	_ = in.Finalize(t.Context(), in.flows.due(base+5000e6))
	for range maxFinalizeTries - 1 {
		if len(in.toFinalize) != 1 {
			t.Fatal("must stay queued")
		}
		_ = in.finalizeQueued(t.Context())
	}
	if len(in.toFinalize) != 0 || count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") != 1 {
		t.Fatal("must give up and close the row")
	}
}

// TestFinalizeAfterCommitNoNak: a falha da finalização das conexões encerradas por reuso, depois do commit do
// lote, não devolve erro (o lote recebe Ack, sem reentrega duplicada) e a conexão é finalizada depois.
func TestFinalizeAfterCommitNoNak(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	reuse := append(append([]pkt(nil), fullTCP...), pkt{2000, true, tcpSYN, 0}, pkt{2010, false, tcpSYN | tcpACK, 0})
	drop := failOn(t, db, "pcaps")
	if err := processErr(in, batch(client, mirror, protoTCP, reuse)); err != nil {
		t.Fatalf("error after commit must not fail the batch: %v", err)
	}
	if pktCount(t, in, db) != len(reuse) || count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL") != 2 {
		t.Fatal("batch must be stored once")
	}
	drop()
	if err := in.finalizeQueued(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL") != 1 || count(t, db, "SELECT count(*) FROM pcaps") != 1 ||
		pktCount(t, in, db) != 2 {
		t.Fatal("old connection must be finalized on retry")
	}
}

// TestRetentionPurgesOrphans: linha aberta fora da memória do ingest e mais velha que retenção + ociosidade sai;
// a aberta na tabela de fluxos fica.
func TestRetentionPurgesOrphans(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 30, batch(client, mirror, protoTCP, fullTCP[:3]))
	if _, err := db.Exec(`INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto, started_ns, degraded, record_json, updated_ns)
		VALUES ('orphan', 'tcp', 4, '192.0.2.1', 1, '192.0.2.2', 2, 'tcp', ?, 0, '{}', ?)`, base, base); err != nil {
		t.Fatal(err)
	}
	r := NewRetention(db, 10*time.Minute, 1<<40)
	r.Tracked, r.OrphanIdle = in.flows.tracked, 150*time.Second
	if _, err := r.RunOnce(t.Context(), time.Unix(0, base).Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections") != 2 {
		t.Fatal("orphan purged too early")
	}
	if _, err := r.RunOnce(t.Context(), time.Unix(0, base).Add(13*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE conn_id = 'orphan'") != 0 || count(t, db, "SELECT count(*) FROM connections") != 1 {
		t.Fatal("orphan must go, the open one must stay")
	}
}

func withHeaders(m fakeMsg, format, version, cnt string) fakeMsg {
	h := nats.Header{}
	h.Set(event.HeaderFormat, format)
	h.Set(event.HeaderSchemaVersion, version)
	if cnt != "" {
		h.Set(event.HeaderCount, cnt)
	}
	m.hdr = h
	return m
}

// TestPacketBatchHeaders: formato ou versão desconhecidos não são decodificados (descarte contado); Fs-Count
// divergente só avisa; lote truncado é descartado inteiro, sem aplicar os registros anteriores.
func TestPacketBatchHeaders(t *testing.T) {
	m := batch(client, mirror, protoTCP, fullTCP[:3])
	for _, c := range []struct{ format, version string }{{"fspb2", "1"}, {event.FSPBFormat, "2"}, {"", ""}} {
		in, db := newTestIngestor(t, nil)
		if err := processErr(in, withHeaders(m, c.format, c.version, "3")); err != nil {
			t.Fatal(err)
		}
		if count(t, db, "SELECT count(*) FROM connections") != 0 || in.flows.open() != 0 || in.metrics.Get("store_bad_batches_total") != 1 {
			t.Fatalf("%q/%q must be rejected", c.format, c.version)
		}
	}

	in, db := newTestIngestor(t, nil)
	if err := processErr(in, withHeaders(m, event.FSPBFormat, "1", "4")); err != nil {
		t.Fatal(err)
	}
	if pktCount(t, in, db) != 3 || in.metrics.Get("store_batch_count_mismatch_total") != 1 || in.metrics.Get("store_bad_batches_total") != 0 {
		t.Fatal("count mismatch must only warn")
	}
	if err := processErr(in, batch(client2, mirror, protoTCP, fullTCP[:3])); err != nil {
		t.Fatal(err)
	}
	if in.metrics.Get("store_batch_count_mismatch_total") != 1 {
		t.Fatal("valid batch must not warn")
	}

	in, db = newTestIngestor(t, nil)
	short := batch(client, mirror, protoTCP, fullTCP[:3])
	short.data = short.data[:len(short.data)-1]
	if err := processErr(in, short); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "SELECT count(*) FROM connections") != 0 || in.flows.open() != 0 || in.metrics.Get("store_bad_batches_total") != 1 {
		t.Fatal("short batch must be discarded whole")
	}
}

// TestLatePacketOnlyFKDropped: o tardio de uma conexão apagada continua descartado e contado (FK), mas qualquer
// outro erro de SQL no INSERT do tardio aborta o lote inteiro (task 384).
func TestLatePacketOnlyFKDropped(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.CloseGrace = prodGrace(t) })
	other := netip.AddrPortFrom(mirror.Addr(), 7701)
	run(t, in, 1060, segBatch(client, other, closeSegs))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("%d conexões", n)
	}
	pcapLen := count(t, db, "SELECT length(data) FROM pcaps")

	// erro diferente da FK no tardio (gatilho só em packets, a conexão segue no banco): o lote volta
	drop := failOn(t, db, "packets")
	late := segBatch(client, other, []seg{{ms: 1100, fromCli: true, flags: tcpRST, seq: 1102}})
	if err := processErr(in, late); err == nil {
		t.Fatal("non-FK SQL error in a late packet must abort the batch")
	}
	if v := in.metrics.Get("store_late_dropped_total"); v != 0 {
		t.Fatalf("store_late_dropped_total = %v", v)
	}
	drop()
	if err := processErr(in, late); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, "SELECT length(data) FROM pcaps"); n <= pcapLen {
		t.Fatalf("redelivery: pcap %d bytes, want > %d", n, pcapLen)
	}

	// conexão apagada: a FK recusa o tardio, que é descartado e contado sem derrubar o lote
	if _, err := db.Exec("DELETE FROM connections"); err != nil {
		t.Fatal(err)
	}
	if err := processErr(in, segBatch(client, other, []seg{{ms: 1150, fromCli: true, flags: tcpRST, seq: 1102}})); err != nil {
		t.Fatalf("FK violation of a late packet must not abort the batch: %v", err)
	}
	if v := in.metrics.Get("store_late_dropped_total"); v != 1 {
		t.Fatalf("store_late_dropped_total = %v", v)
	}
}
