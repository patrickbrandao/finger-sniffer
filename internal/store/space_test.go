package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Banco no tmpfs (ADR 0045 itens 4 e 5): expurgo pelo livre do tmpfs e comportamento com SQLITE_FULL.

// fakeSpace é um tmpfs simulado: tamanho e livre fixos, trocados pelo teste.
type fakeSpace struct{ size, free atomic.Int64 }

func newFakeSpace(size, free int64) *fakeSpace {
	f := &fakeSpace{}
	f.set(size, free)
	return f
}

func (f *fakeSpace) set(size, free int64) { f.size.Store(size); f.free.Store(free) }

func (f *fakeSpace) Space() (int64, int64, error) { return f.size.Load(), f.free.Load(), nil }

// TestSpacePurgeBelowMaxBytes: com o tmpfs abaixo de 10% livre, o expurgo por tamanho roda mesmo com o banco
// abaixo de FS_STORE_MAX_BYTES, apaga das conexões mais antigas o que falta para 15% livre, conta reason=space e
// devolve as páginas (freelist zerada); entre 10% e 15% a histerese mantém o expurgo; acima de 15%, nada.
func TestSpacePurgeBelowMaxBytes(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	fillConns(t, db, "c", 200, base)
	const size = 4_000_000
	sp := newFakeSpace(size, size*5/100) // 5% livre: faltam 10% (~410 KiB) para 15%
	r := NewRetention(db, time.Hour, 1<<40)
	r.Space = sp
	reasons := map[string]int64{}
	r.OnPurge = func(reason string, n int64) { reasons[reason] += n }
	before, _ := r.logicalSize(ctx)
	if _, err := r.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	after, _ := r.logicalSize(ctx)
	if need := int64(size*15/100 - size*5/100); before-after < need {
		t.Fatalf("freed %d bytes, want ≥ %d", before-after, need)
	}
	if reasons["space"] == 0 || reasons["size"] != 0 || reasons["space"] > 100 {
		t.Fatalf("purged by reason %v", reasons)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE conn_id = 'c00000000'") != 0 ||
		count(t, db, "SELECT count(*) FROM connections WHERE conn_id = 'c00000199'") != 1 {
		t.Fatal("the oldest connections must go first")
	}
	if count(t, db, "PRAGMA freelist_count") != 0 {
		t.Fatal("space purge must give the free pages back (incremental_vacuum)")
	}

	// 12% livre: a histerese continua até 15%.
	sp.set(size, size*12/100)
	first := reasons["space"]
	if _, err := r.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	if reasons["space"] == first {
		t.Fatal("between 10% and 15% free the space purge must go on")
	}
	// 20% livre: termina; um expurgador novo a 12% (sem ter passado de 10%) também não expurga.
	sp.set(size, size*20/100)
	second := reasons["space"]
	if _, err := r.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	r2 := NewRetention(db, time.Hour, 1<<40)
	r2.Space, r2.OnPurge = newFakeSpace(size, size*12/100), r.OnPurge
	if _, err := r2.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	if reasons["space"] != second {
		t.Fatal("no space purge at or above 15% free, nor at 12% without passing 10%")
	}
}

// TestIsDBFull: SQLITE_FULL de verdade (max_page_count), embrulhado por %w ou só no texto.
func TestIsDBFull(t *testing.T) {
	db, _ := testDB(t)
	capPages(t, db, 0)
	_, err := db.Exec("CREATE TABLE big (b BLOB); INSERT INTO big VALUES (zeroblob(1 << 20))")
	if !isDBFull(err) || !isDBFull(fmt.Errorf("insert: %w", err)) || !isDBFull(errors.New("x: database or disk is full")) {
		t.Fatalf("SQLITE_FULL not detected: %v", err)
	}
	if isDBFull(nil) || isDBFull(errors.New("constraint failed")) {
		t.Fatal("false positive")
	}
}

// capPages limita o banco ao número de páginas atual mais extra (PRAGMA max_page_count, na única conexão do
// escritor): o próximo crescimento dá SQLITE_FULL, como o tmpfs cheio.
func capPages(t *testing.T, db *sql.DB, extra int64) {
	t.Helper()
	var pages int64
	if err := db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA max_page_count = " + strconv.FormatInt(pages+extra, 10)); err != nil {
		t.Fatal(err)
	}
}

// manyConns é um lote com o início (SYN, SYN-ACK, ACK) de n conexões TCP novas, das portas from.. do cliente.
func manyConns(n, from int) fakeMsg {
	var m fakeMsg
	for i := range n {
		c := netip.AddrPortFrom(client.Addr(), uint16(from+i))
		b := batch(c, mirror, protoTCP, fullTCP[:3])
		m.subject = b.subject
		m.data = append(m.data, b.data...)
	}
	return m
}

func sources(msgs ...fakeMsg) []msgSource {
	out := make([]msgSource, len(msgs))
	for i, m := range msgs {
		out[i] = m
	}
	return out
}

// fullIngestor é o ingestor de teste com métricas, o tmpfs simulado e o expurgo de emergência do store.
func fullIngestor(t *testing.T, sp SpaceReader) (*Ingestor, *sql.DB, *storeMetrics) {
	t.Helper()
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.MaxNewPerS = 1000 })
	m := newStoreMetrics(func(context.Context) Health { return Health{} }, func() int { return 0 }, nil)
	in.SetMetrics(m)
	r := NewRetention(db, time.Hour, 1<<40)
	r.Space = sp
	r.OnPurge = m.purge
	r.Checkpoint = func(ctx context.Context) error { return CheckpointTruncate(ctx, db) }
	// o checkpoint TRUNCATE vai pela própria conexão do escritor (não há outra no teste)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	space := newDBSpace(sp)
	in.SetSpace(space, func(ctx context.Context) { emergencyPurge(ctx, r, space, db, log) })
	return in, db, m
}

// TestDBFullRetryAfterEmergencyPurge: SQLITE_FULL no lote → rollback, expurgo de emergência (reason=space) e uma
// nova tentativa que passa; sem modo banco cheio, sem descarte, health "db full" pelos 5 min seguintes.
func TestDBFullRetryAfterEmergencyPurge(t *testing.T) {
	const size = 4_000_000
	sp := newFakeSpace(size, size*5/100)
	in, db, m := fullIngestor(t, sp)
	fillConns(t, db, "old", 100, base-3600e9)
	capPages(t, db, 0)
	dropped, err := in.processBatch(context.Background(), sources(manyConns(40, 20000)))
	if err != nil || dropped {
		t.Fatalf("retry after the emergency purge must pass: dropped %v, err %v", dropped, err)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE conn_id NOT LIKE 'old%'") != 40 {
		t.Fatal("batch not written on retry")
	}
	if in.space.isFull() || testutil.ToFloat64(m.dbFullErrs) != 1 || testutil.ToFloat64(m.dbFullDrop) != 0 {
		t.Fatalf("full mode %v, db_full_total %v, dropped %v", in.space.isFull(), testutil.ToFloat64(m.dbFullErrs), testutil.ToFloat64(m.dbFullDrop))
	}
	if testutil.ToFloat64(m.purged.WithLabelValues("space")) == 0 {
		t.Fatal("emergency purge not counted as reason=space")
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE degraded = 1") != 0 {
		t.Fatal("connections degraded without full mode")
	}
	now := time.Unix(0, base)
	if r := in.space.reasons(now.Add(time.Minute)); !slices.Contains(r, "db full") || !slices.Contains(r, "db space 5% free") {
		t.Fatalf("health reasons %v", r)
	}
	sp.set(size, size/2)
	if r := in.space.reasons(now.Add(fullHealthHold + time.Second)); len(r) != 0 {
		t.Fatalf("health reasons 5 min after the last SQLITE_FULL: %v", r)
	}
}

// TestDBFullModeAndDrop: sem nada a expurgar, a nova tentativa falha e o store entra no modo banco cheio; o lote
// sem BLOBs também não cabe e é confirmado e descartado (com métrica), sem Nak e sem travar. No modo, as conexões
// novas saem degradadas (sem pcap nem bytes crus); com o livre de volta a 15%, o modo termina.
func TestDBFullModeAndDrop(t *testing.T) {
	const size = 4_000_000
	sp := newFakeSpace(size, size*2/100)
	in, db, m := fullIngestor(t, sp)
	capPages(t, db, 0)
	start := time.Now()
	dropped, err := in.processBatch(context.Background(), sources(manyConns(40, 20000), manyConns(1, 30000)))
	if err != nil || !dropped {
		t.Fatalf("batch must be acked and dropped: dropped %v, err %v", dropped, err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("ingest stuck for %v", d)
	}
	if !in.space.isFull() || testutil.ToFloat64(m.dbFullErrs) != 3 || testutil.ToFloat64(m.dbFullDrop) != 2 {
		t.Fatalf("full mode %v, db_full_total %v, dropped %v", in.space.isFull(), testutil.ToFloat64(m.dbFullErrs), testutil.ToFloat64(m.dbFullDrop))
	}
	if in.flows.open() != 0 || count(t, db, "SELECT count(*) FROM connections") != 0 {
		t.Fatal("dropped batch left connections behind")
	}
	if r := in.space.reasons(time.Unix(0, base)); !slices.Contains(r, "db full") {
		t.Fatalf("health reasons %v", r)
	}

	// Um pouco de espaço (ainda abaixo de 15%): o modo continua e a conexão nova sai degradada.
	capPages(t, db, 200)
	sp.set(size, size*12/100)
	if dropped, err := in.processBatch(context.Background(), sources(manyConns(1, 40000))); err != nil || dropped {
		t.Fatalf("dropped %v, err %v", dropped, err)
	}
	if !in.space.isFull() || count(t, db, "SELECT count(*) FROM connections WHERE degraded = 1") != 1 {
		t.Fatal("full mode: new connection must be degraded")
	}
	// Livre de volta a 15%: o modo termina e a conexão seguinte tem pcap de novo.
	sp.set(size, size*15/100)
	if dropped, err := in.processBatch(context.Background(), sources(manyConns(1, 50000))); err != nil || dropped {
		t.Fatalf("dropped %v, err %v", dropped, err)
	}
	if in.space.isFull() || count(t, db, "SELECT count(*) FROM connections WHERE degraded = 0") != 1 {
		t.Fatal("full mode must end at 15% free")
	}
}

// TestDBFullOtherErrorNaks: erro que não é SQLITE_FULL continua voltando por Nak (ADR 0034), sem expurgo.
func TestDBFullOtherErrorNaks(t *testing.T) {
	called := false
	in, db := newTestIngestor(t, nil)
	in.SetSpace(newDBSpace(nil), func(context.Context) { called = true })
	failOn(t, db, "connections")
	if dropped, err := in.processBatch(context.Background(), sources(manyConns(1, 20000))); err == nil || dropped || called {
		t.Fatalf("dropped %v, err %v, emergency %v", dropped, err, called)
	}
}

// logWriter manda o log do store para t.Log.
type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

// TestDBFullRealTmpfs: com FS_TEST_TMPFS apontando para um tmpfs pequeno (Linux, montado por quem roda o teste;
// spec 017 RF-08c, 16 MiB), enche o tmpfs de verdade com o laço do store ligado (checkpoint com recomeço do WAL) e
// depois manda lotes ao ingest: o store nunca trava nem devolve o lote por Nak, e o expurgo de emergência devolve
// espaço ao tmpfs e recria a reserva. Passa em qualquer tamanho de 16 MiB para cima (task 416: 16, 24, 32, 40, 48,
// 64 e 128 MiB).
func TestDBFullRealTmpfs(t *testing.T) {
	dir := os.Getenv("FS_TEST_TMPFS")
	if dir == "" {
		t.Skip("FS_TEST_TMPFS not set (small test tmpfs)")
	}
	d, err := os.MkdirTemp(dir, "full-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	path := filepath.Join(d, "store.sqlite")
	db, err := OpenDB(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cdb, err := OpenCheckpointDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cdb.Close() })
	sp := NewStatfsSpace(path)
	log := slog.New(slog.NewTextHandler(logWriter{t}, nil))
	in := NewIngestor(db, IngestConfig{
		PcapMax: 16 << 20, TCPIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: time.Second,
		MaxOpen: 100000, MaxNewPerS: 100000, Snaplen: 65535,
	}, log, service.NewMetrics())
	in.now = func() time.Time { return time.Unix(0, base) }
	r := NewRetention(db, time.Hour, 1<<40)
	r.Space, r.Path = sp, path
	r.Checkpoint = func(ctx context.Context) error { return CheckpointTruncate(ctx, cdb) }
	old := ReserveBytes
	ReserveBytes = 2 << 20 // tmpfs de teste pequeno
	t.Cleanup(func() { ReserveBytes = old })
	space := newDBSpace(sp).withReserve(path)
	r.Reserve = space.reserve // como no store (newRetention)
	if err := space.ensureReserve(); err != nil {
		t.Fatal(err)
	}
	in.SetSpace(space, func(ctx context.Context) { emergencyPurge(ctx, r, space, cdb, log) })
	// Enche com conexões encerradas até o primeiro SQLITE_FULL, com o checkpoint do laço do store a cada 20.
	ctx := context.Background()
	for i := 0; ; i++ {
		if i%20 == 0 {
			if _, err := CheckpointRestart(ctx, db, cdb, 256, nil); err != nil && !isDBFull(err) {
				t.Fatal(err)
			}
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		err = insertConn(ctx, tx, fmt.Sprintf("f%08d", i), base-3600e9+int64(i)*1e6, "r", make([]byte, 64<<10), "e", 1)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if isDBFull(err) {
			t.Logf("tmpfs full after %d connections", i)
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if i > 1<<20 {
			t.Fatal("tmpfs never filled up")
		}
	}
	start := time.Now()
	for i := range 20 {
		if _, err := in.processBatch(ctx, sources(manyConns(20, 1000+i*20))); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("ingest took %v on a full tmpfs", d)
	}
	// O laço do store faz o checkpoint a cada rodada: o WAL dos 20 lotes não é crescimento do banco.
	if err := CheckpointTruncate(ctx, cdb); err != nil {
		t.Fatal(err)
	}
	size, free, err := sp.Space()
	t.Logf("free after the batches: %d of %d (%.1f%%)", free, size, freePct(size, free))
	if err != nil || freePct(size, free) < spaceLowPct || in.space.isFull() {
		t.Fatalf("emergency purge left %d of %d free, full mode %v (err %v)", free, size, in.space.isFull(), err)
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE conn_id NOT LIKE 'f%'"); n != 400 {
		t.Fatalf("%d of 400 new connections written", n)
	}
	// O expurgo de emergência mira 15% de livre mais a reserva e a recria no fim (task 416); o laço do store só
	// confirma.
	if err := space.ensureReserve(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path + "-reserve"); err != nil || st.Size() != ReserveBytes {
		t.Fatalf("reserve not restored: %v", err)
	}
}

// TestReserve: a reserva ocupa ReserveBytes, sai no releaseReserve e só volta com o livre em 15% ou mais e fora
// do modo banco cheio.
func TestReserve(t *testing.T) {
	old := ReserveBytes
	ReserveBytes = 1 << 20
	t.Cleanup(func() { ReserveBytes = old })
	path := filepath.Join(t.TempDir(), "db.sqlite")
	fs := newFakeSpace(100<<20, 50<<20)
	sp := newDBSpace(fs).withReserve(path)
	size := func() int64 {
		st, err := os.Stat(path + "-reserve")
		if err != nil {
			return -1
		}
		return st.Size()
	}
	if err := sp.ensureReserve(); err != nil || size() != ReserveBytes {
		t.Fatalf("reserve %d, err %v", size(), err)
	}
	if !sp.releaseReserve() || size() != -1 || sp.releaseReserve() {
		t.Fatal("release must remove the reserve once")
	}
	fs.set(100<<20, 15<<20) // com a reserva, ficaria abaixo de 15%
	if err := sp.ensureReserve(); err != nil || size() != -1 {
		t.Fatal("reserve must not take the last free space")
	}
	fs.set(100<<20, 50<<20)
	sp.enterFull(time.Now())
	if err := sp.ensureReserve(); err != nil || size() != -1 {
		t.Fatal("no reserve in full mode")
	}
}

// TestSpacePurgeCountsMissingReserve: com a reserva de espaço solta, o expurgo por espaço mira 15% de livre mais a
// reserva (o livre de que ensureReserve precisa para recriá-la), e o expurgo de emergência recria a reserva no fim
// (task 416). Antes, num tmpfs em que a reserva é uma parte grande do tamanho, o livre depois de soltá-la já
// passava de 15%, nada era expurgado e a reserva não voltava.
func TestSpacePurgeCountsMissingReserve(t *testing.T) {
	db, path := testDB(t)
	ctx := context.Background()
	fillConns(t, db, "c", 200, base)
	old := ReserveBytes
	ReserveBytes = 400_000
	t.Cleanup(func() { ReserveBytes = old })
	const size = 4_000_000
	sp := newFakeSpace(size, size*16/100) // acima de 15%, mas a reserva (10% do tamanho) está solta
	r := NewRetention(db, time.Hour, 1<<40)
	r.Space, r.Path = sp, path
	space := newDBSpace(sp).withReserve(path)
	r.Reserve = space.reserve
	logical, _ := r.logicalSize(ctx)
	goal, err := r.spaceGoal(ctx, true)
	if err != nil || goal < 0 || logical-goal < size*9/100-size/100 {
		t.Fatalf("missing reserve must be purged for: logical %d, goal %d, err %v", logical, goal, err)
	}
	// Com a reserva no lugar, os mesmos 16% livres não pedem expurgo.
	sp.set(size, size/2)
	if err := space.ensureReserve(); err != nil {
		t.Fatal(err)
	}
	sp.set(size, size*16/100)
	if goal, err := r.spaceGoal(ctx, true); err != nil || goal != -1 {
		t.Fatalf("reserve in place: goal %d, err %v", goal, err)
	}
	// O expurgo de emergência solta a reserva e a recria no fim, com o livre de volta.
	sp.set(size, size/2)
	emergencyPurge(ctx, r, space, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if st, err := os.Stat(path + "-reserve"); err != nil || st.Size() != ReserveBytes {
		t.Fatalf("emergency purge must recreate the reserve: %v", err)
	}
}

// TestDBFullModeNoBlobs: no modo banco cheio, o lote vai sem BLOBs também nos avulsos (frame vazio, length do fio
// mantido) e a finalização de uma conexão aberta antes do modo não grava pcap (registro com pcap_truncated), como
// uma conexão degradada (ADR 0045 item 5; task 381).
func TestDBFullModeNoBlobs(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.CloseGrace = prodGrace(t) })
	in.SetSpace(newDBSpace(nil), nil)
	other := netip.AddrPortFrom(mirror.Addr(), 7701)
	run(t, in, 30, segBatch(client, other, closeSegs[:6])) // aberta antes do modo, com pcap em memória
	if !in.space.enterFull(time.Unix(0, base)) {
		t.Fatal("full mode")
	}
	in.now = func() time.Time { return time.Unix(0, base) } // dentro de fullNoReaderHold: o modo continua

	rst := netip.AddrPortFrom(client.Addr(), 41999)
	run(t, in, 100, segBatch(rst, mirror, []seg{{ms: 50, fromCli: true, flags: tcpRST, seq: 7}}))
	var frameLen, length int
	if err := db.QueryRow("SELECT length(frame), json_extract(record_json, '$.length') FROM stray_packets").Scan(&frameLen, &length); err != nil {
		t.Fatal(err)
	}
	if frameLen != 0 || length == 0 {
		t.Fatalf("stray in full mode: frame %d bytes, length %d", frameLen, length)
	}

	run(t, in, 1060+int(prodGrace(t)/time.Millisecond)+100, segBatch(client, other, closeSegs[6:]))
	if !in.space.isFull() {
		t.Fatal("full mode ended")
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL"); n != 1 {
		t.Fatalf("%d finalized connections", n)
	}
	if n := count(t, db, "SELECT count(*) FROM pcaps"); n != 0 {
		t.Fatalf("full mode wrote %d pcaps", n)
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE pcap_truncated = 1 AND json_extract(record_json, '$.pcap_truncated') = 1"); n != 1 {
		t.Fatal("record without pcap must be marked pcap_truncated")
	}
}
