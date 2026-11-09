package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fillConns grava n conexões encerradas (registro, pcap e eventos de aplicação de tamanho parecido com os da carga
// da task 068), começando em startNs, uma a cada 20 ms.
func fillConns(t testing.TB, db *sql.DB, prefix string, n int, startNs int64) {
	t.Helper()
	ctx := context.Background()
	rec := strings.Repeat("r", 3000)
	pcap := make([]byte, 8000)
	_, _ = rand.Read(pcap)
	ev := strings.Repeat("e", 600)
	for from := 0; from < n; from += 500 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := from; i < min(n, from+500); i++ {
			if err := insertConn(ctx, tx, fmt.Sprintf("%s%08d", prefix, i), startNs+int64(i)*20e6, rec, pcap, ev, 4); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func insertConn(ctx context.Context, tx *sql.Tx, id string, st int64, rec string, pcap []byte, ev string, events int) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto, started_ns, ended_ns, record_json, updated_ns) VALUES (?, 'tcp', 4, '192.0.2.1', 1, '198.51.100.1', 443, 'h2', ?, ?, ?, ?)",
		id, st, st+int64(4*time.Second), rec, st); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO pcaps (conn_id, data) VALUES (?, ?)", id, pcap); err != nil {
		return err
	}
	for range events {
		if _, err := tx.ExecContext(ctx, "INSERT INTO app_events (conn_id, ts_ns, subject, payload_json) VALUES (?, ?, 'web.http.request', ?)", id, st, ev); err != nil {
			return err
		}
	}
	return nil
}

// TestRetentionDoesNotStallIngest: com o banco cheio de registros vencidos, o expurgo do laço do store (lotes,
// orçamento e vacuum fora do regime) não segura o escritor: cada transação do ingest durante o expurgo espera
// menos de 200 ms (task 105).
func TestRetentionDoesNotStallIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("enche o banco")
	}
	db, _ := testDB(t)
	ctx := context.Background()
	const expired = 2500
	old := time.Now().Add(-time.Hour).UnixNano()
	fillConns(t, db, "old", expired, old)

	var (
		mu   sync.Mutex
		lats []time.Duration
	)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		// ingest simulado: uma transação pequena a cada 2 ms, como os lotes do Fetch
		rec, pcap, ev := strings.Repeat("r", 3000), make([]byte, 8000), strings.Repeat("e", 600)
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			case <-time.After(2 * time.Millisecond):
			}
			t0 := time.Now()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				done <- err
				return
			}
			if err := insertConn(ctx, tx, fmt.Sprintf("new%08d", i), time.Now().UnixNano(), rec, pcap, ev, 1); err != nil {
				_ = tx.Rollback()
				done <- err
				return
			}
			if err := tx.Commit(); err != nil {
				done <- err
				return
			}
			mu.Lock()
			lats = append(lats, time.Since(t0))
			mu.Unlock()
		}
	}()

	r := NewRetention(db, 10*time.Minute, 2<<30)
	r.Budget = DefaultRetentionBudget
	var total int64
	for range 1000 {
		n, err := r.RunOnce(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		total += n
		if total >= expired {
			break
		}
		time.Sleep(20 * time.Millisecond) // o laço real espera 1 s entre rodadas
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if total != expired {
		t.Fatalf("expunged %d of %d", total, expired)
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE conn_id LIKE 'old%'"); n != 0 {
		t.Fatalf("%d expired connections left", n)
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	if len(lats) == 0 {
		t.Fatal("no ingest transaction ran during the purge")
	}
	p99, worst := lats[len(lats)*99/100], lats[len(lats)-1]
	t.Logf("ingest tx during purge: %d tx, p50 %v p99 %v max %v", len(lats), lats[len(lats)/2], p99, worst)
	if worst >= 200*time.Millisecond {
		t.Fatalf("ingest stalled %v during the purge (limit 200ms)", worst)
	}
}

// TestRetentionBudget: com orçamento, uma rodada para no fim do lote corrente e o resto fica para a seguinte.
func TestRetentionBudget(t *testing.T) {
	db, _ := testDB(t)
	old := time.Now().Add(-time.Hour).UnixNano()
	fillConns(t, db, "old", 350, old)
	r := NewRetention(db, 10*time.Minute, 2<<30)
	r.Budget = time.Second
	clock := time.Now()
	r.now = func() time.Time { clock = clock.Add(400 * time.Millisecond); return clock } // cada lote "leva" 400 ms
	ctx := context.Background()
	var rounds []int64
	for {
		n, err := r.RunOnce(ctx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		rounds = append(rounds, n)
	}
	// cada leitura do relógio avança 400 ms: depois do 1º lote passaram 400 ms, do 2º 800 ms (seguem) e do 3º
	// 1,2 s (para): 3 lotes de 100 na primeira rodada, o resto na segunda
	if fmt.Sprint(rounds) != "[300 50]" {
		t.Fatalf("rounds %v", rounds)
	}
}

// TestNeedVacuum: em regime (poucas páginas livres, reaproveitadas pelos INSERTs) não há vacuum; quando o banco
// encolhe, o espaço volta ao sistema aos poucos.
func TestNeedVacuum(t *testing.T) {
	for _, c := range []struct {
		pages, free int64
		want        bool
	}{
		{160000, 2500, false},  // regime: um expurgo de 1 s
		{10000, 2047, false},   // pouco livre em números absolutos
		{160000, 39999, false}, // menos de 1/4
		{160000, 40000, true},  // banco encolheu
		{4000, 3000, true},
	} {
		if got := needVacuum(c.pages, c.free); got != c.want {
			t.Errorf("needVacuum(%d, %d) = %v", c.pages, c.free, got)
		}
	}
}

// TestRetentionVacuumAfterShrink: depois de expurgar quase tudo, as rodadas devolvem o espaço livre em passos
// limitados até ficar abaixo do limiar. Usa um banco criado pelo OpenDB, como o de produção: o banco-modelo do
// verify-quick (scripts/testdb) nasce sem auto_vacuum=INCREMENTAL, e nele o incremental_vacuum não faz nada.
func TestRetentionVacuumAfterShrink(t *testing.T) {
	db, err := OpenDB(context.Background(), filepath.Join(t.TempDir(), "store.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	fillConns(t, db, "old", 1500, time.Now().Add(-time.Hour).UnixNano())
	r := NewRetention(db, 10*time.Minute, 2<<30)
	ctx := context.Background()
	pragma := func(q string) (v int64) {
		if err := db.QueryRow(q).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := r.RunOnce(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	prev := pragma("PRAGMA freelist_count")
	for i := 0; needVacuum(pragma("PRAGMA page_count"), pragma("PRAGMA freelist_count")); i++ {
		if i > 100 {
			t.Fatal("vacuum does not converge")
		}
		if _, err := r.RunOnce(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		free := pragma("PRAGMA freelist_count")
		if prev-free > vacuumPages || free >= prev {
			t.Fatalf("vacuum step %d -> %d", prev, free)
		}
		prev = free
	}
}

// TestCheckpointOffWriter: o checkpoint pela conexão própria copia o WAL e não espera uma transação aberta do
// escritor (PASSIVE), ou seja, não entra no caminho do ingest (task 105).
func TestCheckpointOffWriter(t *testing.T) {
	db, path := testDB(t)
	fillConns(t, db, "c", 200, time.Now().UnixNano())
	cdb, err := OpenCheckpointDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cdb.Close() }()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE connections SET updated_ns = 1 WHERE conn_id = 'c00000000'"); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	wal, done, err := Checkpoint(ctx, cdb)
	if err != nil || time.Since(t0) > time.Second {
		t.Fatalf("checkpoint with an open write tx: %v after %v", err, time.Since(t0))
	}
	if wal <= 0 || done != wal {
		t.Fatalf("checkpointed %d of %d WAL pages", done, wal)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
