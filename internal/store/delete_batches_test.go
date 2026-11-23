package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// drainDeleted roda o apagamento em lotes dos probes apagados até deleted_probes esvaziar (ADR 0068 item 3).
func drainDeleted(t *testing.T, db *sql.DB) {
	t.Helper()
	r := NewRetention(db, time.Hour, 1<<40)
	for range 1000 {
		if _, err := r.purgeDeleted(context.Background(), func() bool { return false }); err != nil {
			t.Fatal(err)
		}
		if count(t, db, "SELECT count(*) FROM deleted_probes") == 0 {
			return
		}
	}
	t.Fatal("deleted_probes did not drain")
}

// TestDeleteProbeHidesThenBatches: depois do DELETE nenhuma leitura devolve o probe, mas as linhas continuam no
// banco até o laço de retenção; tráfego novo com o mesmo ID depois do DELETE aparece como probe novo; o laço
// apaga tudo abaixo do corte e tira a linha de deleted_probes (ADR 0068).
func TestDeleteProbeHidesThenBatches(t *testing.T) {
	f := newAPIFixture(t)
	db := f.in.db
	const pr = "batchdel1"
	seedProbe(t, f.q, pr, 5, 100, 3, 100)
	if err := f.q.DeleteProbe(context.Background(), db, pr); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr); n != 5 {
		t.Fatalf("rows deleted in the request: %d left, want 5 until the batches", n)
	}
	for _, p := range []string{"/api/v1/probes/" + pr, "/api/v1/connections?probe=" + pr, "/api/v1/dns?probe=" + pr} {
		code, body := f.get(t, p)
		if code != 404 && strings.TrimSpace(body) != "[]" {
			t.Fatalf("%s: %d %s", p, code, body)
		}
	}
	var id string
	_ = db.QueryRow("SELECT conn_id FROM connections WHERE probe_id = ? LIMIT 1", pr).Scan(&id)
	if code, _ := f.get(t, "/api/v1/connections/"+id); code != 404 {
		t.Fatalf("connection of a deleted probe: %d", code)
	}
	if err := f.q.DeleteProbe(context.Background(), db, pr); err != ErrNotFound {
		t.Fatalf("second DELETE: %v, want ErrNotFound", err)
	}
	// Tráfego novo com o mesmo ID: acima do corte, aparece.
	time.Sleep(2 * time.Millisecond)
	seedProbe(t, f.q, pr, 1, 100, 0, 0)
	if code, body := f.get(t, "/api/v1/probes/"+pr); code != 200 || strings.Count(body, `"pad"`) != 1 {
		t.Fatalf("new traffic after DELETE: %d %s", code, body)
	}
	drainDeleted(t, db)
	if n := count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr); n != 1 {
		t.Fatalf("after batches: %d connections, want only the new one", n)
	}
	if n := count(t, db, "SELECT count(*) FROM dns_queries WHERE probe_id = ?", pr); n != 0 {
		t.Fatalf("after batches: %d dns queries", n)
	}
}

// TestDeleteProbeDoesNotStallIngest: o DELETE de um probe com 2500 conexões, com um ingest simulado gravando, não
// segura o escritor: nenhum comando apaga mais que DefaultRetentionBatch conexões e a maior espera do ingest fica
// abaixo de 2 × o maior passo + 20 ms (task 339, ADR 0068 item 4).
func TestDeleteProbeDoesNotStallIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("enche o banco")
	}
	db, _ := testDB(t)
	ctx := context.Background()
	const conns = 2500
	const pr = "bigprobe1"
	fillConns(t, db, "big", conns, time.Now().UnixNano())
	if _, err := db.Exec("UPDATE connections SET probe_id = ?", pr); err != nil {
		t.Fatal(err)
	}
	// conn_id em ULID (o corte compara a ordem): os de fillConns já crescem com o índice.
	q := NewQueries(db, nil, 65535)

	var (
		mu   sync.Mutex
		lats []time.Duration
	)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		rec := strings.Repeat("r", 3000)
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			t0 := time.Now()
			tx, err := db.BeginTx(ctx, nil)
			if err == nil {
				err = insertConn(ctx, tx, fmt.Sprintf("new%08d", i), time.Now().UnixNano(), rec, make([]byte, 100), "e", 1)
				if err == nil {
					err = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
			}
			if err != nil {
				done <- err
				return
			}
			mu.Lock()
			lats = append(lats, time.Since(t0))
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	t0 := time.Now()
	if err := q.DeleteProbe(ctx, db, pr); err != nil {
		t.Fatal(err)
	}
	deleteDur := time.Since(t0)
	r := NewRetention(db, time.Hour, 1<<40)
	r.StepTarget = DefaultRetentionStep
	var maxStep time.Duration
	var maxRows int64
	r.Observe = func(op string, d time.Duration) {
		if op == opPurgeDelete {
			maxStep = max(maxStep, d)
		}
	}
	before := count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr)
	for count(t, db, "SELECT count(*) FROM deleted_probes") > 0 {
		left := count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr)
		if _, err := r.purgeDeleted(ctx, func() bool { return true }); err != nil {
			t.Fatal(err)
		}
		maxRows = max(maxRows, int64(left-count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr)))
		time.Sleep(time.Millisecond)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if before != conns || count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr) != 0 {
		t.Fatalf("rows before batches %d, want %d; left %d", before, conns, count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", pr))
	}
	if maxRows > DefaultRetentionBatch {
		t.Fatalf("one command deleted %d connections (limit %d)", maxRows, DefaultRetentionBatch)
	}
	mu.Lock()
	defer mu.Unlock()
	var worst time.Duration
	for _, l := range lats {
		worst = max(worst, l)
	}
	step := max(maxStep, deleteDur)
	t.Logf("DELETE %v, longest step %v, worst ingest wait %v (%d ingest tx)", deleteDur, maxStep, worst, len(lats))
	if limit := 2*step + 20*time.Millisecond; worst > limit {
		t.Fatalf("ingest stalled %v (limit %v = 2 x longest step %v + 20ms)", worst, limit, step)
	}
}
