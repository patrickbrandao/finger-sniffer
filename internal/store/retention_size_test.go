package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// fillDNS grava n consultas DNS de ~4 KiB, uma a cada ms a partir de startNs.
func fillDNS(t *testing.T, db *sql.DB, n int, startNs int64) {
	t.Helper()
	rec := `{"raw_b64":"` + strings.Repeat("A", 4000) + `"}`
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := tx.Exec(`INSERT INTO dns_queries (ts_ns, resolver_ip, resolver_port, proto, qname, qtype, record_json)
			VALUES (?, '198.51.100.53', 53, 'udp', 'x.', 'A', ?)`, startNs+int64(i)*1e6, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestRetentionSizeCoversDNS: com o banco dominado por consultas DNS acima do teto, o expurgo por tamanho apaga
// as DNS mais antigas e preserva as conexões encerradas mais novas que elas (task 154, ADR 0034 item 9).
func TestRetentionSizeCoversDNS(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	fillDNS(t, db, 3000, base)             // ~12 MiB, mais antigas
	fillConns(t, db, "c", 50, base+3600e9) // mais novas que todas as DNS
	r := NewRetention(db, time.Hour, 0)
	size, _ := r.logicalSize(ctx)
	r.maxBytes = size / 2
	if _, err := r.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.logicalSize(ctx); s > r.maxBytes {
		t.Fatalf("size %d over cap %d", s, r.maxBytes)
	}
	var left, oldest int64
	_ = db.QueryRow("SELECT count(*), coalesce(min(ts_ns), 0) FROM dns_queries").Scan(&left, &oldest)
	if left == 0 || left == 3000 || oldest == base {
		t.Fatalf("dns left %d oldest %d: the oldest DNS rows must go first", left, oldest)
	}
	if count(t, db, "SELECT count(*) FROM connections") != 50 {
		t.Fatal("newer closed connections must stay")
	}
}

// TestRetentionSizeOnlyOpen: só conexões abertas acima do teto: o laço termina sem apagar nada.
func TestRetentionSizeOnlyOpen(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	fillConns(t, db, "o", 20, base)
	if _, err := db.Exec("UPDATE connections SET ended_ns = NULL"); err != nil {
		t.Fatal(err)
	}
	r := NewRetention(db, time.Hour, 1)
	r.Budget = 5 * time.Second
	start := time.Now()
	if _, err := r.RunOnce(ctx, time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second || count(t, db, "SELECT count(*) FROM connections") != 20 {
		t.Fatal("must stop without deleting open connections")
	}
}
