package botmigrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// openDB abre um SQLite novo com WAL, como o bot.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bot.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestUpDownUp: as migrations (0001 e 0002) aplicam, revertem até zero sem sobra e aplicam de novo; a 0002 sozinha
// também desce e sobe (só control_requests sai).
func TestUpDownUp(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}
	for _, table := range []string{"api_keys", "key_usage_daily", "ip_hourly", "fp_daily", "lists", "control_requests"} {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("tabela %s ausente", table)
		}
	}
	if _, err := p.DownTo(ctx, 1); err != nil {
		t.Fatalf("down até 1: %v", err)
	}
	for table, want := range map[string]int{"control_requests": 0, "lists": 1} {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("down até 1: tabela %s = %d, quer %d", table, n, want)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up da 0002: %v", err)
	}
	if _, err := p.DownTo(ctx, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type IN ('table','index') AND name NOT LIKE 'goose%' AND name NOT LIKE 'sqlite%'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("down deixou %d objetos", n)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up de novo: %v", err)
	}
}

// TestConstraints: o esquema recusa modo desconhecido, hash de chave repetido e tipo de fingerprint fora da lista.
func TestConstraints(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	ins := `INSERT INTO api_keys (id, name, key_sha256, prefix, domains, mode, created_at) VALUES (?, 'x', ?, 'fsk_abcd', '[]', ?, 1)`
	if _, err := db.ExecContext(ctx, ins, "01JC0X3K8V2T7Q9N4M6P1R5S8W", []byte{1}, "observe"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, ins, "01JC0X3K8V2T7Q9N4M6P1R5S8X", []byte{1}, "observe"); err == nil {
		t.Error("key_sha256 repetido aceito")
	}
	if _, err := db.ExecContext(ctx, ins, "01JC0X3K8V2T7Q9N4M6P1R5S8Y", []byte{2}, "deny"); err == nil {
		t.Error("modo desconhecido aceito")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO fp_daily (kind, value, day, ua_family) VALUES ('ja3', 'x', 1, 'curl')`); err == nil {
		t.Error("kind fora da lista aceito")
	}
	insCtl := `INSERT INTO control_requests (op, arg, created_at) VALUES (?, ?, ?)`
	if _, err := db.ExecContext(ctx, insCtl, "forget", "192.0.2.0/24", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, insCtl, "lists_refresh", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, insCtl, "reboot", nil, 1); err == nil {
		t.Error("op fora da lista aceita")
	}
	if _, err := db.ExecContext(ctx, insCtl, "forget", "x", nil); err == nil {
		t.Error("created_at nulo aceito")
	}
	if _, err := db.ExecContext(ctx, insCtl, "forget", "x", "ontem"); err == nil {
		t.Error("created_at texto aceito (STRICT)")
	}
}

// TestIngestLimitsMigration: a 0003 acrescenta api_keys.ingest_rate/ingest_burst (nulas = padrão) e
// key_usage_daily.records (0 por padrão; linhas antigas ficam com 0) e desce sem perder as outras colunas (ADR 0073
// item 3.1, task 371).
func TestIngestLimitsMigration(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO key_usage_daily (key_id, day, requests, limited) VALUES ('k', 1, 5, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up da 0003: %v", err)
	}
	var records int64
	if err := db.QueryRowContext(ctx, `SELECT records FROM key_usage_daily WHERE key_id = 'k'`).Scan(&records); err != nil || records != 0 {
		t.Fatalf("records da linha antiga: %d %v", records, err)
	}
	ins := `INSERT INTO api_keys (id, name, key_sha256, prefix, domains, mode, created_at, ingest_rate, ingest_burst)
		VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', 'x', x'01', 'abcd', '[]', 'observe', 1, ?, ?)`
	if _, err := db.ExecContext(ctx, ins, nil, nil); err != nil {
		t.Fatalf("colunas nulas: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE api_keys SET ingest_rate = 'muito'`); err == nil {
		t.Error("ingest_rate texto aceito (STRICT)")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO key_usage_daily (key_id, day, records) VALUES ('k', 2, NULL)`); err == nil {
		t.Error("records nulo aceito")
	}
	if _, err := p.DownTo(ctx, 2); err != nil {
		t.Fatalf("down da 0003: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info('api_keys') WHERE name LIKE 'ingest_%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("colunas da 0003 depois do down: %d %v", n, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT requests FROM key_usage_daily WHERE key_id = 'k'`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("uso depois do down: %d %v", n, err)
	}
}
