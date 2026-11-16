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

// TestUpDownUp: a migration aplica, reverte até zero sem sobra e aplica de novo.
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
	for _, table := range []string{"api_keys", "key_usage_daily", "ip_hourly", "fp_daily", "lists"} {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("tabela %s ausente", table)
		}
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
}
