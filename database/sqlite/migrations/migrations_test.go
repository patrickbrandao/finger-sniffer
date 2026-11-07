package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

// openDB abre um SQLite novo com as mesmas opções que o store usa.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestUpDownUp(t *testing.T) {
	// Todas as migrations aplicam, revertem até zero e aplicam de novo.
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}
	if _, err := p.DownTo(ctx, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'goose%' AND name NOT LIKE 'sqlite%'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("down left %d tables", n)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

func TestCascadeDelete(t *testing.T) {
	// Apagar a conexão (retenção) remove pacotes, pcap, eventos e bytes crus.
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto, started_ns, record_json, updated_ns)
		 VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', 'tcp', 4, '192.0.2.1', 41234, '172.233.24.85', 443, 'tls/http1.1', 1, '{}', 1)`,
		`INSERT INTO packets (conn_id, ts_ns, dir, wire_len, frame) VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', 1, 0, 60, x'00')`,
		`INSERT INTO pcaps (conn_id, data) VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', x'00')`,
		`INSERT INTO app_events (conn_id, ts_ns, subject, payload_json) VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', 1, 'fs.v1.web.http1.request', '{}')`,
		`INSERT INTO raw_streams (conn_id, dir, offset, data) VALUES ('01JC0X3K8V2T7Q9N4M6P1R5S8W', 0, 0, x'00')`,
		`DELETE FROM connections`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	for _, table := range []string{"packets", "pcaps", "app_events", "raw_streams"} {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows left after cascade", table, n)
		}
	}
}
