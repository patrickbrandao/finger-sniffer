package migrations

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestDeletedProbes: a 00003 cria deleted_probes (ADR 0068) e o Down a remove.
func TestDeletedProbes(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, FS)
	if err != nil {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'deleted_probes'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("00003: deleted_probes devia existir")
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO deleted_probes (probe_id, deleted_ns) VALUES ('abc12345', 1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Fatal("down para 00002: deleted_probes devia sumir")
	}
}
