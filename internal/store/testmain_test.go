package store

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// testDB abre um banco de teste. Com FS_TEST_DB=local (verify-quick), copia o banco-modelo já migrado
// (spec 017 RF-06); senão cria e migra um banco novo (verify-full, banco isolado).
func testDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.sqlite")
	if os.Getenv("FS_TEST_DB") == "local" {
		if tpl := os.Getenv("FS_TEST_DB_TEMPLATE"); tpl != "" {
			copyFile(t, tpl, path)
		}
	}
	db, err := OpenDB(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from) //nolint:gosec // caminho de teste
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(to) //nolint:gosec // caminho de teste
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
