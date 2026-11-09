package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// writeMigration cria um arquivo de migration goose mínimo.
func writeMigration(t *testing.T, dir, name, table string) {
	t.Helper()
	body := "-- +goose Up\nCREATE TABLE " + table + " (id INTEGER PRIMARY KEY);\n-- +goose Down\nDROP TABLE " + table + ";\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureTemplateLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	migrations := filepath.Join(dir, "migrations")
	out := filepath.Join(dir, "testdb", "template.sqlite")
	if err := os.MkdirAll(migrations, 0o755); err != nil {
		t.Fatal(err)
	}

	// Sem migrations: nada a fazer.
	assertResult(t, ctx, migrations, out, resultSkipped)

	// Primeira migration: o modelo é criado.
	writeMigration(t, migrations, "00001_a.sql", "a")
	assertResult(t, ctx, migrations, out, resultRebuilt)

	// Sem mudança: o modelo é reaproveitado.
	assertResult(t, ctx, migrations, out, resultFresh)

	// Nova migration: o hash muda e o modelo é refeito.
	writeMigration(t, migrations, "00002_b.sql", "b")
	assertResult(t, ctx, migrations, out, resultRebuilt)
	assertResult(t, ctx, migrations, out, resultFresh)
}

func TestEnsureTemplateMissingDir(t *testing.T) {
	// Pasta de migrations ausente equivale a "sem migrations".
	dir := t.TempDir()
	assertResult(t, context.Background(), filepath.Join(dir, "nope"), filepath.Join(dir, "t.sqlite"), resultSkipped)
}

func TestEnsureTemplateBadMigration(t *testing.T) {
	// SQL inválido precisa falhar e não deixar modelo para trás.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00001_bad.sql"), []byte("-- +goose Up\nNOT SQL;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "t.sqlite")
	if _, err := ensureTemplate(context.Background(), dir, out); err == nil {
		t.Fatal("expected error for invalid migration")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("template must not exist after failed build")
	}
}

func assertResult(t *testing.T, ctx context.Context, migrations, out, want string) {
	t.Helper()
	got, err := ensureTemplate(ctx, migrations, out)
	if err != nil {
		t.Fatalf("ensureTemplate: %v", err)
	}
	if got != want {
		t.Fatalf("ensureTemplate = %q, want %q", got, want)
	}
}

// TestTemplatePragmas: o modelo nasce com auto_vacuum=INCREMENTAL (2), como o banco do store, e é um arquivo único
// (sem -wal) em journal de rollback (task 107).
func TestTemplatePragmas(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeMigration(t, dir, "00001_a.sql", "a")
	out := filepath.Join(dir, "t.sqlite")
	assertResult(t, ctx, dir, out, resultRebuilt)
	if _, err := os.Stat(out + "-wal"); err == nil {
		t.Fatal("template must not leave a -wal file")
	}

	db, err := sql.Open("sqlite", "file:"+out+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var autoVacuum int
	if err := db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&autoVacuum); err != nil {
		t.Fatal(err)
	}
	if autoVacuum != 2 {
		t.Fatalf("auto_vacuum = %d, want 2 (INCREMENTAL)", autoVacuum)
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "delete" {
		t.Fatalf("journal_mode = %q, want delete", mode)
	}
}

// TestHashCoversPragmas: mudar as pragmas de criação muda o hash, e um modelo antigo é refeito uma vez.
func TestHashCoversPragmas(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeMigration(t, dir, "00001_a.sql", "a")
	out := filepath.Join(dir, "t.sqlite")

	saved := createPragmas
	t.Cleanup(func() { createPragmas = saved })

	// Modelo gerado como antes da task 107, sem pragmas de criação.
	createPragmas = nil
	before, _, err := hashMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	assertResult(t, ctx, dir, out, resultRebuilt)

	createPragmas = saved
	after, _, err := hashMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("hash must change when create pragmas change")
	}
	assertResult(t, ctx, dir, out, resultRebuilt)
	assertResult(t, ctx, dir, out, resultFresh)
}
