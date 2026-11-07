package main

import (
	"context"
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
