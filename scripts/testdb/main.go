// Comando testdb mantém o banco-modelo SQLite usado pelos testes do nível rápido (spec 017 RF-06).
//
// O modelo é refeito só quando o hash (sha256) da pasta de migrations muda. O hash fica gravado
// dentro do próprio banco, na tabela fs_template_meta, para que um modelo copiado ou restaurado
// continue verificável. Cada teste copia o modelo para um arquivo temporário e começa limpo.
//
// Uso:
//
//	go run ./scripts/testdb -migrations database/sqlite/migrations -out tmp/testdb/template.sqlite
//
// Saída (stdout, uma linha): "skipped" (sem migrations), "fresh" (modelo em dia) ou "rebuilt".
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // driver "sqlite" em Go puro (ADR 0005)
)

// Resultados possíveis de ensureTemplate.
const (
	resultSkipped = "skipped"
	resultFresh   = "fresh"
	resultRebuilt = "rebuilt"
)

// metaTable guarda o hash das migrations usado para gerar o modelo.
const metaTable = "fs_template_meta"

func main() {
	migrations := flag.String("migrations", "database/sqlite/migrations", "migrations directory")
	out := flag.String("out", "tmp/testdb/template.sqlite", "template database path")
	flag.Parse()

	result, err := ensureTemplate(context.Background(), *migrations, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testdb:", err)
		os.Exit(1)
	}
	fmt.Println(result)
}

// ensureTemplate garante que out é um banco migrado com as migrations atuais.
func ensureTemplate(ctx context.Context, migrationsDir, out string) (string, error) {
	hash, count, err := hashMigrations(migrationsDir)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return resultSkipped, nil
	}

	if current, err := readTemplateHash(ctx, out); err == nil && current == hash {
		return resultFresh, nil
	}

	if err := buildTemplate(ctx, migrationsDir, out, hash); err != nil {
		return "", err
	}
	return resultRebuilt, nil
}

// hashMigrations calcula o sha256 dos arquivos .sql (nome + conteúdo, em ordem).
func hashMigrations(dir string) (string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", 0, nil
		}
		return "", 0, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	h := sha256.New()
	fsys := os.DirFS(dir)
	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			return "", 0, err
		}
		_, _ = io.WriteString(h, name+"\x00")
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return "", 0, err
		}
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil)), len(names), nil
}

// readTemplateHash lê o hash gravado no modelo existente.
func readTemplateHash(ctx context.Context, path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()

	var hash string
	err = db.QueryRowContext(ctx, "SELECT value FROM "+metaTable+" WHERE key = 'migrations_sha256'").Scan(&hash)
	return hash, err
}

// buildTemplate recria o modelo do zero num arquivo temporário e troca de forma atômica.
func buildTemplate(ctx context.Context, migrationsDir, out, hash string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	tmp := out + ".building"
	_ = os.Remove(tmp)

	db, err := sql.Open("sqlite", "file:"+tmp)
	if err != nil {
		return err
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS(migrationsDir))
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("goose: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("goose up: %w", err)
	}

	if _, err := db.ExecContext(ctx, "CREATE TABLE "+metaTable+" (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		_ = db.Close()
		return err
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO "+metaTable+" (key, value) VALUES ('migrations_sha256', ?)", hash); err != nil {
		_ = db.Close()
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}
