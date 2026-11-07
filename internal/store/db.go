// Package store é o serviço dono dos registros (spec 004). Nesta fase (task 007): banco SQLite migrado,
// stream JetStream, health agregado pelos heartbeats e API mínima na porta 9001.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // driver "sqlite" em Go puro (ADR 0005)

	"github.com/patrickbrandao/finger-sniffer/database/sqlite/migrations"
)

// OpenDB abre (ou cria) o SQLite do store com as opções da spec 004 e aplica as migrations goose.
// auto_vacuum=INCREMENTAL só vale se definido antes da primeira tabela, por isso vem antes das migrations.
func OpenDB(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: %s: %w", p, err)
		}
	}
	prov, err := goose.NewProvider(goose.DialectSQLite3, db, migrations.FS)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: goose: %w", err)
	}
	if _, err := prov.Up(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrations: %w", err)
	}
	return db, nil
}

// dbStats lê o que o health publica sobre o banco.
func dbStats(ctx context.Context, db *sql.DB, path string) (size int64, conns int64, oldestNs sql.NullInt64) {
	for _, s := range []string{"", "-wal"} {
		if st, err := os.Stat(path + s); err == nil {
			size += st.Size()
		}
	}
	_ = db.QueryRowContext(ctx, "SELECT count(*), min(started_ns) FROM connections").Scan(&conns, &oldestNs)
	return size, conns, oldestNs
}
