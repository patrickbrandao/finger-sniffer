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
	// O checkpoint automático do WAL roda no commit de quem escreve, ou seja, no caminho do ingest. O store faz o
	// checkpoint por uma conexão própria a cada segundo (Checkpoint, task 105); o automático fica só como rede de
	// segurança, com limiar alto (64 MiB de WAL), e journal_size_limit devolve o espaço do WAL depois do reinício.
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)" +
		"&_pragma=wal_autocheckpoint(16384)&_pragma=journal_size_limit(67108864)"
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
// Recebe o banco de leitura: a contagem não pode disputar a conexão do escritor com o ingest (task 105).
func dbStats(ctx context.Context, db *sql.DB, path string) (size int64, conns int64, oldestNs sql.NullInt64) {
	size = dbFileSize(path)
	_ = db.QueryRowContext(ctx, "SELECT count(*), min(started_ns) FROM connections").Scan(&conns, &oldestNs)
	return size, conns, oldestNs
}

// dbFileSize soma o arquivo do banco e o WAL.
func dbFileSize(path string) (size int64) {
	for _, s := range []string{"", "-wal"} {
		if st, err := os.Stat(path + s); err == nil {
			size += st.Size()
		}
	}
	return size
}

// OpenReadDB abre conexões só de leitura para a API (WAL permite ler enquanto o ingest escreve).
func OpenReadDB(path string, maxConns int) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxConns)
	return db, nil
}

// OpenCheckpointDB abre a conexão que só faz checkpoint do WAL, fora da conexão do escritor (task 105).
func OpenCheckpointDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Checkpoint copia o WAL para o banco sem esperar travas (PASSIVE): não bloqueia o escritor nem os leitores; o
// que não deu para copiar fica para a próxima vez. Devolve as páginas no WAL e as já copiadas.
func Checkpoint(ctx context.Context, db *sql.DB) (walPages, done int64, err error) {
	var busy int64
	err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &walPages, &done)
	return walPages, done, err
}
