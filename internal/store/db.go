// Package store é o serviço dono dos registros (spec 004). Nesta fase (task 007): banco SQLite migrado,
// stream JetStream, health agregado pelos heartbeats e API mínima na porta 9001.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	// segurança, com limiar alto (256 MiB de WAL, acima de WALRestartFrames, task 248), e journal_size_limit devolve o espaço do WAL depois do reinício.
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)" +
		"&_pragma=wal_autocheckpoint(65536)&_pragma=journal_size_limit(67108864)"
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

// WALRestartFrames é o tamanho do WAL (em quadros de 4 KiB, 128 MiB) a partir do qual o laço do store faz o WAL
// recomeçar do início (CheckpointRestart, task 248). Cada recomeço para o escritor por um instante, então ele é
// raro (a cada dezenas de segundos na carga 200/50); fica abaixo do wal_autocheckpoint (65536) para que o
// checkpoint automático, que roda dentro do COMMIT do escritor, não chegue a disparar.
const WALRestartFrames = 32768

const (
	// walSettlePasses é o máximo de passadas sem trava antes da passada com o escritor parado.
	walSettlePasses = 4
	// walQuickPass: a passada sem trava mais curta que isso deixa pouco para a passada sob trava.
	walQuickPass = 100 * time.Millisecond
)

// CheckpointRestart faz o checkpoint do WAL fora do escritor e, quando o WAL passa de restartAt quadros, deixa-o
// pronto para recomeçar do início (task 248).
//
// O WAL só recomeça do início quando uma transação de escrita começa com todos os quadros já copiados para o
// banco. O checkpoint PASSIVE da conexão própria quase nunca consegue isso sob carga: enquanto ele copia e faz o
// fsync do banco (dezenas a centenas de ms no disco do finger-01, 37 IOPS com fsync), o ingest grava quadros
// novos. Sem ajuda, quem recomeçava o WAL era o checkpoint automático no COMMIT do escritor, a cada
// wal_autocheckpoint quadros (6 a 7 s na carga 200/50), copiando até 1 s de quadros e esperando os fsync com o
// ingest parado: as paradas de 0,6 a 2,2 s da carga no finger-01 (ADR 0043).
//
// Aqui o grosso é copiado sem trava, em passadas até uma ficar curta; depois um fsync do WAL e do banco, ainda
// sem trava, adianta o que a passada final teria de esperar. Só ela, com o pouco que o ingest gravou nesse meio
// tempo, segura a conexão do escritor (o ingest e o expurgo esperam por ela no pool). Com tudo copiado, a próxima
// transação do escritor recomeça o WAL. A durabilidade não muda: a passada final faz os mesmos fsync do
// checkpoint automático (synchronous=NORMAL).
//
// path é o arquivo do banco (o WAL é path-wal). obs (opcional) recebe a duração de cada passada sem trava
// (opCheckpoint) e da passada com o escritor parado (opWALRestart), sem a espera pela conexão. Devolve os
// quadros no WAL na última passada.
func CheckpointRestart(ctx context.Context, writer, cdb *sql.DB, path string, restartAt int64, obs func(op string, d time.Duration)) (int64, error) {
	pass := func() (int64, time.Duration, error) {
		t0 := time.Now()
		wal, _, err := Checkpoint(ctx, cdb)
		d := time.Since(t0)
		if obs != nil {
			obs(opCheckpoint, d)
		}
		return wal, d, err
	}
	wal, _, err := pass()
	if err != nil || restartAt <= 0 || wal < restartAt {
		return wal, err // WAL pequeno: nada a segurar
	}
	for range walSettlePasses - 1 {
		var d time.Duration
		if wal, d, err = pass(); err != nil {
			return wal, err
		}
		if d < walQuickPass {
			break
		}
	}
	syncFile(path + "-wal")
	syncFile(path)
	conn, err := writer.Conn(ctx) // a única conexão do escritor: o ingest espera no pool
	if err != nil {
		return wal, err
	}
	defer func() { _ = conn.Close() }()
	t0 := time.Now()
	wal, _, err = Checkpoint(ctx, cdb)
	if obs != nil {
		obs(opWALRestart, time.Since(t0))
	}
	return wal, err
}

// syncFile faz o fsync de um arquivo do banco por um descritor próprio; só adianta o trabalho do checkpoint, que
// faz os seus (erro aqui não importa).
func syncFile(path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) //nolint:gosec // arquivo do próprio banco
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

// Checkpoint copia o WAL para o banco sem esperar travas (PASSIVE): não bloqueia o escritor nem os leitores; o
// que não deu para copiar fica para a próxima vez. Devolve as páginas no WAL e as já copiadas.
func Checkpoint(ctx context.Context, db *sql.DB) (walPages, done int64, err error) {
	var busy int64
	err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &walPages, &done)
	return walPages, done, err
}
