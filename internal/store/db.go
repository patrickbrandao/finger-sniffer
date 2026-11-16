// Package store é o serviço dono dos registros (spec 004). Nesta fase (task 007): banco SQLite migrado,
// stream JetStream, health agregado pelos heartbeats e API mínima na porta 9001.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // driver "sqlite" em Go puro (ADR 0005)

	"github.com/patrickbrandao/finger-sniffer/database/sqlite/migrations"
)

// WALJournalLimit é o journal_size_limit do escritor: o tamanho a que o WAL é cortado quando recomeça (64 MiB, o
// mesmo do wal_autocheckpoint). O banco fica num tmpfs (ADR 0045): o WAL custa RAM, e o motivo dos 512 MiB da
// task 246 (não realocar blocos do ext4 a cada recomeço, que entravam no journal esperado pelo fsync) deixou de
// existir. É uma variável para os testes.
var WALJournalLimit int64 = 64 << 20

// walAutocheckpoint é o wal_autocheckpoint do escritor, em quadros de 4 KiB (64 MiB, ADR 0045 item 4).
const walAutocheckpoint = 16384

// OpenDB abre (ou cria) o SQLite do store com as opções da spec 004 e aplica as migrations goose.
// auto_vacuum=INCREMENTAL só vale se definido antes da primeira tabela, por isso vem antes das migrations.
func OpenDB(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { //nolint:gosec // FS_STORE_DB, da configuração
		return nil, err
	}
	// O banco fica num tmpfs dedicado (ADR 0045): synchronous=OFF, porque fsync no tmpfs não faz nada e, no WAL,
	// a queda do processo não corrompe o banco (os dados já estão no kernel); a queda do host apaga o tmpfs de todo
	// jeito. A durabilidade por fsync (synchronous=NORMAL da spec 004 antes da ADR 0045) deixou de valer.
	// O checkpoint automático do WAL roda no commit de quem escreve, ou seja, no caminho do ingest. O store faz o
	// checkpoint por uma conexão própria a cada segundo (Checkpoint, task 105); o automático fica só como rede de
	// segurança, a walAutocheckpoint quadros (acima de WALRestartFrames, task 248); journal_size_limit em
	// WALJournalLimit.
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(OFF)" +
		"&_pragma=wal_autocheckpoint(" + strconv.Itoa(walAutocheckpoint) + ")&_pragma=journal_size_limit(" +
		strconv.FormatInt(WALJournalLimit, 10) + ")"
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

// OpenCheckpointDB abre a conexão que só faz checkpoint do WAL, fora da conexão do escritor (task 105). É ela
// que faz a finalização das páginas no banco, com synchronous=OFF como o escritor (tmpfs, ADR 0045).
func OpenCheckpointDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=synchronous(OFF)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// WALRestartFrames é o tamanho do WAL (em quadros de 4 KiB, 32 MiB) a partir do qual o laço do store faz o WAL
// recomeçar do início (CheckpointRestart, task 248). Fica abaixo do wal_autocheckpoint (walAutocheckpoint, 64 MiB)
// para que o checkpoint automático, que roda dentro do COMMIT do escritor, não chegue a disparar. No tmpfs
// (ADR 0045) o recomeço não espera fsync e custa só a cópia das páginas em memória.
const WALRestartFrames = 8192

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
// Aqui o grosso é copiado sem trava, em passadas até uma ficar curta. Só a passada final, com o pouco que o
// ingest gravou nesse meio tempo, segura a conexão do escritor (o ingest e o expurgo esperam por ela no pool).
// Com tudo copiado, a próxima transação do escritor recomeça o WAL. Com o banco no tmpfs (ADR 0045) não há fsync
// a adiantar (o fsync do WAL e do banco antes da passada final, da task 248, saiu).
//
// obs (opcional) recebe a duração de cada passada sem trava
// (opCheckpoint) e da passada com o escritor parado (opWALRestart), sem a espera pela conexão. Devolve os
// quadros no WAL na última passada.
func CheckpointRestart(ctx context.Context, writer, cdb *sql.DB, restartAt int64, obs func(op string, d time.Duration)) (int64, error) {
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

// Checkpoint copia o WAL para o banco sem esperar travas (PASSIVE): não bloqueia o escritor nem os leitores; o
// que não deu para copiar fica para a próxima vez. Devolve as páginas no WAL e as já copiadas.
func Checkpoint(ctx context.Context, db *sql.DB) (walPages, done int64, err error) {
	var busy int64
	err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &walPages, &done)
	return walPages, done, err
}

// CheckpointTruncate copia o WAL inteiro para o banco e corta o WAL a zero (TRUNCATE), esperando o escritor e os
// leitores pelo busy_timeout da conexão ou até ctx vencer. Usado depois do expurgo de emergência (ADR 0045 item
// 5): só o checkpoint corta o arquivo do banco no tmpfs depois do incremental_vacuum.
func CheckpointTruncate(ctx context.Context, db *sql.DB) error {
	var busy, wal, done int64
	return db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &wal, &done)
}
