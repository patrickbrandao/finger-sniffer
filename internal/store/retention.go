package store

import (
	"context"
	"database/sql"
	"time"
)

// Retention expurga o mais antigo por tempo (FS_RETENTION) e por tamanho (FS_STORE_MAX_BYTES) (spec 004 RF-06).
type Retention struct {
	db       *sql.DB
	maxAge   time.Duration
	maxBytes int64
	batch    int
	// OnPurge, se definido, recebe as conexões expurgadas por motivo (age ou size).
	OnPurge func(reason string, n int64)
}

// NewRetention cria o expurgador.
func NewRetention(db *sql.DB, maxAge time.Duration, maxBytes int64) *Retention {
	return &Retention{db: db, maxAge: maxAge, maxBytes: maxBytes, batch: 500}
}

// RunOnce expurga e devolve quantas conexões saíram. Só conexões já encerradas são apagadas: as abertas estão
// na memória do ingest e ainda vão receber pacotes. A idade conta a partir do fim (ended_ns): uma conexão longa
// continua consultável por FS_RETENTION depois de fechar (spec 004 RF-06). Como ended_ns >= started_ns, o filtro
// por started_ns usa o índice connections_started sem mudar o resultado.
func (r *Retention) RunOnce(ctx context.Context, now time.Time) (int64, error) {
	cut := now.Add(-r.maxAge).UnixNano()
	var total int64
	for {
		n, err := r.exec(ctx, "DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE started_ns < ? AND ended_ns IS NOT NULL AND ended_ns < ? ORDER BY started_ns LIMIT ?)", cut, cut, r.batch)
		if err != nil {
			return total, err
		}
		total += n
		r.purged("age", n)
		if n < int64(r.batch) {
			break
		}
	}
	for _, q := range []string{
		"DELETE FROM stray_packets WHERE ts_ns < ?",
		"DELETE FROM dns_queries WHERE ts_ns < ?",
		"DELETE FROM probes WHERE last_seen < ?",
	} {
		if _, err := r.exec(ctx, q, cut); err != nil {
			return total, err
		}
	}
	// Teto de tamanho: apaga as mais antigas até ficar abaixo do teto.
	for {
		size, err := r.logicalSize(ctx)
		if err != nil || size <= r.maxBytes {
			break
		}
		n, err := r.exec(ctx, "DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE ended_ns IS NOT NULL ORDER BY started_ns LIMIT ?)", r.batch)
		if err != nil {
			return total, err
		}
		if n == 0 {
			if _, err := r.exec(ctx, "DELETE FROM stray_packets WHERE id IN (SELECT id FROM stray_packets ORDER BY ts_ns LIMIT ?)", r.batch); err != nil {
				return total, err
			}
			if s2, _ := r.logicalSize(ctx); s2 >= size {
				break
			}
		}
		total += n
		r.purged("size", n)
	}
	_, err := r.db.ExecContext(ctx, "PRAGMA incremental_vacuum(4096)")
	return total, err
}

func (r *Retention) purged(reason string, n int64) {
	if r.OnPurge != nil && n > 0 {
		r.OnPurge(reason, n)
	}
}

func (r *Retention) exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// logicalSize é o tamanho ocupado pelos dados (páginas usadas), independente do vacuum.
func (r *Retention) logicalSize(ctx context.Context) (int64, error) {
	var pages, free, size int64
	if err := r.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return 0, err
	}
	if err := r.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return 0, err
	}
	if err := r.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return 0, err
	}
	return (pages - free) * size, nil
}
