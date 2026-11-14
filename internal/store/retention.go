package store

import (
	"context"
	"database/sql"
	"math"
	"strconv"
	"time"
)

// Parâmetros do expurgo (spec 004 RF-06, task 105). O escritor do SQLite é um só e o ingest divide com o expurgo a
// mesma conexão: cada comando do expurgo segura o ingest pelo tempo que leva. Por isso o expurgo roda a cada
// segundo, em lotes pequenos (cada lote é uma transação curta, e entre lotes o ingest que espera pega a conexão)
// e com um orçamento de tempo por rodada; o que sobrar fica para a rodada seguinte.
const (
	// DefaultRetentionBatch é o máximo de conexões apagadas por comando (com BLOBs e eventos, em cascata).
	DefaultRetentionBatch = 100
	// DefaultRetentionBudget é o tempo máximo de uma rodada do laço do store.
	DefaultRetentionBudget = 100 * time.Millisecond
	// RetentionInterval é o intervalo entre rodadas do laço do store.
	RetentionInterval = time.Second
	// rowBatch é o máximo de linhas avulsas (pacotes avulsos, consultas DNS, probes) por comando.
	rowBatch = 1000
	// vacuumPages é o máximo de páginas devolvidas por incremental_vacuum numa rodada.
	vacuumPages = 512
	// vacuumMinFree é o mínimo de páginas livres para valer a pena devolver espaço ao sistema (8 MiB em páginas
	// de 4 KiB). Junto com vacuumFreeRatio, mantém o vacuum fora do regime: lá as páginas livres de um expurgo
	// são reaproveitadas pelos INSERTs dos segundos seguintes, e devolvê-las (realocando páginas do fim do
	// arquivo) era o que mais custava (~80% do tempo do expurgo antigo).
	vacuumMinFree = 2048
	// vacuumFreeRatio: só devolve espaço quando as livres passam de 1/4 das páginas do arquivo (o banco encolheu).
	vacuumFreeRatio = 4
)

// Retention expurga o mais antigo por tempo (FS_RETENTION) e por tamanho (FS_STORE_MAX_BYTES) (spec 004 RF-06).
type Retention struct {
	db       *sql.DB
	maxAge   time.Duration
	maxBytes int64
	batch    int
	// Budget limita o tempo de uma chamada de RunOnce (0 = até acabar o que venceu). Passado o orçamento, a
	// rodada para no fim do lote corrente e o restante fica para a próxima.
	Budget time.Duration
	// OnPurge, se definido, recebe as conexões expurgadas por motivo (age ou size).
	OnPurge func(reason string, n int64)
	// Tracked, se definido, diz se um conn_id está na memória do ingest (aberto ou à espera da finalização).
	// Liga o expurgo de órfãs (ADR 0034): linha com ended_ns nulo, fora da memória e com started_ns mais velho
	// que maxAge + OrphanIdle, que nenhuma finalização vai fechar.
	Tracked func(id string) bool
	// OrphanIdle é a ociosidade máxima do TCP (a conexão aberta mais longa sem pacote que o ingest mantém).
	OrphanIdle time.Duration
	// now mede o orçamento (testes trocam).
	now func() time.Time
}

// NewRetention cria o expurgador, sem orçamento (o laço do store define Budget).
func NewRetention(db *sql.DB, maxAge time.Duration, maxBytes int64) *Retention {
	return &Retention{db: db, maxAge: maxAge, maxBytes: maxBytes, batch: DefaultRetentionBatch, now: time.Now}
}

// RunOnce expurga e devolve quantas conexões saíram. Só conexões já encerradas são apagadas: as abertas estão
// na memória do ingest e ainda vão receber pacotes. A idade conta a partir do fim (ended_ns): uma conexão longa
// continua consultável por FS_RETENTION depois de fechar (spec 004 RF-06). Como ended_ns >= started_ns, o filtro
// por started_ns usa o índice connections_started sem mudar o resultado.
func (r *Retention) RunOnce(ctx context.Context, now time.Time) (int64, error) {
	start := r.now()
	over := func() bool { return r.Budget > 0 && r.now().Sub(start) >= r.Budget }
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
		if over() {
			return total, nil
		}
	}
	n, err := r.purgeOrphans(ctx, now, over)
	total += n
	r.purged("age", n)
	if err != nil || over() {
		return total, err
	}
	for _, q := range []string{
		"DELETE FROM stray_packets WHERE id IN (SELECT id FROM stray_packets WHERE ts_ns < ? ORDER BY ts_ns LIMIT ?)",
		"DELETE FROM dns_queries WHERE id IN (SELECT id FROM dns_queries WHERE ts_ns < ? ORDER BY ts_ns LIMIT ?)",
		"DELETE FROM probes WHERE probe_id IN (SELECT probe_id FROM probes WHERE last_seen < ? LIMIT ?)",
	} {
		for {
			n, err := r.exec(ctx, q, cut, rowBatch)
			if err != nil {
				return total, err
			}
			if n < rowBatch {
				break
			}
			if over() {
				return total, nil
			}
		}
	}
	n, err = r.purgeSize(ctx, over)
	total += n
	if err != nil {
		return total, err
	}
	if over() {
		return total, nil
	}
	return total, r.vacuum(ctx)
}

// sizeTable é uma tabela do expurgo por tamanho: head lê o instante da linha mais antiga e del apaga, das mais
// antigas, até limit linhas com instante <= o limite.
type sizeTable struct {
	head, del string
	limit     int
	conns     bool // conta em fs_store_purged_total{reason="size"}
}

var sizeTables = []sizeTable{
	{
		"SELECT min(started_ns) FROM connections WHERE ended_ns IS NOT NULL",
		"DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE ended_ns IS NOT NULL AND started_ns <= ? ORDER BY started_ns LIMIT ?)",
		DefaultRetentionBatch, true,
	},
	{
		"SELECT min(ts_ns) FROM dns_queries",
		"DELETE FROM dns_queries WHERE id IN (SELECT id FROM dns_queries WHERE ts_ns <= ? ORDER BY ts_ns LIMIT ?)", rowBatch, false,
	},
	{
		"SELECT min(ts_ns) FROM stray_packets",
		"DELETE FROM stray_packets WHERE id IN (SELECT id FROM stray_packets WHERE ts_ns <= ? ORDER BY ts_ns LIMIT ?)", rowBatch, false,
	},
}

// purgeSize aplica o teto de tamanho (ADR 0034 item 9): enquanto o banco passa de maxBytes, apaga do mais antigo
// para o mais novo entre as conexões encerradas (com as filhas), as consultas DNS e os pacotes avulsos. A cada
// passo, a tabela cuja linha mais antiga é a mais velha perde um lote, só até o instante da mais antiga das
// outras; desiste quando nada mais pode ser apagado (restam só conexões abertas). Devolve as conexões apagadas.
func (r *Retention) purgeSize(ctx context.Context, over func() bool) (int64, error) {
	var total int64
	for !over() {
		size, err := r.logicalSize(ctx)
		if err != nil || size <= r.maxBytes {
			return total, err
		}
		heads := make([]sql.NullInt64, len(sizeTables))
		pick := -1
		for i, st := range sizeTables {
			if err := r.db.QueryRowContext(ctx, st.head).Scan(&heads[i]); err != nil {
				return total, err
			}
			if heads[i].Valid && (pick < 0 || heads[i].Int64 < heads[pick].Int64) {
				pick = i
			}
		}
		if pick < 0 {
			return total, nil // nada encerrado a apagar
		}
		bound := int64(math.MaxInt64)
		for i, h := range heads {
			if i != pick && h.Valid && h.Int64 < bound {
				bound = h.Int64
			}
		}
		st := sizeTables[pick]
		limit := st.limit
		if st.conns {
			limit = r.batch
		}
		n, err := r.exec(ctx, st.del, bound, limit)
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil // não acontece: a linha mais antiga tem instante <= bound
		}
		if st.conns {
			total += n
			r.purged("size", n)
		}
	}
	return total, nil
}

// purgeOrphans apaga as linhas abertas (ended_ns nulo) que o ingest esqueceu (ver Tracked). Percorre as
// candidatas por (started_ns, conn_id), em páginas, porque as conexões longas ainda abertas também aparecem.
// Uma linha fora da memória não volta a ela (só conexões novas entram na tabela de fluxos), então conferir e
// apagar em passos separados não tem corrida.
func (r *Retention) purgeOrphans(ctx context.Context, now time.Time, over func() bool) (int64, error) {
	if r.Tracked == nil {
		return 0, nil
	}
	cut := now.Add(-r.maxAge - r.OrphanIdle).UnixNano()
	var total int64
	lastTs, lastID := int64(-1<<63), ""
	for {
		rows, err := r.db.QueryContext(ctx, `SELECT conn_id, started_ns FROM connections WHERE ended_ns IS NULL AND started_ns < ?
			AND (started_ns, conn_id) > (?, ?) ORDER BY started_ns, conn_id LIMIT ?`, cut, lastTs, lastID, r.batch)
		if err != nil {
			return total, err
		}
		var orphans []string
		seen := 0
		for rows.Next() {
			if err := rows.Scan(&lastID, &lastTs); err != nil {
				_ = rows.Close()
				return total, err
			}
			seen++
			if !r.Tracked(lastID) {
				orphans = append(orphans, lastID)
			}
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return total, err
		}
		for _, id := range orphans {
			n, err := r.exec(ctx, "DELETE FROM connections WHERE conn_id = ? AND ended_ns IS NULL", id)
			if err != nil {
				return total, err
			}
			total += n
		}
		if seen < r.batch || over() {
			return total, nil
		}
	}
}

// vacuum devolve ao sistema, aos poucos, o espaço livre que sobrou quando o banco encolheu (fim de uma carga).
func (r *Retention) vacuum(ctx context.Context) error {
	var pages, free int64
	if err := r.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return err
	}
	if err := r.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return err
	}
	if !needVacuum(pages, free) {
		return nil
	}
	_, err := r.db.ExecContext(ctx, "PRAGMA incremental_vacuum("+strconv.Itoa(vacuumPages)+")")
	return err
}

// needVacuum decide se vale devolver páginas livres (ver vacuumMinFree e vacuumFreeRatio).
func needVacuum(pages, free int64) bool {
	return free >= vacuumMinFree && free*vacuumFreeRatio >= pages
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
