package store

import (
	"context"
	"database/sql"
	"math"
	"os"
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
	// DefaultRetentionStep é o prazo de cada passo (um DELETE em lote) do expurgo de conexões (Retention.adapt,
	// task 248).
	DefaultRetentionStep = 25 * time.Millisecond
	// minRetentionBatch é o menor lote a que o prazo por passo reduz o expurgo de conexões.
	minRetentionBatch = 10
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
	batch    int // lote corrente do expurgo de conexões (adapt), entre minRetentionBatch e maxBatch
	maxBatch int
	// Budget limita o tempo de uma chamada de RunOnce (0 = até acabar o que venceu). Passado o orçamento, a
	// rodada para no fim do lote corrente e o restante fica para a próxima.
	Budget time.Duration
	// StepTarget é o prazo de cada DELETE em lote de conexões (0 = lote fixo): ver adapt.
	StepTarget time.Duration
	// OnPurge, se definido, recebe as conexões expurgadas por motivo (age, size ou space).
	OnPurge func(reason string, n int64)
	// Observe, se definido, recebe a duração de cada comando de escrita do expurgo: opPurgeDelete (um DELETE em
	// lote) e opPurgeVacuum (incremental_vacuum) (task 248).
	Observe func(op string, d time.Duration)
	// Tracked, se definido, diz se um conn_id está na memória do ingest (aberto ou à espera da finalização).
	// Liga o expurgo de órfãs (ADR 0034): linha com ended_ns nulo, fora da memória e com started_ns mais velho
	// que maxAge + OrphanIdle, que nenhuma finalização vai fechar.
	Tracked func(id string) bool
	// OrphanIdle é a ociosidade máxima do TCP (a conexão aberta mais longa sem pacote que o ingest mantém).
	OrphanIdle time.Duration
	// Space, se definido, lê o livre do sistema de arquivos do banco (o tmpfs, ADR 0045 item 5): com menos de
	// spaceLowPct livre, o expurgo por tamanho roda mesmo abaixo de maxBytes, até o livre voltar a spaceOKPct.
	Space SpaceReader
	// Path é o arquivo do banco: o que ele ocupa além de page_count já vai voltar ao tmpfs no próximo checkpoint
	// (incremental_vacuum feito, arquivo ainda não cortado) e não precisa de mais expurgo.
	Path string
	// spaceMode é a histerese do expurgo por espaço: liga abaixo de spaceLowPct, desliga em spaceOKPct.
	spaceMode bool
	// Checkpoint, se definido, é o checkpoint TRUNCATE do WAL que o expurgo de emergência faz depois de cada
	// passo (Emergency).
	Checkpoint func(ctx context.Context) error
	// afterStep roda depois de cada comando de escrita do expurgo (só durante Emergency).
	afterStep func()
	// chunk é o tamanho de cada incremental_vacuum de releaseFree (0 = releaseChunk).
	chunk int64
	// now mede o orçamento (testes trocam).
	now func() time.Time
}

// NewRetention cria o expurgador, sem orçamento (o laço do store define Budget).
func NewRetention(db *sql.DB, maxAge time.Duration, maxBytes int64) *Retention {
	return &Retention{db: db, maxAge: maxAge, maxBytes: maxBytes, batch: DefaultRetentionBatch, maxBatch: DefaultRetentionBatch, now: time.Now}
}

// RunOnce expurga e devolve quantas conexões saíram. Só conexões já encerradas são apagadas: as abertas estão
// na memória do ingest e ainda vão receber pacotes. A idade conta a partir do fim (ended_ns): uma conexão longa
// continua consultável por FS_RETENTION depois de fechar (spec 004 RF-06). Como ended_ns >= started_ns, o filtro
// por started_ns usa o índice connections_started sem mudar o resultado.
func (r *Retention) RunOnce(ctx context.Context, now time.Time) (int64, error) {
	start := r.now()
	over := func() bool { return r.Budget > 0 && r.now().Sub(start) >= r.Budget }
	// Probes apagados pelo DELETE primeiro (ADR 0068 item 3): têm prioridade sobre o expurgo por idade.
	if did, err := r.purgeDeleted(ctx, over); err != nil || (did && over()) {
		return 0, err
	}
	cut := now.Add(-r.maxAge).UnixNano()
	var total int64
	for {
		batch := r.batch
		t0 := time.Now() // o prazo por passo usa o relógio real (r.now é o do orçamento)
		n, err := r.exec(ctx, "DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE started_ns < ? AND ended_ns IS NOT NULL AND ended_ns < ? ORDER BY started_ns LIMIT ?)", cut, cut, batch)
		if err != nil {
			return total, err
		}
		r.adapt(time.Since(t0))
		total += n
		r.purged("age", n)
		if n < int64(batch) {
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
	n, err = r.purgeSize(ctx, over, false)
	total += n
	if err != nil {
		return total, err
	}
	if over() {
		return total, nil
	}
	if r.spaceMode {
		return total, r.releaseFree(ctx, over) // devolve tudo ao tmpfs, não só o que sobrou de uma carga
	}
	return total, r.vacuum(ctx)
}

// purgeDeleted apaga as linhas dos probes apagados pelo DELETE (ADR 0068 item 3): conexões (com as filhas, em
// cascata) e consultas DNS até o corte, em lotes de no máximo r.batch (com o prazo por passo de adapt), cada um
// numa transação curta, e tira a linha de deleted_probes quando nada mais está abaixo do corte. Um DELETE novo do
// mesmo probe durante o apagamento só sobe o corte: a linha sai só se o corte lido ainda for o mesmo.
// did diz se havia algum probe apagado (sem nenhum, a rodada não gasta orçamento aqui).
func (r *Retention) purgeDeleted(ctx context.Context, over func() bool) (did bool, err error) {
	rows, err := r.db.QueryContext(ctx, "SELECT probe_id, conn_cut, dns_cut FROM deleted_probes ORDER BY deleted_ns")
	if err != nil {
		return false, err
	}
	type cut struct {
		id, conn string
		dns      int64
	}
	var cuts []cut
	for rows.Next() {
		var c cut
		if err := rows.Scan(&c.id, &c.conn, &c.dns); err != nil {
			_ = rows.Close()
			return false, err
		}
		cuts = append(cuts, c)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || len(cuts) == 0 {
		return false, err
	}
	for _, c := range cuts {
		for {
			batch := r.batch
			t0 := time.Now()
			n, err := r.exec(ctx, "DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE probe_id = ? AND conn_id <= ? LIMIT ?)", c.id, c.conn, batch)
			if err != nil {
				return true, err
			}
			r.adapt(time.Since(t0))
			if n < int64(batch) {
				break
			}
			if over() {
				return true, nil
			}
		}
		for {
			n, err := r.exec(ctx, "DELETE FROM dns_queries WHERE id IN (SELECT id FROM dns_queries WHERE probe_id = ? AND id <= ? LIMIT ?)", c.id, c.dns, DefaultRetentionBatch)
			if err != nil {
				return true, err
			}
			if n < DefaultRetentionBatch {
				break
			}
			if over() {
				return true, nil
			}
		}
		if _, err := r.exec(ctx, "DELETE FROM deleted_probes WHERE probe_id = ? AND conn_cut = ? AND dns_cut = ?", c.id, c.conn, c.dns); err != nil {
			return true, err
		}
		if over() {
			return true, nil
		}
	}
	return true, nil
}

// Emergency é o expurgo de emergência depois de um SQLITE_FULL no ingest (ADR 0045 item 5): fora do orçamento da
// rodada, do mais antigo para o mais novo, até o livre do tmpfs voltar a spaceOKPct ou por no máximo
// emergencyPurgeMax, devolvendo as páginas com incremental_vacuum. As conexões contam como reason=space. Quem
// chama faz o checkpoint TRUNCATE do WAL em seguida (só ele corta o arquivo do banco no tmpfs).
//
// Com o tmpfs cheio de verdade o WAL não pode crescer: cada passo (um DELETE em lote ou um incremental_vacuum de
// emergencyChunk páginas) é seguido do checkpoint TRUNCATE (Checkpoint), que copia o pouco que o passo gravou no
// WAL, corta o arquivo do banco e devolve o WAL ao tmpfs antes do passo seguinte.
func (r *Retention) Emergency(ctx context.Context) (int64, error) {
	start := r.now()
	over := func() bool { return r.now().Sub(start) >= emergencyPurgeMax }
	if r.Checkpoint != nil {
		r.afterStep = func() { _ = r.Checkpoint(ctx) }
	}
	r.chunk = emergencyChunk
	defer func() { r.afterStep, r.chunk = nil, 0 }()
	n, err := r.purgeSize(ctx, over, true)
	if err != nil {
		return n, err
	}
	return n, r.releaseFree(ctx, over)
}

// spaceGoal devolve o tamanho lógico (páginas usadas) a que o expurgo por espaço precisa chegar, ou -1 quando o
// livre do tmpfs não pede expurgo. force (emergência) ignora a histerese e mira spaceOKPct de livre.
func (r *Retention) spaceGoal(ctx context.Context, force bool) (int64, error) {
	if r.Space == nil {
		return -1, nil
	}
	size, free, err := r.Space.Space()
	if err != nil || size <= 0 {
		return -1, nil
	}
	switch pct := freePct(size, free); {
	case pct < spaceLowPct:
		r.spaceMode = true
	case pct >= spaceOKPct:
		r.spaceMode = false
	}
	if !r.spaceMode && !force {
		return -1, nil
	}
	need := spaceDeficit(size, free)
	if need == 0 {
		return -1, nil
	}
	logical, pending, err := r.pageUse(ctx)
	if err != nil {
		return -1, err
	}
	// O que já está livre no banco (freelist) ou à espera do corte do arquivo volta ao tmpfs sem expurgo.
	need -= pending
	if need <= 0 {
		return -1, nil
	}
	return max(logical-need, 0), nil
}

// pageUse devolve o tamanho lógico (páginas usadas) e quanto do arquivo do banco já pode voltar ao tmpfs: as
// páginas livres mais o que o arquivo tem além de page_count (corte pendente do próximo checkpoint).
func (r *Retention) pageUse(ctx context.Context) (logical, pending int64, err error) {
	pages, free, psize, err := r.pageCounts(ctx)
	if err != nil {
		return 0, 0, err
	}
	pending = free * psize
	if r.Path != "" {
		if st, err := os.Stat(r.Path); err == nil && st.Size() > pages*psize { //nolint:gosec // FS_STORE_DB, da configuração
			pending += st.Size() - pages*psize
		}
	}
	return (pages - free) * psize, pending, nil
}

const (
	// releaseChunk é o máximo de páginas de cada incremental_vacuum de releaseFree (16 MiB).
	releaseChunk = 4096
	// emergencyChunk é o mesmo no expurgo de emergência (1 MiB): cada página movida passa pelo WAL.
	emergencyChunk = 256
)

// releaseFree devolve ao tmpfs todas as páginas livres do banco, em comandos de até releaseChunk páginas, até
// acabar ou vencer o prazo.
func (r *Retention) releaseFree(ctx context.Context, over func() bool) error {
	for !over() {
		var free int64
		if err := r.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
			return err
		}
		if free == 0 {
			return nil
		}
		chunk := int64(releaseChunk)
		if r.chunk > 0 {
			chunk = r.chunk
		}
		t0 := time.Now()
		_, err := r.db.ExecContext(ctx, "PRAGMA incremental_vacuum("+strconv.FormatInt(min(free, chunk), 10)+")") //nolint:gosec // número inteiro
		r.observe(opPurgeVacuum, t0)
		if err != nil {
			return err
		}
		if r.afterStep != nil {
			r.afterStep()
		}
	}
	return nil
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
//
// Com o tmpfs do banco quase cheio (spaceGoal, ADR 0045 item 5), o alvo desce abaixo de maxBytes, até o tamanho
// que devolve spaceOKPct de livre; as conexões apagadas só por isso contam como reason=space. force é a
// emergência (Emergency).
func (r *Retention) purgeSize(ctx context.Context, over func() bool, force bool) (int64, error) {
	goal, err := r.spaceGoal(ctx, force)
	if err != nil {
		return 0, err
	}
	var total int64
	for !over() {
		size, err := r.logicalSize(ctx)
		if err != nil {
			return total, err
		}
		reason := "size"
		if size <= r.maxBytes {
			if goal < 0 || size <= goal {
				return total, nil
			}
			reason = "space"
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
			r.purged(reason, n)
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
	t0 := time.Now()
	_, err := r.db.ExecContext(ctx, "PRAGMA incremental_vacuum("+strconv.Itoa(vacuumPages)+")")
	r.observe(opPurgeVacuum, t0)
	return err
}

// needVacuum decide se vale devolver páginas livres (ver vacuumMinFree e vacuumFreeRatio).
func needVacuum(pages, free int64) bool {
	return free >= vacuumMinFree && free*vacuumFreeRatio >= pages
}

// adapt ajusta o lote do expurgo de conexões ao prazo por passo (task 248): o passo que segurou o escritor por
// mais que StepTarget divide o lote por 2 (até minRetentionBatch); o que levou menos de 1/4 dele dobra o lote,
// até o máximo do NewRetention. Um disco lento (fsync, cache frio) encolhe os passos em vez de alongá-los.
func (r *Retention) adapt(d time.Duration) {
	switch {
	case r.StepTarget <= 0:
	case d > r.StepTarget:
		r.batch = max(r.batch/2, minRetentionBatch)
	case d < r.StepTarget/4:
		r.batch = min(r.batch*2, r.maxBatch)
	}
}

func (r *Retention) purged(reason string, n int64) {
	if r.OnPurge != nil && n > 0 {
		r.OnPurge(reason, n)
	}
}

func (r *Retention) observe(op string, t0 time.Time) {
	if r.Observe != nil {
		r.Observe(op, time.Since(t0))
	}
}

func (r *Retention) exec(ctx context.Context, q string, args ...any) (int64, error) {
	t0 := time.Now()
	res, err := r.db.ExecContext(ctx, q, args...)
	r.observe(opPurgeDelete, t0)
	if err != nil {
		return 0, err
	}
	if r.afterStep != nil {
		r.afterStep()
	}
	return res.RowsAffected()
}

// logicalSize é o tamanho ocupado pelos dados (páginas usadas), independente do vacuum.
func (r *Retention) logicalSize(ctx context.Context) (int64, error) {
	pages, free, size, err := r.pageCounts(ctx)
	return (pages - free) * size, err
}

// pageCounts lê page_count, freelist_count e page_size.
func (r *Retention) pageCounts(ctx context.Context) (pages, free, size int64, err error) {
	if err = r.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return 0, 0, 0, err
	}
	if err = r.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&free); err != nil {
		return 0, 0, 0, err
	}
	if err = r.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return 0, 0, 0, err
	}
	return pages, free, size, nil
}

// Operações do escritor medidas em fs_store_writer_seconds{op} (task 248).
const (
	opIngestTx     = "ingest_tx"      // transação de um lote do ingest, do BEGIN ao fim do COMMIT
	opIngestCommit = "ingest_commit"  // só o COMMIT do lote (onde cai o checkpoint automático do WAL)
	opFinalizeTx   = "finalize_tx"    // transação da finalização (pcap, registro final)
	opPurgeDelete  = "purge_delete"   // um DELETE em lote do expurgo
	opPurgeVacuum  = "purge_vacuum"   // um incremental_vacuum do expurgo
	opCheckpoint   = "wal_checkpoint" // checkpoint PASSIVE da conexão própria (fora do escritor)
	opWALRestart   = "wal_restart"    // última passada do checkpoint, com o escritor parado (CheckpointRestart)
)
