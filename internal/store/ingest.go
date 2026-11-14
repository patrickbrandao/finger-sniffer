package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// IngestConfig controla correlação, pcap e modo degradado (spec 004 RF-02..RF-04, RF-11).
type IngestConfig struct {
	PcapMax    int64         // FS_PCAP_MAX_BYTES_PER_CONN
	TCPIdle    time.Duration // TCP estabelecido: max(FS_IDLE_DEFAULT, FS_IDLE_MAX) + 30 s (ADR 0034 item 2)
	QUICIdle   time.Duration // UDP com evento h3 e sem close: FS_IDLE_DEFAULT + 30 s (0 = TCPIdle)
	UDPIdle    time.Duration // 30 s
	CloseGrace time.Duration // folga depois do fechamento para pegar o último ACK
	MaxOpen    int           // FS_MAX_CONNS
	MaxNewPerS int           // FS_MAX_NEW_CONNS_PER_S
	Snaplen    uint32
	// SegmentsTracked é FS_TCP_SEGMENTS_TRACKED (segmentos com dados guardados por sentido, ≥ 32).
	SegmentsTracked int
	// P0F é o banco p0f.fp (FS_P0F_DB); nil dá só a assinatura crua, sem palpite de SO.
	P0F *p0f.DB
	// Syncookies lê o contador TcpExt SyncookiesSent (nil desliga a detecção de SYN cookie).
	Syncookies func() int64
	// RawStreamMax é FS_RAW_STREAM_MAX_BYTES (0 = padrão de 16 MiB).
	RawStreamMax int
	// Retention é FS_RETENTION: evento sem conexão mais antigo que isso é descartado (0 = não descarta).
	Retention time.Duration
}

// Ingestor consome o stream e grava pacotes e conexões no SQLite.
type Ingestor struct {
	db      *sql.DB
	cfg     IngestConfig
	flows   *flowTable
	log     *slog.Logger
	metrics *service.Metrics
	now     func() time.Time

	lagMu sync.Mutex
	lags  []float64 // ms, janela corrente

	// Usados só pelo laço de ingest (sem trava).
	pending     []pendingEvent             // eventos à espera da conexão (até pendingWait)
	pendingKeys map[flowKey]int            // pendentes por 5-tupla
	eventOnly   map[flowKey]*eventOnlyConn // conexões criadas só pelos eventos
	dirty       map[string]dirtyConn       // conexões gravadas a refazer no fim do lote
	appReloads  int                        // releituras completas de app_events (testes de custo)
	live        *Hub                       // tempo real (nil = desligado)
	liveBatch   []*liveMsg                 // eventos ao vivo do lote em curso, publicados após o commit
	prom        *storeMetrics              // métricas do /metrics (nil = desligadas)
	appTs       []int64                    // ts dos eventos de aplicação do lote (lag)
	readyEnds   []readyEnd                 // fim das conexões finalizadas na transação (record_ready)
	late        map[string]*conn           // conexões gravadas que receberam pacotes tardios neste lote

	// Falha de transação (ADR 0034): o que o rollback do lote precisa desfazer e a fila de finalização.
	batchCreated []*conn             // conexões cuja linha foi inserida pelo lote em curso
	eoUndo       []eventOnlyUndo     // mudanças do lote em curso em eventOnly, para desfazer
	batchApp     map[string]struct{} // conexões abertas que receberam eventos no lote em curso
	eoChecked    map[string]struct{} // conexões só de eventos com a linha conferida no lote em curso
	appStale     []*conn             // conexões abertas cujo estado de aplicação é relido no próximo lote
	pendSnap     []pendingEvent      // pending no início do lote em curso
	pendKeysSnap map[flowKey]int     // pendingKeys no início do lote em curso
	toFinalize   []*conn             // conexões fora da tabela à espera da finalização (saem só depois do commit)
	finalStats   []finalStat         // métricas da transação de finalização em curso
}

// maxFinalizeTries é o máximo de tentativas de finalizar uma conexão; esgotadas, a linha é fechada com ended_ns
// e o que houver (ADR 0034).
const maxFinalizeTries = 5

// SetMetrics liga as métricas Prometheus do ingest.
func (in *Ingestor) SetMetrics(m *storeMetrics) { in.prom = m }

// SetLive liga o tempo real: os lotes confirmados passam a alimentar o hub.
func (in *Ingestor) SetLive(h *Hub) { in.live = h }

// NewIngestor cria o ingestor.
func NewIngestor(db *sql.DB, cfg IngestConfig, log *slog.Logger, m *service.Metrics) *Ingestor {
	return &Ingestor{
		db: db, cfg: cfg, log: log, metrics: m, now: time.Now,
		flows: newFlowTable(cfg), eventOnly: map[flowKey]*eventOnlyConn{},
		pendingKeys: map[flowKey]int{}, dirty: map[string]dirtyConn{}, late: map[string]*conn{},
		batchApp: map[string]struct{}{}, eoChecked: map[string]struct{}{},
	}
}

// Run busca lotes do consumidor durável, grava e confirma (ack depois do commit) até ctx terminar. O fim de ctx
// só é olhado entre lotes: o lote em curso usa um contexto sem cancelamento e termina (commit + ack ou
// rollback + nak) antes de Run voltar (task 206).
func (in *Ingestor) Run(ctx context.Context, cons jetstream.Consumer) error {
	work := context.WithoutCancel(ctx)
	if err := in.recoverOrphans(ctx); err != nil {
		in.log.Error("recover orphans", "err", err)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		select {
		case <-tick.C:
			in.publishMetrics()
			if in.cfg.Syncookies != nil {
				in.flows.sampleCookies(in.now().UnixNano(), in.cfg.Syncookies())
			}
		default:
		}
		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(100*time.Millisecond))
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				time.Sleep(200 * time.Millisecond)
			}
			continue
		}
		var msgs []jetstream.Msg
		for m := range batch.Messages() {
			msgs = append(msgs, m)
		}
		if len(msgs) > 0 || len(in.pending) > 0 || len(in.eventOnly) > 0 {
			// Só erro antes do commit chega aqui (rollback): o lote volta por Nak (ADR 0034).
			if err := in.Process(work, msgs); err != nil {
				in.log.Error("ingest", "err", err)
				in.metrics.Add("store_ingest_errors_total", 1)
				for _, m := range msgs {
					_ = m.Nak()
				}
				continue
			}
			for _, m := range msgs {
				_ = m.Ack()
			}
		}
		// As que falharam antes ficam na fila e são tentadas de novo aqui, uma a uma.
		in.toFinalize = append(in.toFinalize, in.flows.due(in.now().UnixNano())...)
		if err := in.finalizeQueued(work); err != nil {
			in.log.Error("finalize", "err", err)
		}
	}
	in.drainPending()
	return nil
}

// drainPending, no desligamento, grava os eventos ainda pendentes como conexões só de eventos: as mensagens já
// foram confirmadas no JetStream e, sem isso, se perderiam no reinício. Uma queda abrupta ainda perde até
// pendingWait de eventos sem conexão (risco aceito: o ack só depois da associação prenderia o consumidor).
func (in *Ingestor) drainPending() {
	if len(in.pending) == 0 {
		return
	}
	in.beginBatch()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := func() (err error) {
		defer func() {
			if err != nil {
				in.discardBatchState()
			}
		}()
		tx, err := in.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := in.flushPending(ctx, tx, true); err != nil {
			return err
		}
		if err := in.flushDirty(ctx, tx); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil {
		in.log.Error("drain pending events", "err", err, "events", len(in.pending))
	}
}

// msgSource é o que o Process precisa de uma mensagem (permite testar sem NATS).
type msgSource interface {
	Subject() string
	Headers() nats.Header
	Data() []byte
}

// metadataSource é a mensagem do JetStream, com o instante em que entrou no stream.
type metadataSource interface {
	Metadata() (*jetstream.MsgMetadata, error)
}

// publishedAt devolve quando a mensagem entrou no stream (JetStream) ou, sem metadado, received (ADR 0025).
func publishedAt(m msgSource, received int64) int64 {
	if ms, ok := m.(metadataSource); ok {
		if md, err := ms.Metadata(); err == nil && md != nil && !md.Timestamp.IsZero() {
			return md.Timestamp.UnixNano()
		}
	}
	return received
}

// Process grava as mensagens do lote numa transação.
func (in *Ingestor) Process(ctx context.Context, msgs []jetstream.Msg) error {
	return in.process(ctx, toSources(msgs))
}

func toSources(msgs []jetstream.Msg) []msgSource {
	out := make([]msgSource, len(msgs))
	for i, m := range msgs {
		out[i] = m
	}
	return out
}

func (in *Ingestor) process(ctx context.Context, msgs []msgSource) (err error) {
	defer func() {
		if err != nil {
			in.discardBatchState()
		}
	}()
	return in.processTx(ctx, msgs)
}

func (in *Ingestor) processTx(ctx context.Context, msgs []msgSource) error {
	in.beginBatch()
	tx, err := in.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	st, err := prepare(ctx, tx)
	if err != nil {
		return err
	}
	defer st.close()
	if err := in.reloadStaleApp(ctx, tx); err != nil {
		return err
	}

	var tss []int64
	in.appTs = in.appTs[:0]
	received := in.now().UnixNano()
	for _, m := range msgs {
		subject := m.Subject()
		in.prom.event(subject)
		if isAppSubject(subject) {
			if err := in.appMessage(ctx, tx, subject, m.Data(), publishedAt(m, received)); err != nil {
				return err
			}
			continue
		}
		if subject != event.SubjectCapturePacket {
			continue // heartbeat vai por assinatura própria; subjects desconhecidos são ignorados
		}
		h := m.Headers()
		// Lote FSPB malformado (cabeçalhos de outro formato ou corpo truncado) é descartado inteiro, antes de
		// aplicar qualquer registro, e confirmado (ADR 0034 itens 6 e 10).
		if err := event.CheckPacketHeaders(h.Get); err != nil {
			in.log.Warn("unsupported packet batch", "err", err)
			in.metrics.Add("store_bad_batches_total", 1)
			continue
		}
		n, err := event.DecodePackets(m.Data(), func(event.Packet) error { return nil })
		if err != nil {
			in.log.Warn("bad packet batch", "err", err)
			in.metrics.Add("store_bad_batches_total", 1)
			continue
		}
		if want := h.Get(event.HeaderCount); want != strconv.Itoa(n) {
			in.log.Warn("packet batch count mismatch", "header", want, "decoded", n)
			in.metrics.Add("store_batch_count_mismatch_total", 1)
		}
		// Erro aqui é de banco, não de formato: aborta a transação e o lote volta por Nak.
		if _, err := event.DecodePackets(m.Data(), func(p event.Packet) error {
			tss = append(tss, p.TsNs)
			return in.packet(ctx, tx, st, p)
		}); err != nil {
			return fmt.Errorf("store packet: %w", err)
		}
	}
	// Eventos que chegaram antes dos pacotes (no mesmo lote ou antes) acham a conexão agora.
	if err := in.flushPending(ctx, tx, false); err != nil {
		return err
	}
	if err := in.writeLate(ctx, tx); err != nil {
		return err
	}
	if err := in.flushDirty(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	in.commitBatch()
	in.publishLive()
	now := in.now().UnixNano()
	in.lagMu.Lock()
	for _, ts := range tss {
		in.lags = append(in.lags, float64(now-ts)/1e6)
	}
	in.lagMu.Unlock()
	if in.prom != nil {
		for _, ts := range append(tss, in.appTs...) {
			in.prom.lag(time.Duration(now - ts))
		}
	}
	in.metrics.Add("store_packets_total", float64(len(tss)))
	// O lote já está gravado: falha da finalização (conexões encerradas por reuso da 5-tupla) nunca vira Nak,
	// porque a reentrega duplicaria pacotes e eventos; as conexões ficam na fila para a próxima tentativa.
	if err := in.finalizeQueued(ctx); err != nil {
		in.log.Error("finalize after commit", "err", err)
	}
	return nil
}

func (in *Ingestor) packet(ctx context.Context, tx *sql.Tx, st *stmts, p event.Packet) error {
	fi := parseFrame(p.Frame)
	res := in.flows.handle(fi, p.TsNs)
	if res.evicted != nil {
		// Despejada pela tabela cheia (ADR 0034 item 1): sem registro nem avulso; a linha sai com as filhas.
		in.prom.flowDropped(dropEvicted)
		if _, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE conn_id = ?", res.evicted.id); err != nil {
			return err
		}
	}
	if res.dropped {
		in.prom.flowDropped(dropTableFull)
		return nil // 5-tupla nova recusada com a tabela cheia: nada é gravado
	}
	if res.ended != nil {
		// Já saiu da tabela: entra na fila de finalização mesmo que este lote seja desfeito.
		in.toFinalize = append(in.toFinalize, res.ended)
	}
	if c := res.conn; c != nil {
		// flags do capture: offload suspeito e frame cortado pelo snaplen (pcap incompleto); sob a trava da
		// tabela, que a API usa para ler o registro ao vivo (task 158)
		off := p.Flags&event.FlagOffloadSuspect != 0 && !c.offloadSuspect
		cut := p.Flags&event.FlagTruncated != 0 && !c.truncated
		if off || cut {
			in.flows.mark(c, cut, off)
		}
	}
	if res.hidden {
		return nil // probe apagado: a linha já saiu do banco e não volta (ADR 0034 item 8)
	}
	if res.late {
		in.metrics.Add("store_late_packets_total", 1)
		c := res.conn
		if c.degraded {
			return nil
		}
		frame, keep := in.pcapFrame(c, fi, p.Frame)
		if !keep {
			return nil
		}
		// a conexão pode ter saído do banco (retenção, DELETE): o tardio é descartado, sem derrubar o lote
		if _, err := st.insPkt.ExecContext(ctx, c.id, p.TsNs, int(p.Dir), int(p.WireLen), frame); err != nil {
			in.metrics.Add("store_late_dropped_total", 1)
			return nil //nolint:nilerr // descarte deliberado
		}
		in.late[c.id] = c
		return nil
	}
	if res.stray {
		in.metrics.Add("store_stray_total", 1)
		in.prom.strayPackets(1)
		in.liveStray(fi, p.TsNs, strayRecord(fi, p.TsNs, p.Dir, int(p.WireLen)))
		return st.insertStray(ctx, fi, p)
	}
	c := res.conn
	if res.created {
		// As métricas contam no commit (commitBatch): no rollback a conexão é recriada pela reentrega.
		in.batchCreated = append(in.batchCreated, c)
		rec, _ := json.Marshal(c.record(0, ""))
		if _, err := st.insConn.ExecContext(ctx, c.id, l4Name(c.l4), c.family, c.client.Addr().String(), int(c.client.Port()),
			c.server.Addr().String(), int(c.server.Port()), l4Name(c.l4), c.started, boolInt(c.degraded), string(rec), c.started); err != nil {
			return fmt.Errorf("insert connection: %w", err)
		}
		// O ID pode ser o de uma conexão criada antes só pelos eventos (pacotes atrasados).
		if err := in.adoptEventOnly(ctx, tx, c, keyOf(c.l4, c.client, c.server)); err != nil {
			return err
		}
		in.liveConn(LiveConnOpened, c.liveSummary(), c.started)
	}
	if c.degraded {
		return nil // modo degradado: sem pcap nem bytes crus
	}
	frame, keep := in.pcapFrame(c, fi, p.Frame)
	if !keep {
		return nil
	}
	_, err := st.insPkt.ExecContext(ctx, c.id, p.TsNs, int(p.Dir), int(p.WireLen), frame)
	return err
}

// pcapFrame conta o frame no pcap da conexão. Até PcapMax o frame entra inteiro; depois, só os cabeçalhos, com
// orçamento próprio de mais PcapMax bytes; esgotado, o pacote não entra em packets (keep false) e o pcap fica
// com no máximo ~2×PcapMax (spec 004 RF-04, ADR 0034). A análise IP/TCP já rodou em handle.
func (in *Ingestor) pcapFrame(c *conn, fi frameInfo, frame []byte) (out []byte, keep bool) {
	size := int64(len(frame)) + 16 // registro do pcap: cabeçalho de 16 bytes + frame
	if c.pcapHdrBytes == 0 && c.pcapBytes+size <= in.cfg.PcapMax {
		c.pcapBytes += size
		return frame, true
	}
	if !c.truncated {
		in.flows.mark(c, true, false)
	}
	if fi.headers > 0 && fi.headers < len(frame) {
		frame = frame[:fi.headers]
	}
	size = int64(len(frame)) + 16
	if c.pcapHdrBytes+size > in.cfg.PcapMax {
		return nil, false
	}
	c.pcapHdrBytes += size
	return frame, true
}

// readyEnd é o fim de uma conexão finalizada e o motivo, para fs_store_record_ready_seconds.
type readyEnd struct {
	end    int64
	reason string // close (FIN/RST), quic_close ou idle
}

// writeLate anexa ao pcap gravado os pacotes tardios do lote e refaz o registro (o fim pode mudar e um RST
// depois do FIN aparece no fechamento). O estado de aplicação é relido de app_events em flushDirty, porque o
// registro em memória não tem os eventos que chegaram depois da finalização.
func (in *Ingestor) writeLate(ctx context.Context, tx *sql.Tx) error {
	for id, c := range in.late {
		var one int
		switch err := tx.QueryRowContext(ctx, "SELECT 1 FROM connections WHERE conn_id = ?", id).Scan(&one); {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, "DELETE FROM packets WHERE conn_id = ?", id); err != nil {
				return err
			}
			continue
		case err != nil:
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT ts_ns, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", id)
		if err != nil {
			return err
		}
		var add []byte
		for rows.Next() {
			var ts int64
			var wl int
			var fr []byte
			if err := rows.Scan(&ts, &wl, &fr); err != nil {
				_ = rows.Close()
				return err
			}
			add = appendPcapRecord(add, ts, wl, fr)
		}
		_ = rows.Close()
		if _, err := tx.ExecContext(ctx, "DELETE FROM packets WHERE conn_id = ?", id); err != nil {
			return err
		}
		var pcap []byte
		switch err := tx.QueryRowContext(ctx, "SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&pcap); {
		case err == nil:
			if _, err := tx.ExecContext(ctx, "UPDATE pcaps SET data = ?, truncated = ? WHERE conn_id = ?", append(pcap, add...), boolInt(c.truncated), id); err != nil {
				return err
			}
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		end := c.endTs()
		r := c.record(end, "")
		rec, _ := json.Marshal(r)
		if _, err := tx.ExecContext(ctx, "UPDATE connections SET ended_ns = ?, pcap_truncated = ?, record_json = ? WHERE conn_id = ?",
			end, boolInt(c.truncated), string(rec), id); err != nil {
			return err
		}
		if _, ok := in.dirty[id]; !ok {
			in.dirty[id] = dirtyConn{}
		}
	}
	clear(in.late)
	return nil
}

// Finalize põe as conexões terminadas na fila de finalização e a processa (finalizeQueued).
func (in *Ingestor) Finalize(ctx context.Context, conns []*conn) error {
	in.toFinalize = append(in.toFinalize, conns...)
	return in.finalizeQueued(ctx)
}

// finalizeQueued materializa o pcap das conexões da fila (ou as converte em pacotes avulsos) e grava o registro
// final (ADR 0034). As que nunca falharam vão numa transação só; se ela falha, cada uma é tentada de novo nas
// rodadas seguintes numa transação própria (uma conexão problemática não leva as outras), até maxFinalizeTries;
// esgotadas, a linha é fechada com ended_ns e o que houver. Uma conexão só sai da fila depois do commit.
// Devolve o primeiro erro, só para o log.
func (in *Ingestor) finalizeQueued(ctx context.Context) error {
	if len(in.toFinalize) == 0 {
		return nil
	}
	var fresh, retry []*conn
	for _, c := range in.toFinalize {
		if c.finalTries == 0 {
			fresh = append(fresh, c)
		} else {
			retry = append(retry, c)
		}
	}
	in.toFinalize = nil
	var first error
	fail := func(err error) {
		in.metrics.Add("store_ingest_errors_total", 1)
		if first == nil {
			first = err
		}
	}
	if len(fresh) > 0 {
		if err := in.finalizeTx(ctx, fresh); err != nil {
			fail(err)
			for _, c := range fresh {
				c.finalTries = 1
			}
			in.toFinalize = append(in.toFinalize, fresh...)
		} else {
			in.flows.finalized(fresh...)
		}
	}
	for _, c := range retry {
		in.metrics.Add("store_finalize_retries_total", 1)
		err := in.finalizeTx(ctx, []*conn{c})
		if err == nil {
			in.flows.finalized(c)
			continue
		}
		fail(err)
		c.finalTries++
		if c.finalTries < maxFinalizeTries {
			in.toFinalize = append(in.toFinalize, c)
			continue
		}
		in.log.Error("finalize gave up", "conn_id", c.id, "tries", c.finalTries, "err", err)
		in.closeUnfinalized(ctx, c)
		in.flows.finalized(c)
	}
	return first
}

// closeUnfinalized fecha a linha de uma conexão cuja finalização falhou maxFinalizeTries vezes: ended_ns e o
// registro final, sem pcap (os frames ficam em packets e saem com a linha na retenção). Se nem isso grava, a
// retenção a apaga como órfã (linha aberta fora da memória do ingest).
func (in *Ingestor) closeUnfinalized(ctx context.Context, c *conn) {
	end := c.endTs()
	rec, _ := json.Marshal(c.record(end, "timeout"))
	if _, err := in.db.ExecContext(ctx, "UPDATE connections SET ended_ns = ?, record_json = ?, updated_ns = ? WHERE conn_id = ? AND ended_ns IS NULL",
		end, string(rec), max(end, in.now().UnixNano()), c.id); err != nil {
		in.log.Error("close unfinalized connection", "conn_id", c.id, "err", err)
	}
}

// finalStat é o que a finalização conta nas métricas, aplicado só depois do commit (a nova tentativa não conta
// duas vezes).
type finalStat struct {
	l4, proto string
	stray     int
}

// finalizeTx finaliza as conexões numa transação.
func (in *Ingestor) finalizeTx(ctx context.Context, conns []*conn) error {
	in.readyEnds = in.readyEnds[:0]
	in.finalStats = in.finalStats[:0]
	err := func() error {
		tx, err := in.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		for _, c := range conns {
			if err := in.finalizeOne(ctx, tx, c); err != nil {
				return err
			}
		}
		return tx.Commit()
	}()
	if err != nil {
		in.liveBatch = nil // os eventos ao vivo são refeitos na nova tentativa
		return err
	}
	in.publishLive()
	for _, s := range in.finalStats {
		if s.stray > 0 {
			in.metrics.Add("store_stray_total", float64(s.stray))
			in.prom.strayPackets(s.stray)
			continue
		}
		in.prom.connection(s.l4, s.proto)
	}
	if in.prom != nil {
		now := in.now().UnixNano()
		for _, e := range in.readyEnds {
			in.prom.ready(time.Duration(max(now-e.end, 0)), e.reason)
		}
	}
	return nil
}

func (in *Ingestor) finalizeOne(ctx context.Context, tx *sql.Tx, c *conn) error {
	if c.unstored {
		// A linha foi desfeita com o lote que a criou e a reentrega não chegou: nada gravado a finalizar.
		in.log.Warn("connection without stored row dropped", "conn_id", c.id)
		return nil
	}
	if in.flows.isHidden(c.id) {
		return nil // probe apagado pelo DELETE: a linha já saiu, nada a gravar (finalized tira do conjunto)
	}
	rows, err := tx.QueryContext(ctx, "SELECT ts_ns, dir, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", c.id)
	if err != nil {
		return err
	}
	type pkt struct {
		ts      int64
		dir     uint8
		wireLen int
		frame   []byte
	}
	var pkts []pkt
	for rows.Next() {
		var p pkt
		if err := rows.Scan(&p.ts, &p.dir, &p.wireLen, &p.frame); err != nil {
			_ = rows.Close()
			return err
		}
		pkts = append(pkts, p)
	}
	_ = rows.Close()

	// Com eventos de aplicação a conexão existe de fato (ex. capture reiniciado no meio dela): não vira avulso.
	if c.isStray() && c.app.events == 0 {
		// Sem resposta do outro lado: pacotes avulsos (spec 004 RF-03). O fato "é avulso" só existe quando o
		// store decide, na saída da tabela (ociosidade de 30 s no UDP, por exemplo): o ts do feed é esse instante
		// (ADR 0025, task 108); o registro e /api/v1/packets continuam com o ts do pacote.
		decided := in.now().UnixNano()
		for _, p := range pkts {
			fi := parseFrame(p.frame)
			sr := strayRecord(fi, p.ts, p.dir, p.wireLen)
			in.liveStray(fi, max(decided, p.ts), sr)
			rec, _ := json.Marshal(sr)
			if _, err := tx.ExecContext(ctx, insStraySQL, p.ts, int(p.dir), l4Name(fi.proto), addrOrNil(fi, true), addrOrNil(fi, false), string(rec), p.frame); err != nil {
				return err
			}
		}
		if len(pkts) > 0 {
			in.finalStats = append(in.finalStats, finalStat{stray: len(pkts)})
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE conn_id = ?", c.id)
		return err
	}

	pcap := pcapHeader(in.cfg.Snaplen)
	for _, p := range pkts {
		pcap = appendPcapRecord(pcap, p.ts, p.wireLen, p.frame)
	}
	end := c.endTs()
	how, reason := "timeout", "idle"
	switch {
	case c.l4 == protoUDP && c.closing():
		how, reason = "", "quic_close"
	case c.closing():
		how, reason = "", "close" // closeInfo decide (fin/rst)
	}
	r := c.record(end, how)
	rec, _ := json.Marshal(r)
	if !c.degraded {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO pcaps (conn_id, data, truncated) VALUES (?, ?, ?)", c.id, pcap, boolInt(c.truncated)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM packets WHERE conn_id = ?", c.id); err != nil {
		return err
	}
	// updated_ns é o relógio do store no instante em que ele registrou o fechamento (settle do long-poll, ADR 0029):
	// no fim por ociosidade, bem depois do último pacote.
	if _, err = tx.ExecContext(ctx, "UPDATE connections SET ended_ns = ?, pcap_truncated = ?, record_json = ?, proto = ?, updated_ns = ? WHERE conn_id = ?",
		end, boolInt(c.truncated), string(rec), r.Proto, max(end, in.now().UnixNano()), c.id); err != nil {
		return err
	}
	// Por ociosidade, o fato "fechou" só existe quando o store decide (ADR 0025): o ts do feed é esse instante;
	// data.ended e o registro continuam com o último pacote.
	liveTs := end
	if reason == "idle" {
		liveTs = in.now().UnixNano()
	}
	in.liveConn(LiveConnClosed, summaryFrom(r), liveTs)
	in.finalStats = append(in.finalStats, finalStat{l4: r.L4, proto: r.Proto})
	in.readyEnds = append(in.readyEnds, readyEnd{end, reason})
	return nil
}

// recoverOrphans fecha conexões que ficaram abertas no banco por um reinício do store.
func (in *Ingestor) recoverOrphans(ctx context.Context) error {
	rows, err := in.db.QueryContext(ctx, "SELECT conn_id, record_json FROM connections WHERE ended_ns IS NULL")
	if err != nil {
		return err
	}
	type orphan struct{ id, rec string }
	var list []orphan
	for rows.Next() {
		var o orphan
		if err := rows.Scan(&o.id, &o.rec); err == nil {
			list = append(list, o)
		}
	}
	_ = rows.Close()
	for _, o := range list {
		var last sql.NullInt64
		_ = in.db.QueryRowContext(ctx, "SELECT max(ts_ns) FROM packets WHERE conn_id = ?", o.id).Scan(&last)
		var r connectionJSON
		_ = json.Unmarshal([]byte(o.rec), &r)
		// updated_ns usa o relógio do store no reinício (settle do long-poll, ADR 0029), não o último pacote.
		now := in.now().UnixNano()
		end := last.Int64
		if end == 0 {
			end = now
		}
		pcap, truncated, err := in.orphanPcap(ctx, o.id)
		if err != nil {
			return err
		}
		r.Ended, r.Close = tsPtr(end), closeJSON{By: "unknown", How: "timeout"}
		r.PcapTruncated = r.PcapTruncated || truncated
		rec, _ := json.Marshal(r)
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT OR REPLACE INTO pcaps (conn_id, data, truncated) VALUES (?, ?, ?)", []any{o.id, pcap, boolInt(r.PcapTruncated)}},
			{"DELETE FROM packets WHERE conn_id = ?", []any{o.id}},
			{
				"UPDATE connections SET ended_ns = ?, pcap_truncated = ?, record_json = ?, updated_ns = ? WHERE conn_id = ?",
				[]any{end, boolInt(r.PcapTruncated), string(rec), max(end, now), o.id},
			},
		} {
			if _, err := in.db.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
	}
	if len(list) > 0 {
		in.log.Info("recovered orphan connections", "count", len(list))
	}
	return nil
}

// orphanPcap monta o pcap de uma conexão órfã com o mesmo orçamento do ingest (pcapFrame): frames até PcapMax e
// registros "só cabeçalhos" até mais PcapMax; o que passa disso fica fora, e a leitura para ali (memória
// limitada mesmo com mais linhas em packets). truncated vem de um frame menor que o fio (snaplen ou corte nos
// cabeçalhos) ou do orçamento esgotado (task 137).
func (in *Ingestor) orphanPcap(ctx context.Context, id string) (pcap []byte, truncated bool, err error) {
	pcap = pcapHeader(in.cfg.Snaplen)
	rows, err := in.db.QueryContext(ctx, "SELECT ts_ns, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", id)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	var full, hdr int64
	for rows.Next() {
		var ts int64
		var wl int
		var f []byte
		if rows.Scan(&ts, &wl, &f) != nil {
			continue
		}
		size := int64(len(f)) + 16
		switch {
		case hdr == 0 && full+size <= in.cfg.PcapMax:
			full += size
		case hdr+size <= in.cfg.PcapMax:
			hdr += size
			truncated = true
		default:
			return pcap, true, nil
		}
		if wl > len(f) {
			truncated = true
		}
		pcap = appendPcapRecord(pcap, ts, wl, f)
	}
	return pcap, truncated, rows.Err()
}

func (in *Ingestor) publishMetrics() {
	in.lagMu.Lock()
	lags := in.lags
	in.lags = nil
	in.lagMu.Unlock()
	if len(lags) > 0 {
		sort.Float64s(lags)
		in.metrics.Set("store_ingest_lag_ms", lags[min(len(lags)-1, int(0.95*float64(len(lags))))])
	}
	in.metrics.Set("store_connections_open", float64(in.flows.open()))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func addrOrNil(fi frameInfo, src bool) any {
	if !fi.ok {
		return nil
	}
	if src {
		return fi.src.String()
	}
	return fi.dst.String()
}

const insStraySQL = "INSERT INTO stray_packets (ts_ns, dir, l4, src_ip, dst_ip, record_json, frame) VALUES (?, ?, ?, ?, ?, ?, ?)"

type stmts struct {
	insConn, insPkt, insStray *sql.Stmt
}

func prepare(ctx context.Context, tx *sql.Tx) (*stmts, error) {
	var s stmts
	var err error
	if s.insConn, err = tx.PrepareContext(ctx, `INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port,
		proto, started_ns, degraded, record_json, updated_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (conn_id) DO UPDATE SET started_ns = excluded.started_ns, ended_ns = NULL, degraded = excluded.degraded,
		record_json = excluded.record_json, updated_ns = excluded.updated_ns`); err != nil {
		return nil, err
	}
	if s.insPkt, err = tx.PrepareContext(ctx, "INSERT INTO packets (conn_id, ts_ns, dir, wire_len, frame) VALUES (?, ?, ?, ?, ?)"); err != nil {
		return nil, err
	}
	if s.insStray, err = tx.PrepareContext(ctx, insStraySQL); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *stmts) close() {
	for _, x := range []*sql.Stmt{s.insConn, s.insPkt, s.insStray} {
		if x != nil {
			_ = x.Close()
		}
	}
}

func (s *stmts) insertStray(ctx context.Context, fi frameInfo, p event.Packet) error {
	rec, _ := json.Marshal(strayRecord(fi, p.TsNs, p.Dir, int(p.WireLen)))
	_, err := s.insStray.ExecContext(ctx, p.TsNs, int(p.Dir), l4Name(fi.proto), addrOrNil(fi, true), addrOrNil(fi, false), string(rec), p.Frame)
	return err
}
