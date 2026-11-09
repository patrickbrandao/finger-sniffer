package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// IngestConfig controla correlação, pcap e modo degradado (spec 004 RF-02..RF-04, RF-11).
type IngestConfig struct {
	PcapMax    int64         // FS_PCAP_MAX_BYTES_PER_CONN
	TCPIdle    time.Duration // FS_IDLE_DEFAULT + 30 s
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
}

// SetLive liga o tempo real: os lotes confirmados passam a alimentar o hub.
func (in *Ingestor) SetLive(h *Hub) { in.live = h }

// NewIngestor cria o ingestor.
func NewIngestor(db *sql.DB, cfg IngestConfig, log *slog.Logger, m *service.Metrics) *Ingestor {
	return &Ingestor{
		db: db, cfg: cfg, log: log, metrics: m, now: time.Now,
		flows: newFlowTable(cfg), eventOnly: map[flowKey]*eventOnlyConn{},
		pendingKeys: map[flowKey]int{}, dirty: map[string]dirtyConn{},
	}
}

// Run busca lotes do consumidor durável, grava e confirma (ack depois do commit) até ctx terminar.
func (in *Ingestor) Run(ctx context.Context, cons jetstream.Consumer) error {
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
			if err := in.Process(ctx, msgs); err != nil {
				in.log.Error("ingest", "err", err)
				for _, m := range msgs {
					_ = m.Nak()
				}
				continue
			}
			for _, m := range msgs {
				_ = m.Ack()
			}
		}
		if err := in.Finalize(ctx, in.flows.due(in.now().UnixNano())); err != nil {
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
	Data() []byte
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

	var tss []int64
	var ended []*conn
	for _, m := range msgs {
		subject := m.Subject()
		if isAppSubject(subject) {
			if err := in.appMessage(ctx, tx, subject, m.Data()); err != nil {
				return err
			}
			continue
		}
		if subject != event.SubjectCapturePacket {
			continue // heartbeat vai por assinatura própria; subjects desconhecidos são ignorados
		}
		_, err := event.DecodePackets(m.Data(), func(p event.Packet) error {
			tss = append(tss, p.TsNs)
			return in.packet(ctx, tx, st, p, &ended)
		})
		if err != nil {
			in.log.Warn("bad packet batch", "err", err)
			in.metrics.Add("store_bad_batches_total", 1)
		}
	}
	// Eventos que chegaram antes dos pacotes (no mesmo lote ou antes) acham a conexão agora.
	if err := in.flushPending(ctx, tx, false); err != nil {
		return err
	}
	if err := in.flushDirty(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	in.publishLive()
	now := in.now().UnixNano()
	in.lagMu.Lock()
	for _, ts := range tss {
		in.lags = append(in.lags, float64(now-ts)/1e6)
	}
	in.lagMu.Unlock()
	in.metrics.Add("store_packets_total", float64(len(tss)))
	return in.Finalize(ctx, ended)
}

func (in *Ingestor) packet(ctx context.Context, tx *sql.Tx, st *stmts, p event.Packet, ended *[]*conn) error {
	fi := parseFrame(p.Frame)
	res := in.flows.handle(fi, p.TsNs)
	if res.ended != nil {
		*ended = append(*ended, res.ended)
	}
	if res.stray {
		in.metrics.Add("store_stray_total", 1)
		in.liveStray(fi, p.TsNs, strayRecord(fi, p.TsNs, p.Dir, int(p.WireLen)))
		return st.insertStray(ctx, fi, p)
	}
	c := res.conn
	if res.created {
		in.metrics.Add("store_connections_total", 1)
		if c.degraded {
			in.metrics.Add("store_degraded_connections_total", 1)
		}
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
	frame := p.Frame
	c.pcapBytes += int64(len(frame)) + 16
	if c.pcapBytes > in.cfg.PcapMax {
		c.truncated = true
		if fi.headers > 0 && fi.headers < len(frame) {
			frame = frame[:fi.headers]
		}
	}
	_, err := st.insPkt.ExecContext(ctx, c.id, p.TsNs, int(p.Dir), int(p.WireLen), frame)
	return err
}

// Finalize materializa o pcap das conexões terminadas (ou as converte em pacotes avulsos) e grava o registro final.
func (in *Ingestor) Finalize(ctx context.Context, conns []*conn) error {
	if len(conns) == 0 {
		return nil
	}
	tx, err := in.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, c := range conns {
		if err := in.finalizeOne(ctx, tx, c); err != nil {
			in.liveBatch = nil
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		in.liveBatch = nil
		return err
	}
	in.publishLive()
	return nil
}

func (in *Ingestor) finalizeOne(ctx context.Context, tx *sql.Tx, c *conn) error {
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
		// Sem resposta do outro lado: pacotes avulsos (spec 004 RF-03).
		for _, p := range pkts {
			fi := parseFrame(p.frame)
			sr := strayRecord(fi, p.ts, p.dir, p.wireLen)
			in.liveStray(fi, p.ts, sr)
			rec, _ := json.Marshal(sr)
			if _, err := tx.ExecContext(ctx, insStraySQL, p.ts, int(p.dir), l4Name(fi.proto), addrOrNil(fi, true), addrOrNil(fi, false), string(rec), p.frame); err != nil {
				return err
			}
		}
		in.metrics.Add("store_stray_total", float64(len(pkts)))
		_, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE conn_id = ?", c.id)
		return err
	}

	pcap := pcapHeader(in.cfg.Snaplen)
	for _, p := range pkts {
		pcap = appendPcapRecord(pcap, p.ts, p.wireLen, p.frame)
	}
	end := c.lastSeen
	// QUIC encerrado pelo web: o fim é o do evento, se vier depois do último pacote.
	if c.app != nil && c.app.h3CloseTs > end {
		end = c.app.h3CloseTs
	}
	how := "timeout"
	if c.closing() {
		how = "" // closeInfo decide (fin/rst)
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
	if _, err = tx.ExecContext(ctx, "UPDATE connections SET ended_ns = ?, pcap_truncated = ?, record_json = ?, proto = ?, updated_ns = ? WHERE conn_id = ?",
		end, boolInt(c.truncated), string(rec), r.Proto, end, c.id); err != nil {
		return err
	}
	in.liveConn(LiveConnClosed, summaryFrom(r), end)
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
		end := last.Int64
		if end == 0 {
			end = in.now().UnixNano()
		}
		r.Ended, r.Close = tsPtr(end), closeJSON{By: "unknown", How: "timeout"}
		rec, _ := json.Marshal(r)
		pcap := pcapHeader(in.cfg.Snaplen)
		prow, err := in.db.QueryContext(ctx, "SELECT ts_ns, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", o.id)
		if err != nil {
			return err
		}
		for prow.Next() {
			var ts int64
			var wl int
			var f []byte
			if prow.Scan(&ts, &wl, &f) == nil {
				pcap = appendPcapRecord(pcap, ts, wl, f)
			}
		}
		_ = prow.Close()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT OR REPLACE INTO pcaps (conn_id, data, truncated) VALUES (?, ?, 0)", []any{o.id, pcap}},
			{"DELETE FROM packets WHERE conn_id = ?", []any{o.id}},
			{"UPDATE connections SET ended_ns = ?, record_json = ?, updated_ns = ? WHERE conn_id = ?", []any{end, string(rec), end, o.id}},
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
