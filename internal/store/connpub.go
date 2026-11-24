package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Publicação do estado das conexões para o serviço bot (spec 004 RF-12, ADR 0047, asyncapi
// fs.v1.store.connection): o ingest acumula os estágios durante a transação do lote e, só depois do commit, os
// entrega sem bloquear a uma fila; uma goroutine própria monta o envelope, corta o registro acima de 900 KiB e
// publica no NATS core. Sem assinante, o NATS descarta.

// connPubQueue é o tamanho da fila entre o ingest e a publicação (spec 004 RF-12).
const connPubQueue = 4096

// connPubCoalesce é a espera depois de cada envio, para juntar os lotes seguintes (atraso máximo acrescentado ao
// bot, que espera a visão por até FS_BOT_VIEW_WAIT = 100 ms).
const connPubCoalesce = 5 * time.Millisecond

// connPubUpdateEvery é o intervalo mínimo entre dois updated da mesma conexão (pubConnOpen).
const connPubUpdateEvery = 100 * time.Millisecond

// connPubBuckets: tempo de montar e publicar uma mensagem, de 10 µs a 1 s.
var connPubBuckets = prometheus.ExponentialBucketsRange(0.00001, 1, 11)

// connStage é um estágio a publicar. rec é o registro já serializado na transação (opened, closed e conexões
// gravadas); sem rec (updated de conexão aberta), o registro é montado na hora do envio pelo estado ao vivo, fora
// do laço de ingest.
type connStage struct {
	stage string
	ts    int64
	id    string
	rec   []byte
	flow  *event.Flow
	probe *string
}

// connPublisher publica os estágios em fs.v1.store.connection.
type connPublisher struct {
	publish func(subject string, data []byte) error // nc.Publish
	version string
	live    func(id string) (connectionJSON, bool) // registro de uma conexão aberta (flowTable.live)
	max     int                                    // teto da mensagem (event.MaxEventBytes; testes trocam)

	// Fila de até connPubQueue estágios. O ingest entrega o lote inteiro de uma vez e acorda o envio por wake
	// (capacidade 1): uma troca de goroutine por lote, não por estágio (o sinal custava mais que a serialização).
	mu   sync.Mutex
	q    []connStage
	wake chan struct{}

	dropped   atomic.Int64 // fs_store_conn_publish_dropped_total
	published atomic.Int64
	accepted  atomic.Int64         // estágios aceitos na fila
	handled   atomic.Int64         // estágios tirados da fila e tratados (publicados, pulados ou recusados)
	seconds   prometheus.Histogram // fs_store_conn_publish_seconds
}

func newConnPublisher(publish func(string, []byte) error, version string, live func(string) (connectionJSON, bool)) *connPublisher {
	return &connPublisher{
		publish: publish, version: version, live: live, max: event.MaxEventBytes, wake: make(chan struct{}, 1),
		seconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "fs_store_conn_publish_seconds", Help: "Time to build and publish one fs.v1.store.connection message (for the bot service).", Buckets: connPubBuckets,
		}),
	}
}

// collectors devolve as métricas do /metrics.
func (p *connPublisher) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "fs_store_conn_publish_dropped_total", Help: "fs.v1.store.connection messages dropped: queue full (4096) or refused by NATS.",
		}, func() float64 { return float64(p.dropped.Load()) }),
		p.seconds,
	}
}

// enqueue entrega os estágios sem bloquear: o que não cabe na fila é descartado e contado.
func (p *connPublisher) enqueue(ss ...connStage) {
	if len(ss) == 0 {
		return
	}
	p.mu.Lock()
	n := min(len(ss), connPubQueue-len(p.q))
	p.q = append(p.q, ss[:n]...)
	p.mu.Unlock()
	p.accepted.Add(int64(n))
	if n < len(ss) {
		p.dropped.Add(int64(len(ss) - n))
	}
	if n > 0 {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}

// idle informa se tudo o que foi aceito já foi tratado.
func (p *connPublisher) idle() bool { return p.accepted.Load() == p.handled.Load() }

// take tira da fila tudo o que espera envio.
func (p *connPublisher) take() []connStage {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.q
	p.q = nil
	return out
}

// Run publica até done fechar (receptor nil: só espera).
func (p *connPublisher) Run(done <-chan struct{}) {
	if p == nil {
		<-done
		return
	}
	for {
		select {
		case <-done:
			return
		case <-p.wake:
			for _, s := range p.take() {
				p.send(s)
				p.handled.Add(1)
			}
			// junta os lotes que chegarem nos próximos connPubCoalesce: menos trocas de goroutine com o ingest
			select {
			case <-done:
				return
			case <-time.After(connPubCoalesce):
			}
		}
	}
}

// send monta e publica um estágio.
func (p *connPublisher) send(s connStage) {
	start := time.Now()
	rec := s.rec
	if rec == nil {
		r, ok := p.live(s.id)
		if !ok {
			return // a conexão já saiu da tabela: o closed vem na fila
		}
		rec, _ = json.Marshal(r)
		s.flow, s.probe = flowOf(r), r.ProbeID
	}
	msg := p.encode(s, rec)
	if err := p.publish(event.SubjectStoreConnection, msg); err != nil {
		p.dropped.Add(1)
		return
	}
	p.published.Add(1)
	p.seconds.Observe(time.Since(start).Seconds())
}

// encode monta o envelope; acima do teto, corta o registro (ADR 0032) e marca connection_truncated.
func (p *connPublisher) encode(s connStage, rec []byte) []byte {
	env := event.Envelope{
		SchemaVersion: event.SchemaVersion, Service: event.ServiceStore, ServiceVersion: p.version,
		Ts: event.FormatTime(time.Unix(0, s.ts)), Flow: s.flow, ProbeID: s.probe,
	}
	head, _ := json.Marshal(env)
	head = head[:len(head)-1] // sem o "}" final: o payload vem em seguida
	build := func(rec []byte, truncated bool) []byte {
		out := make([]byte, 0, len(head)+len(rec)+96)
		out = append(out, head...)
		out = append(out, `,"payload":{"stage":`...)
		out = strconv.AppendQuote(out, s.stage)
		out = append(out, `,"connection_truncated":`...)
		out = strconv.AppendBool(out, truncated)
		out = append(out, `,"connection":`...)
		out = append(out, rec...)
		return append(out, "}}"...)
	}
	msg := build(rec, false)
	if len(msg) <= p.max {
		return msg
	}
	return build(fitRecord(rec, p.max-(len(msg)-len(rec))), true)
}

func flowOf(r connectionJSON) *event.Flow {
	return &event.Flow{L4: r.L4, SrcIP: r.Src.IP, SrcPort: r.Src.Port, DstIP: r.Dst.IP, DstPort: r.Dst.Port}
}

// fitRecord reduz o registro até caber em limit bytes: corta pela metade, repetidamente, a maior lista (http,
// http2.streams, http3.requests, websocket.frames); sem lista a cortar, tira a maior camada de aplicação inteira
// (tls, http2, http3, raw, websocket). Os totais (requests, totals) ficam como estavam.
func fitRecord(rec []byte, limit int) []byte {
	var r connectionJSON
	if err := json.Unmarshal(rec, &r); err != nil {
		return []byte("null")
	}
	for range 64 {
		out, _ := json.Marshal(r)
		if len(out) <= limit {
			return out
		}
		if !halveLargestList(&r) && !dropLargestLayer(&r) {
			return out // só sobrou o núcleo IP/TCP, que não chega perto do teto
		}
	}
	out, _ := json.Marshal(r)
	return out
}

// halveLargestList corta pela metade a lista de aplicação com mais bytes; false se não houver lista com itens.
func halveLargestList(r *connectionJSON) bool {
	type cand struct {
		size int
		cut  func()
	}
	var cs []cand
	if n := len(r.HTTP); n > 0 {
		size := 0
		for _, h := range r.HTTP {
			size += len(h)
		}
		cs = append(cs, cand{size, func() { r.HTTP = r.HTTP[:n/2] }})
	}
	if r.WebSocket != nil && len(r.WebSocket.Frames) > 0 {
		n := len(r.WebSocket.Frames)
		cs = append(cs, cand{n * 120, func() { r.WebSocket.Frames, r.WebSocket.FramesTruncated = r.WebSocket.Frames[:n/2], true }})
	}
	for _, l := range []struct {
		obj *json.RawMessage
		key string
	}{{&r.HTTP2, "streams"}, {&r.HTTP3, "requests"}} {
		var m map[string]json.RawMessage
		if len(*l.obj) == 0 || json.Unmarshal(*l.obj, &m) != nil {
			continue
		}
		var items []json.RawMessage
		if json.Unmarshal(m[l.key], &items) != nil || len(items) == 0 {
			continue
		}
		obj, key := l.obj, l.key
		cs = append(cs, cand{len(m[key]), func() {
			m[key], _ = json.Marshal(items[:len(items)/2])
			*obj, _ = json.Marshal(m)
		}})
	}
	if len(cs) == 0 {
		return false
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].size > cs[j].size })
	cs[0].cut()
	return true
}

// dropLargestLayer tira a maior camada de aplicação; false se não restar nenhuma.
func dropLargestLayer(r *connectionJSON) bool {
	layers := []*json.RawMessage{&r.TLS, &r.HTTP2, &r.HTTP3, &r.Raw}
	var big *json.RawMessage
	for _, l := range layers {
		if len(*l) > 0 && (big == nil || len(*l) > len(*big)) {
			big = l
		}
	}
	if big != nil {
		*big = nil
		return true
	}
	if r.WebSocket != nil {
		r.WebSocket = nil
		return true
	}
	if r.HTTP != nil {
		r.HTTP = nil
		return true
	}
	return false
}

// Lado do ingest: os estágios do lote em curso, entregues à fila só depois do commit.

// SetConnPublisher liga a publicação de fs.v1.store.connection.
func (in *Ingestor) SetConnPublisher(p *connPublisher) { in.conns = p }

// pubConn acumula um estágio com o registro já serializado. Conexão em modo degradado publica só opened e closed.
func (in *Ingestor) pubConn(stage string, ts int64, rec []byte, r *connectionJSON) {
	if in.conns == nil || (r.Degraded && stage == event.StageUpdated) {
		return
	}
	in.connBatch = append(in.connBatch, connStage{stage: stage, ts: ts, id: r.ConnID, rec: rec, flow: flowOf(*r), probe: r.ProbeID})
}

// pubConnOpen acumula o updated de uma conexão aberta, no máximo um por conexão a cada connPubUpdateEvery
// (parede): o primeiro sai no lote; os seguintes dentro da janela viram um só, no fim dela (flushConnTrails),
// com o estado daquele instante. O bot substitui o registro a cada estágio (spec 018), então só o último
// importa; montar o registro inteiro a cada evento custava mais de 10% do ingest (task 268).
func (in *Ingestor) pubConnOpen(id string, _ int64, degraded bool) {
	if in.conns == nil || degraded {
		return
	}
	if in.connUpd == nil {
		in.connUpd, in.connLast, in.connTrail = map[string]struct{}{}, map[string]int64{}, map[string]int64{}
	}
	if _, ok := in.connUpd[id]; ok {
		return
	}
	now := in.now().UnixNano()
	if last, ok := in.connLast[id]; ok && now-last < int64(connPubUpdateEvery) {
		if _, ok := in.connTrail[id]; !ok {
			in.connTrail[id] = last + int64(connPubUpdateEvery)
		}
		return
	}
	in.connUpd[id] = struct{}{}
	in.connLast[id] = now
	delete(in.connTrail, id)
	in.connBatch = append(in.connBatch, connStage{stage: event.StageUpdated, ts: now, id: id})
}

// flushConnTrails publica os updated adiados cuja janela venceu e esquece as janelas já sem efeito. Chamado no
// laço de ingest, fora de transação (afterBatch).
func (in *Ingestor) flushConnTrails() {
	if in.conns == nil || len(in.connLast) == 0 {
		return
	}
	now := in.now().UnixNano()
	var out []connStage
	for id, due := range in.connTrail {
		if now < due {
			continue
		}
		delete(in.connTrail, id)
		in.connLast[id] = now
		if s, ok := in.liveStage(connStage{stage: event.StageUpdated, ts: now, id: id}); ok {
			out = append(out, s)
		}
	}
	for id, last := range in.connLast {
		if _, trail := in.connTrail[id]; !trail && now-last >= int64(connPubUpdateEvery) {
			delete(in.connLast, id)
		}
	}
	in.conns.enqueue(out...)
}

// liveStage monta o registro de um updated de conexão aberta (fora da transação); false se ela já saiu da tabela.
func (in *Ingestor) liveStage(s connStage) (connStage, bool) {
	r, ok := in.flows.live(s.id)
	if !ok {
		return s, false
	}
	s.rec = marshalRecord(r)
	s.flow, s.probe = flowOf(r), r.ProbeID
	return s, true
}

// marshalRecord serializa o registro como json.Marshal, mas emenda as camadas de aplicação (já JSON compacto,
// vindas dos eventos ou dos caches de layers) sem revalidá-las: a revalidação era metade do custo do updated
// (task 268). As camadas são os últimos campos de connectionJSON, na mesma ordem; só muda o escape de HTML
// (<, >, & ficam literais), equivalente em JSON.
func marshalRecord(r connectionJSON) []byte {
	tls, http, h2, h3, ws, raw := r.TLS, r.HTTP, r.HTTP2, r.HTTP3, r.WebSocket, r.Raw
	r.TLS, r.HTTP, r.HTTP2, r.HTTP3, r.WebSocket, r.Raw = nil, nil, nil, nil, nil, nil
	head, _ := json.Marshal(r)
	n := len(head) + len(tls) + len(h2) + len(h3) + len(raw) + 64
	for _, h := range http {
		n += len(h) + 1
	}
	out := make([]byte, 0, n)
	out = append(out, head[:len(head)-1]...)
	field := func(key string) {
		out = append(out, ',', '"')
		out = append(out, key...)
		out = append(out, '"', ':')
	}
	if len(tls) > 0 {
		field("tls")
		out = append(out, tls...)
	}
	if len(http) > 0 {
		field("http")
		out = append(out, '[')
		for i, h := range http {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, h...)
		}
		out = append(out, ']')
	}
	if len(h2) > 0 {
		field("http2")
		out = append(out, h2...)
	}
	if len(h3) > 0 {
		field("http3")
		out = append(out, h3...)
	}
	if ws != nil {
		b, _ := json.Marshal(ws)
		field("websocket")
		out = append(out, b...)
	}
	if len(raw) > 0 {
		field("raw")
		out = append(out, raw...)
	}
	return append(out, '}')
}

// publishConns entrega à fila o que o lote confirmado produziu.
func (in *Ingestor) publishConns() {
	if in.conns != nil {
		out := in.connBatch[:0]
		for _, s := range in.connBatch {
			if s.rec == nil {
				var ok bool
				if s, ok = in.liveStage(s); !ok {
					continue
				}
			}
			if s.stage == event.StageClosed {
				delete(in.connLast, s.id)
				delete(in.connTrail, s.id)
			}
			out = append(out, s)
		}
		in.conns.enqueue(out...)
	}
	in.discardConns()
}

// discardConns esquece os estágios do lote (desfeito ou já entregue).
func (in *Ingestor) discardConns() {
	clear(in.connBatch)
	in.connBatch = in.connBatch[:0]
	clear(in.connUpd)
}

// Estágios garantidos (ADR 0076): no canal do bot o opened só sai com a conexão estabelecida, e toda conexão com
// opened publicado (nos dois canais) recebe exatamente um closed, com discarded quando sai do banco sem registro.

// Valores de connectionJSON.Discarded (openapi ConnectionSummary.discarded).
const (
	discardedStray   = "stray"   // virou pacotes avulsos
	discardedEvicted = "evicted" // despejada pela tabela de fluxos cheia
	discardedDeleted = "deleted" // probe apagado pelo DELETE
)

// markBotOpened liga botOpened, guardando a conexão para o rollback do lote desligar.
func (in *Ingestor) markBotOpened(c *conn) {
	c.botOpened = true
	in.botOpenUndo = append(in.botOpenUndo, c)
}

// openBot publica o opened do canal do bot quando a conexão fica estabelecida (conn.botReady), com o registro
// daquele instante (started do SYN ou do primeiro datagrama). O registro gravado passa a ser esse, para a órfã do
// reinício saber que a conexão foi estabelecida (recoverOrphans).
func (in *Ingestor) openBot(ctx context.Context, tx *sql.Tx, c *conn, ts int64) error {
	if c.botOpened || !c.botReady() {
		return nil
	}
	in.markBotOpened(c)
	r := c.record(0, "")
	rec, _ := json.Marshal(r)
	if _, err := tx.ExecContext(ctx, "UPDATE connections SET record_json = ? WHERE conn_id = ?", string(rec), c.id); err != nil {
		return fmt.Errorf("update established connection: %w", err)
	}
	in.pubConn(event.StageOpened, ts, rec, &r)
	return nil
}

// closeStages acumula o fim de uma conexão que sai da memória sem o registro final normal: connection.closed no
// tempo real e, se o opened do bot saiu, closed no canal do bot. O registro é o estado em memória (ended = último
// pacote, close pelo visto ou timeout) com discarded (vazio: registro gravado). ts é o instante da decisão.
func (in *Ingestor) closeStages(c *conn, ts int64, how, discarded string) {
	if how == "" && !c.closing() {
		how = "timeout"
	}
	r := c.record(c.endTs(), how)
	r.Discarded = discarded
	in.liveConn(LiveConnClosed, summaryFrom(r), ts)
	if c.botOpened {
		rec, _ := json.Marshal(r)
		in.pubConn(event.StageClosed, ts, rec, &r)
	}
}

// evictConn apaga a linha da conexão despejada pela tabela cheia (com as filhas) e acumula o closed com
// discarded: evicted, ou deleted se ela era de um probe apagado. ts é o relógio do store.
func (in *Ingestor) evictConn(ctx context.Context, tx *sql.Tx, c *conn) error {
	in.batchEvicted = append(in.batchEvicted, c)
	in.pktDrop = append(in.pktDrop, c)
	if _, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE conn_id = ?", c.id); err != nil {
		return err
	}
	why := discardedEvicted
	if in.flows.isHidden(c.id) {
		why = discardedDeleted
	}
	in.closeStages(c, in.now().UnixNano(), "", why)
	return nil
}

// redoEvicted refaz no lote em curso o despejo das conexões de um lote desfeito (DELETE e closed).
func (in *Ingestor) redoEvicted(ctx context.Context, tx *sql.Tx) error {
	carry := in.evictCarry
	in.evictCarry = nil
	for i, c := range carry {
		if err := in.evictConn(ctx, tx, c); err != nil {
			in.evictCarry = append(in.evictCarry, carry[i+1:]...)
			return err
		}
	}
	return nil
}

// closeEventOnly tira a conexão só de eventos do conjunto (expirada por eventOnlyIdle ou com a linha apagada) e
// acumula o closed nos dois canais: o registro gravado ou, sem a linha, o da criação com discarded: deleted.
func (in *Ingestor) closeEventOnly(ctx context.Context, tx *sql.Tx, k flowKey, eo *eventOnlyConn) error {
	in.setEventOnly(k, nil)
	r := eo.rec
	var raw string
	switch err := tx.QueryRowContext(ctx, "SELECT record_json FROM connections WHERE conn_id = ?", eo.id).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
		if eo.app != nil {
			eo.app.apply(&r)
		}
		r.Discarded = discardedDeleted
	case err != nil:
		return err
	default:
		var stored connectionJSON
		if json.Unmarshal([]byte(raw), &stored) == nil {
			r = stored
		}
	}
	now := in.now().UnixNano()
	rec, _ := json.Marshal(r)
	in.liveConn(LiveConnClosed, summaryFrom(r), now)
	in.pubConn(event.StageClosed, now, rec, &r)
	return nil
}

// orphanBotSeen decide se a órfã do reinício teve o opened do bot (ADR 0076 item 1): o registro gravado é o da
// criação ou, depois de openBot, o da conexão estabelecida (TCP com times.established; UDP com resposta do espelho
// e datagrama seguinte do cliente), ou há evento de aplicação.
func (in *Ingestor) orphanBotSeen(ctx context.Context, id string, r connectionJSON) bool {
	if r.Times != nil && r.Times.Established != nil {
		return true
	}
	if r.L4 == "udp" && r.Totals.In.Segments >= 2 && r.Totals.Out.Segments >= 1 {
		return true
	}
	var one int
	return in.db.QueryRowContext(ctx, "SELECT 1 FROM app_events WHERE conn_id = ? LIMIT 1", id).Scan(&one) == nil
}
