package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Janelas da correlação de eventos de aplicação (spec 004 "Comportamento").
const (
	// eventSlack é a folga antes do início da conexão: o evento pode chegar antes do lote de pacotes do SYN.
	eventSlack = 2 * time.Second
	// pendingWait é quanto um evento sem conexão espera na fila antes de criar a conexão só com os eventos.
	pendingWait = 2 * time.Second
	// eventOnlyIdle é quanto uma conexão conhecida só pelos eventos continua recebendo eventos da mesma 5-tupla.
	eventOnlyIdle = 30 * time.Second
	// lateSlack é a folga depois do fim de uma conexão gravada para eventos publicados no fechamento.
	lateSlack = 30 * time.Second
	// acceptSlack é a folga antes da chegada do pedido de conn_id (o accept no web vem antes dela, e o primeiro
	// evento da conexão pode vir antes também): a espera máxima do web pela resposta (ADR 0017).
	acceptSlack = service.ConnIDTimeout
)

// target é a conexão a que um evento pertence.
type target struct {
	id        string
	open      bool // está na tabela de fluxos (estado em memória)
	degraded  bool
	eventOnly bool // conexão criada só pelos eventos (sem pacotes)
}

// pendingEvent é um evento à espera da conexão.
type pendingEvent struct {
	ev      appEvent
	arrived int64 // relógio do store
}

// eventOnlyConn é uma conexão criada só pelos eventos, ainda aceitando eventos da mesma 5-tupla.
type eventOnlyConn struct {
	id            string
	started, last int64
	degraded      bool
	// app é o estado de aplicação mantido em memória (incremental: cada evento custa O(1), sem reler app_events);
	// nil = desconhecido (lote desfeito), recarregado de app_events no próximo uso.
	app *appState
	// rec é o registro da criação: base do closed com discarded se a linha sumir antes da expiração (ADR 0076).
	rec connectionJSON
	// O que identifica a conexão entre outras da mesma 5-tupla (task 424): accept é o início estimado pela reserva
	// de conn_id consumida na criação (0 = sem reserva); dcid é o flow.quic_dcid_hex dos eventos QUIC.
	accept int64
	dcid   string
	// prev são os DCID das conexões só de eventos anteriores na mesma 5-tupla, trocadas por esta (no máximo
	// maxPrevDCIDs, a mais recente no fim): evento com um deles é da anterior, nunca de uma conexão nova (task 427).
	prev []string
}

// maxPrevDCIDs é o teto de eventOnlyConn.prev.
const maxPrevDCIDs = 4

// Resultado de eventOnlyConn.owner.
const (
	ownerSame  = iota // o evento é da conexão
	ownerNewer        // de uma conexão nova na mesma 5-tupla, ainda sem registro
	ownerOlder        // de uma conexão anterior na mesma 5-tupla, já gravada
)

// owner decide se o evento é da conexão só de eventos ou de outra com a mesma 5-tupla (porta de origem
// reaproveitada pelo cliente ou pelo NAT, task 424). Sem pacotes, só os eventos e a reserva de conn_id dizem:
//   - antes do accept dela (reserva consumida na criação), é de uma conexão anterior;
//   - QUIC com DCID diferente do dela é outra conexão: anterior se for de antes do início dela ou se o DCID for o
//     de uma só de eventos anterior trocada por ela (prev: o web publicou com outro DCID algo que não abria
//     conexão, e os eventos seguintes da conexão de verdade voltam ao DCID original, task 427), nova nos demais
//     casos (a migração de caminho troca a 5-tupla, não o DCID do envelope, que é o do primeiro Initial);
//   - depois do fim h3 dela (com a folga dos eventos publicados no fechamento), é de uma conexão nova.
func (eo *eventOnlyConn) owner(ev appEvent) int {
	if eo.accept > 0 && ev.ts < eo.accept {
		return ownerOlder
	}
	if d := ev.quicDCID(); d != "" && eo.dcid != "" && d != eo.dcid {
		if ev.ts < eo.started || slices.Contains(eo.prev, d) {
			return ownerOlder
		}
		return ownerNewer
	}
	if a := eo.app; a != nil && a.h3Close != nil && ev.ts > a.h3CloseTs+eventSlack.Nanoseconds() {
		return ownerNewer
	}
	return ownerSame
}

// claimedReservation é uma reserva consumida por uma conexão só de eventos, guardada para o rollback do lote.
type claimedReservation struct {
	k flowKey
	r reservation
}

// dirtyConn é uma conexão gravada cujo registro precisa ser refeito no fim do lote.
type dirtyConn struct {
	end int64     // > 0 estende o fim (conexão só de eventos)
	app *appState // nil = recarregar de app_events
}

// openFor devolve a conexão aberta da 5-tupla que contém ts (com folga antes do início).
func (t *flowTable) openFor(k flowKey, ts int64, dcid string) (target, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.conns[k]
	if c == nil || ts < c.started-eventSlack.Nanoseconds() {
		return target{}, false
	}
	// Evento atrasado da conexão QUIC anterior na mesma 5-tupla (DCID diferente, anterior ao início desta):
	// pertence à conexão já gravada.
	if dcid != "" && c.quicDCID != "" && dcid != c.quicDCID && ts < c.started {
		return target{}, false
	}
	return target{id: c.id, open: true, degraded: c.degraded}, true
}

// addApp aplica um evento ao estado em memória de uma conexão aberta; devolve se o probe foi definido agora, o
// proto antes e depois do evento. ok=false se a conexão saiu da tabela.
func (t *flowTable) addApp(id string, ev appEvent) (probeSet bool, before, after string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byID[id]
	if c == nil {
		return false, "", "", false
	}
	l4 := l4Name(c.l4)
	before = c.app.proto(l4)
	probeSet = c.app.add(ev)
	if c.l4 == protoUDP && c.app.isQUIC() {
		t.establishQUIC(c, ev.ts) // evento h3: QUIC estabelecido (ADR 0069 item 1)
	}
	// Fim da conexão QUIC visto pelo web: fecha o fluxo depois da mesma folga do TCP (FS_TCP_CLOSE_GRACE, task
	// 090); datagramas que chegarem depois vão para o registro gravado (flowTable.closed).
	if c.l4 == protoUDP && c.closeAt == 0 && c.app.h3Close != nil {
		c.closeAt = c.app.h3CloseTs + t.grace.Nanoseconds()
	}
	t.refresh(c) // fechou: sai da conta de vivas do modo degradado
	return probeSet, before, c.app.proto(l4), true
}

// chargeAppBytes soma n aos bytes de app_events da conexão aberta id; false (sem somar) se passaria de max
// (ADR 0067). Sem estado em memória (lote desfeito, a recarregar) ou max <= 0, aceita.
func (t *flowTable) chargeAppBytes(id string, n, limit int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.byID[id]
	if c == nil || c.app == nil || limit <= 0 {
		return true
	}
	if c.app.eventBytes+n > limit {
		return false
	}
	c.app.eventBytes += n
	return true
}

// setApp troca o estado de aplicação de uma conexão aberta (reconstruído de app_events).
func (t *flowTable) setApp(c *conn, a *appState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c.app = a
}

// claimReserved consome a reserva de conn_id da 5-tupla para uma conexão só de eventos, se houver, ou gera um ID
// novo; devolve também o início estimado da conexão pela reserva (0 sem reserva). O ID guardado para os pacotes
// atrasados de outra conexão só de eventos (late) nunca serve: a linha dela já existe.
func (t *flowTable) claimReserved(k flowKey, ts int64) (id string, accept int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.reserved[k]; ok && ts <= r.expires {
		t.claimed = append(t.claimed, claimedReservation{k: k, r: r})
		delete(t.reserved, k)
		return r.id, r.accept()
	}
	return t.takeReserved(k, ts), 0
}

// accept é o início estimado da conexão dona da reserva: a reserva vale reservationTTL desde a chegada do pedido
// de conn_id (ou desde o início da conexão desfeita pelo rollback), menos acceptSlack.
func (r reservation) accept() int64 {
	return r.expires - reservationTTL.Nanoseconds() - acceptSlack.Nanoseconds()
}

// acceptAfter informa se a 5-tupla tem reserva de conn_id de uma conexão que começou até ts (accept de uma conexão
// nova ainda sem registro, task 424).
func (t *flowTable) acceptAfter(k flowKey, ts int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.reserved[k]
	return ok && ts <= r.expires && ts >= r.accept()
}

// takeFor dá o conn_id de uma conexão criada pelos pacotes: a reserva do pedido de conn_id (a conexão nova da
// 5-tupla) ou, para os pacotes de antes dela, o ID guardado de uma conexão só de eventos (adotada); senão um ID
// novo. Chamado com a trava.
func (t *flowTable) takeFor(k flowKey, ts int64) string {
	l, late := t.late[k]
	if r, ok := t.reserved[k]; ok && (!late || ts >= r.accept()) {
		return t.takeReserved(k, ts)
	}
	if late {
		delete(t.late, k)
		if ts <= l.expires {
			return l.id
		}
	}
	return t.takeReserved(k, ts)
}

// reserveFor guarda o ID já usado (conexão só de eventos) para os pacotes que chegarem atrasados.
func (t *flowTable) reserveFor(k flowKey, id string, now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.late[k] = reservation{id: id, expires: now + eventOnlyIdle.Nanoseconds()}
}

// dropReservation apaga o ID guardado (ou a reserva) da 5-tupla se ainda for do conn_id.
func (t *flowTable) dropReservation(k flowKey, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r, ok := t.late[k]; ok && r.id == id {
		delete(t.late, k)
	}
	if r, ok := t.reserved[k]; ok && r.id == id {
		delete(t.reserved, k)
	}
}

// resetClaimed esquece as reservas consumidas pelo lote (gravado); com restore, as devolve (lote desfeito: a
// reentrega recria a conexão só de eventos com o mesmo ID), sem passar por cima de uma reserva mais nova.
func (t *flowTable) resetClaimed(restore bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.claimed) - 1; restore && i >= 0; i-- {
		c := t.claimed[i]
		if _, ok := t.reserved[c.k]; !ok {
			t.reserved[c.k] = c.r
		}
		if l, ok := t.late[c.k]; ok && l.id == c.r.id {
			delete(t.late, c.k)
		}
	}
	t.claimed = t.claimed[:0]
}

// locate acha a conexão de um evento: aberta na tabela, criada só por eventos, ou já gravada (até a retenção).
func (in *Ingestor) locate(ctx context.Context, tx *sql.Tx, ev appEvent) (target, bool, error) {
	k := ev.key()
	if tg, ok := in.flows.openFor(k, ev.ts, ev.quicDCID()); ok {
		return tg, true, nil
	}
	// Sem conexão aberta, a reserva de conn_id de um accept até o ts do evento é de uma conexão nova na 5-tupla,
	// ainda sem registro: o evento é dela (espera os pacotes ou cria a só de eventos com o ID reservado), nunca de
	// uma anterior gravada ou só de eventos (task 424).
	if in.flows.acceptAfter(k, ev.ts) {
		return target{}, false, nil
	}
	exclude := "" // conexão só de eventos da 5-tupla que não é a do evento (ownerOlder)
	if eo := in.eventOnly[k]; eo != nil && ev.ts >= eo.started-eventSlack.Nanoseconds() && ev.ts <= eo.last+eventOnlyIdle.Nanoseconds() {
		switch eo.owner(ev) {
		case ownerNewer:
			// Conexão nova sem registro: o evento espera e cria a dela (createEventOnly tira esta do conjunto).
			return target{}, false, nil
		case ownerOlder:
			exclude = eo.id
		}
	}
	if eo := in.eventOnly[k]; eo != nil && exclude == "" && ev.ts >= eo.started-eventSlack.Nanoseconds() && ev.ts <= eo.last+eventOnlyIdle.Nanoseconds() {
		// Mesma conexão (ownerSame).
		ok, err := in.eventOnlyStored(ctx, tx, eo.id)
		if err != nil {
			return target{}, false, err
		}
		if ok {
			return target{id: eo.id, degraded: eo.degraded, eventOnly: true}, true, nil
		}
		// A linha saiu do banco (DELETE do probe, teto de tamanho): sem ela o INSERT do evento falharia na FK e o
		// lote voltaria por Nak em laço (ADR 0034 item 7). A entrada é esquecida (com o closed, ADR 0076) e o
		// evento segue a regra do evento sem conexão, com um conn_id novo (a reserva para pacotes atrasados também
		// é esquecida).
		if err := in.closeEventOnly(ctx, tx, k, eo); err != nil {
			return target{}, false, err
		}
		in.flows.dropReservation(k, eo.id)
	}
	var tg target
	var degraded int
	err := tx.QueryRowContext(ctx, `SELECT conn_id, degraded FROM connections
		WHERE l4 = ? AND src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ? AND started_ns <= ? AND ended_ns IS NOT NULL
		AND ended_ns >= ? AND conn_id <> ? ORDER BY started_ns DESC LIMIT 1`,
		l4Name(ev.l4), ev.client.Addr().String(), int(ev.client.Port()), ev.server.Addr().String(), int(ev.server.Port()),
		ev.ts+eventSlack.Nanoseconds(), ev.ts-lateSlack.Nanoseconds(), exclude).Scan(&tg.id, &degraded)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, false, nil
	}
	if err != nil {
		return target{}, false, err
	}
	tg.degraded = degraded == 1
	return tg, true, nil
}

// eventOnlyStored confere se a linha da conexão só de eventos ainda existe; a confirmação vale até o fim do lote
// (só a API e a retenção apagam linhas, e elas não entram no meio da transação do lote).
func (in *Ingestor) eventOnlyStored(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	if _, ok := in.eoChecked[id]; ok {
		return true, nil
	}
	var one int
	switch err := tx.QueryRowContext(ctx, "SELECT 1 FROM connections WHERE conn_id = ?", id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	in.eoChecked[id] = struct{}{}
	return true, nil
}

// appMessage trata uma mensagem de aplicação dentro da transação do lote.
// published é o instante de publicação no stream (ver appEvent.published).
func (in *Ingestor) appMessage(ctx context.Context, tx *sql.Tx, subject string, data []byte, published int64) error {
	ev, err := parseAppEvent(subject, data)
	if err != nil {
		in.log.Warn("bad app event", "subject", subject, "err", err)
		in.metrics.Add("store_bad_events_total", 1)
		return nil
	}
	ev.published = published
	in.clock.observe(ev.ts, in.batchWall)
	in.appTs = append(in.appTs, ev.ts)
	in.metrics.Add("store_app_events_total", 1)
	// DNS por UDP (ou sem 5-tupla) não tem conexão: vai direto para dns_queries.
	if subject == event.SubjectDNSQuery && (!ev.hasFlow() || ev.l4 != protoTCP) {
		return in.insertDNS(ctx, tx, ev, nil)
	}
	if !ev.hasFlow() {
		in.metrics.Add("store_bad_events_total", 1)
		return nil
	}
	// Mantém a ordem: se a 5-tupla já tem evento pendente, este espera junto.
	if in.hasPending(ev.key()) {
		in.addPending(ev)
		return nil
	}
	tg, ok, err := in.locate(ctx, tx, ev)
	if err != nil {
		return err
	}
	if !ok {
		in.addPending(ev)
		in.metrics.Add("store_pending_events_total", 1)
		return nil
	}
	return in.applyEvent(ctx, tx, ev, tg)
}

// hasPending é O(1): pendingKeys conta os pendentes por 5-tupla.
func (in *Ingestor) hasPending(k flowKey) bool { return in.pendingKeys[k] > 0 }

func (in *Ingestor) addPending(ev appEvent) {
	in.pending = append(in.pending, pendingEvent{ev: ev, arrived: in.now().UnixNano()})
	in.pendingKeys[ev.key()]++
}

// flushPending tenta de novo os eventos pendentes; os que passaram de pendingWait (ou todos, com force, no
// desligamento) criam a conexão só com os eventos. Também expira as conexões só de eventos ociosas.
func (in *Ingestor) flushPending(ctx context.Context, tx *sql.Tx, force bool) error {
	// A espera na fila conta desde a chegada (parede); a ociosidade das conexões só de eventos compara com o ts
	// dos eventos (relógio de captura, ADR 0041 item 2).
	now := in.now().UnixNano()
	capNow := in.clock.at(now)
	for k, eo := range in.eventOnly {
		if capNow-eo.last > eventOnlyIdle.Nanoseconds() {
			// Sai do conjunto sem ter sido adotada por pacotes: o closed nos dois canais (ADR 0076 item 2).
			if err := in.closeEventOnly(ctx, tx, k, eo); err != nil {
				return err
			}
		}
	}
	if len(in.pending) == 0 {
		return nil
	}
	list := in.pending
	in.pending = nil
	clear(in.pendingKeys)
	blocked := map[flowKey]bool{} // 5-tuplas que continuam esperando (preserva a ordem)
	for _, p := range list {
		k := p.ev.key()
		if blocked[k] {
			in.pending = append(in.pending, p)
			in.pendingKeys[k]++
			continue
		}
		tg, ok, err := in.locate(ctx, tx, p.ev)
		if err != nil {
			return err
		}
		if !ok {
			if !force && now-p.arrived < pendingWait.Nanoseconds() {
				blocked[k] = true
				in.pending = append(in.pending, p)
				in.pendingKeys[k]++
				continue
			}
			// Evento mais antigo que a retenção: a conexão dele já foi expurgada (ou seria no próximo ciclo);
			// não cria um registro só de eventos falso (task 080). Parede, como a própria retenção.
			if in.cfg.Retention > 0 && p.ev.ts < now-in.cfg.Retention.Nanoseconds() {
				in.log.Debug("app event older than retention dropped", "subject", p.ev.subject, "client", p.ev.client.String(), "server", p.ev.server.String())
				continue
			}
			if tg, err = in.createEventOnly(ctx, tx, p.ev); err != nil {
				return err
			}
		}
		if err := in.applyEvent(ctx, tx, p.ev, tg); err != nil {
			return err
		}
	}
	return nil
}

// createEventOnly grava uma conexão sem pacotes a partir do evento (capture fora do ar ou atrasado).
func (in *Ingestor) createEventOnly(ctx context.Context, tx *sql.Tx, ev appEvent) (target, error) {
	k := ev.key()
	// updated_ns é o relógio do store (settle do long-poll, ADR 0029), não o ts do evento.
	now := in.now().UnixNano()
	// Conexão só de eventos anterior na mesma 5-tupla (o evento é de outra, eventOnlyConn.owner): sai do conjunto
	// com o closed antes de a nova tomar o lugar (ADR 0076 item 2); eventos atrasados dela vão ao registro gravado.
	var prev []string
	if old := in.eventOnly[k]; old != nil {
		prev = slices.Clone(old.prev)
		if old.dcid != "" && old.dcid != ev.quicDCID() && !slices.Contains(prev, old.dcid) {
			prev = append(prev, old.dcid)
		}
		if len(prev) > maxPrevDCIDs {
			prev = prev[len(prev)-maxPrevDCIDs:]
		}
		if err := in.closeEventOnly(ctx, tx, k, old); err != nil {
			return target{}, err
		}
		in.flows.dropReservation(k, old.id)
	}
	id, accept := in.flows.claimReserved(k, ev.ts)
	eo := eventOnlyRecord(id, ev, ev.ts)
	rec, _ := json.Marshal(eo)
	if _, err := tx.ExecContext(ctx, `INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port,
		proto, started_ns, ended_ns, degraded, record_json, updated_ns, requests) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		id, l4Name(ev.l4), familyOf(ev), ev.client.Addr().String(), int(ev.client.Port()), ev.server.Addr().String(),
		int(ev.server.Port()), l4Name(ev.l4), ev.ts, ev.ts, string(rec), max(ev.ts, now), eo.Requests); err != nil {
		return target{}, fmt.Errorf("insert event-only connection: %w", err)
	}
	in.setEventOnly(k, &eventOnlyConn{id: id, started: ev.ts, last: ev.ts, app: newAppState(), rec: eo, accept: accept, dcid: ev.quicDCID(), prev: prev})
	in.liveConn(LiveConnOpened, summaryFrom(eo), ev.ts)
	in.pubConn(event.StageOpened, ev.ts, rec, &eo)
	in.prom.connection(l4Name(ev.l4), l4Name(ev.l4))
	// Pacotes que chegarem atrasados com a mesma 5-tupla ficam com o mesmo ID; a validade é comparada ao ts dos
	// pacotes, por isso conta no relógio de captura.
	in.flows.reserveFor(k, id, in.clock.at(now))
	in.metrics.Add("store_event_only_connections_total", 1)
	return target{id: id, eventOnly: true}, nil
}

func familyOf(ev appEvent) int {
	if ev.client.Addr().Is6() {
		return 6
	}
	return 4
}

// applyEvent associa o evento à conexão: app_events, raw_streams, dns_queries, probe e registro.
func (in *Ingestor) applyEvent(ctx context.Context, tx *sql.Tx, ev appEvent, tg target) error {
	if tg.open && in.flows.isHidden(tg.id) {
		return nil // conexão de um probe apagado: o evento é descartado (ADR 0034 item 8)
	}
	ev, keep, err := in.storeStream(ctx, tx, ev, tg)
	if err != nil {
		return err
	}
	if !keep {
		return nil
	}
	if tg.open && !in.flows.chargeAppBytes(tg.id, int64(len(ev.data)), in.cfg.PcapMax) {
		// Acima do teto de bytes de app_events da conexão aberta (ADR 0067): o evento não é gravado, mas a
		// análise (listas com teto) ainda entra no estado em memória.
		in.metrics.Add("store_app_events_dropped_total", 1)
	} else if _, err := tx.ExecContext(ctx, "INSERT INTO app_events (conn_id, ts_ns, subject, payload_json) VALUES (?, ?, ?, ?)",
		tg.id, ev.ts, ev.subject, string(ev.data)); err != nil {
		return fmt.Errorf("insert app event: %w", err)
	}
	if ev.subject == event.SubjectDNSQuery {
		id := tg.id
		if err := in.insertDNS(ctx, tx, ev, &id); err != nil {
			return err
		}
	}
	if tg.open {
		probeSet, before, after, ok := in.flows.addApp(tg.id, ev)
		if ok {
			in.batchApp[tg.id] = struct{}{}
		}
		if ok {
			var s summaryJSON
			if in.live != nil || in.conns != nil {
				s, _ = in.flows.openSummary(tg.id)
			}
			if in.live != nil {
				in.liveApp(ev, tg.id, strOrEmpty(s.ProbeID))
				in.liveConn(LiveConnUpdated, s, ev.liveTs())
			}
			// Evento antes do opened do bot (ACK ainda não processado): sai o opened com o estado fundido, não
			// um updated (ADR 0076 item 1).
			if c := in.flows.connByID(tg.id); c != nil && !c.botOpened {
				if err := in.openBot(ctx, tx, c, ev.liveTs()); err != nil {
					return err
				}
			} else {
				in.pubConnOpen(tg.id, ev.liveTs(), s.Degraded)
			}
		}
		if ok {
			// As colunas usadas por /connections e /probes acompanham o estado em memória.
			if probeSet || before != after {
				_, err := tx.ExecContext(ctx, "UPDATE connections SET probe_id = coalesce(probe_id, ?), proto = ? WHERE conn_id = ?", ev.env.ProbeID, after, tg.id)
				return err
			}
			return nil
		}
	}
	// Conexão gravada: o registro é refeito uma vez no fim do lote (flushDirty), não a cada evento.
	in.liveApp(ev, tg.id, "")
	d := in.dirty[tg.id]
	if tg.eventOnly {
		if ev.ts > d.end {
			d.end = ev.ts
		}
		if eo := in.eventOnly[ev.key()]; eo != nil && eo.id == tg.id {
			if ev.ts > eo.last {
				eo.last = ev.ts
			}
			if eo.dcid == "" {
				eo.dcid = ev.quicDCID()
			}
			if eo.app != nil {
				eo.app.add(ev)
			}
			d.app = eo.app
		}
	}
	in.dirty[tg.id] = d
	return nil
}

// flushDirty refaz o registro das conexões gravadas que receberam eventos neste lote. Conexão só de eventos usa
// o estado em memória; as demais (evento tardio, raro) relêem app_events uma vez por lote.
func (in *Ingestor) flushDirty(ctx context.Context, tx *sql.Tx) error {
	for id, d := range in.dirty {
		a := d.app
		if a == nil {
			var err error
			in.appReloads++
			if a, err = loadAppState(ctx, tx, id); err != nil {
				return err
			}
			// Repõe o estado em memória da conexão só de eventos que o tinha perdido.
			for _, eo := range in.eventOnly {
				if eo.id == id && eo.app == nil {
					eo.app = a
				}
			}
		}
		if err := in.writeStored(ctx, tx, id, a, d.end); err != nil {
			return err
		}
	}
	clear(in.dirty)
	return nil
}

// eventOnlyUndo é o valor anterior de uma entrada de in.eventOnly mudada pelo lote em curso (nil = não havia).
type eventOnlyUndo struct {
	k    flowKey
	prev *eventOnlyConn
}

// setEventOnly troca (ou, com nil, apaga) a conexão só de eventos da 5-tupla, guardando o valor anterior para o
// rollback do lote.
func (in *Ingestor) setEventOnly(k flowKey, eo *eventOnlyConn) {
	in.eoUndo = append(in.eoUndo, eventOnlyUndo{k: k, prev: in.eventOnly[k]})
	if eo == nil {
		delete(in.eventOnly, k)
		return
	}
	in.eventOnly[k] = eo
}

// beginBatch guarda o que o rollback do lote precisa repor (ADR 0034): a fila de eventos pendentes.
func (in *Ingestor) beginBatch() {
	in.pktSerial++
	in.pendSnap = slices.Clip(in.pending)
	in.pendKeysSnap = maps.Clone(in.pendingKeys)
	in.batchCreated = in.batchCreated[:0]
	in.eoUndo = in.eoUndo[:0]
	in.botOpenUndo = in.botOpenUndo[:0]
	in.batchEvicted = in.batchEvicted[:0]
	clear(in.batchApp)
	clear(in.eoChecked)
	in.flows.resetClaimed(false)
}

// commitBatch esquece o que só servia ao rollback: o lote está gravado.
func (in *Ingestor) commitBatch() {
	in.pendSnap, in.pendKeysSnap = nil, nil
	for _, c := range in.batchCreated {
		in.metrics.Add("store_connections_total", 1)
		if c.degraded {
			in.metrics.Add("store_degraded_connections_total", 1)
			in.prom.degradedConn()
		}
	}
	in.batchCreated = in.batchCreated[:0]
	in.eoUndo = in.eoUndo[:0]
	in.botOpenUndo = in.botOpenUndo[:0]
	in.batchEvicted = in.batchEvicted[:0]
	clear(in.batchApp)
	in.flows.resetClaimed(false)
	in.commitPkts()
}

// discardBatchState desfaz o estado em memória que dependia do lote cuja transação foi desfeita; as mensagens
// voltam por Nak (ADR 0034: só erro antes do commit chega aqui, nunca um erro da finalização depois dele).
//   - o registro sujo e os tardios são descartados e o estado das conexões só de eventos é relido depois;
//   - as conexões criadas pelo lote saem da tabela de fluxos, com a ficha das novas/s devolvida e o conn_id
//     reservado para a 5-tupla: a reentrega as recria (e reinsere a linha) com o mesmo ID. Ficar na tabela faria
//     o SYN reentregue de uma conexão já estabelecida abrir outra (reuso da 5-tupla);
//   - as conexões só de eventos criadas ou adotadas pelo lote voltam ao que eram, e a fila de pendentes também;
//   - o estado de aplicação das conexões abertas que receberam eventos no lote é relido de app_events no
//     próximo lote, para a reentrega não aplicar os eventos duas vezes.
//
// Limitação aceita: a análise IP/TCP e os contadores das conexões que já existiam contam de novo os pacotes
// reentregues.
func (in *Ingestor) discardBatchState() {
	in.discardPkts()
	clear(in.dirty)
	clear(in.late)
	in.liveBatch = nil
	in.discardConns()
	for id := range in.batchApp {
		if c := in.flows.connByID(id); c != nil {
			in.appStale = append(in.appStale, c)
		}
	}
	clear(in.batchApp)
	for _, c := range in.botOpenUndo {
		c.botOpened = false // o opened do bot saiu com o lote desfeito: a reentrega o refaz
	}
	in.botOpenUndo = in.botOpenUndo[:0]
	in.flows.undoCreated(in.batchCreated)
	in.batchCreated = in.batchCreated[:0]
	// Despejadas pelo lote desfeito: já saíram da tabela, mas a linha voltou com o rollback e o closed se perdeu;
	// o próximo lote refaz os dois (redoEvicted). A criada pelo próprio lote não tem linha nem opened.
	for _, c := range in.batchEvicted {
		if !c.unstored {
			in.evictCarry = append(in.evictCarry, c)
		}
	}
	in.batchEvicted = in.batchEvicted[:0]
	for i := len(in.eoUndo) - 1; i >= 0; i-- {
		u := in.eoUndo[i]
		if u.prev == nil {
			delete(in.eventOnly, u.k)
		} else {
			in.eventOnly[u.k] = u.prev
		}
	}
	in.eoUndo = in.eoUndo[:0]
	in.flows.resetClaimed(true)
	for _, eo := range in.eventOnly {
		eo.app = nil
	}
	if in.pendKeysSnap != nil {
		in.pending, in.pendingKeys = in.pendSnap, in.pendKeysSnap
		in.pendSnap, in.pendKeysSnap = nil, nil
	}
}

// reloadStaleApp relê de app_events o estado de aplicação das conexões abertas marcadas por discardBatchState.
func (in *Ingestor) reloadStaleApp(ctx context.Context, tx *sql.Tx) error {
	for _, c := range in.appStale {
		in.appReloads++
		a, err := loadAppState(ctx, tx, c.id)
		if err != nil {
			return err
		}
		in.flows.setApp(c, a)
	}
	in.appStale = in.appStale[:0]
	return nil
}

// loadAppState reconstrói o estado de aplicação de uma conexão a partir de app_events.
func loadAppState(ctx context.Context, tx *sql.Tx, id string) (*appState, error) {
	rows, err := tx.QueryContext(ctx, "SELECT subject, payload_json FROM app_events WHERE conn_id = ? ORDER BY id", id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	a := newAppState()
	for rows.Next() {
		var subject, data string
		if err := rows.Scan(&subject, &data); err != nil {
			return nil, err
		}
		a.eventBytes += int64(len(data))
		if ev, err := parseAppEvent(subject, []byte(data)); err == nil {
			a.add(ev)
		}
	}
	return a, rows.Err()
}

// writeStored aplica o estado de aplicação ao registro gravado; end > 0 estende o fim.
func (in *Ingestor) writeStored(ctx context.Context, tx *sql.Tx, id string, a *appState, end int64) error {
	var raw string
	var ended sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT record_json, ended_ns FROM connections WHERE conn_id = ?", id).Scan(&raw, &ended); err != nil {
		return err
	}
	var r connectionJSON
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return err
	}
	a.apply(&r)
	endNs := ended.Int64
	if end > endNs {
		endNs = end
		r.Ended = tsPtr(end)
		if r.Times != nil {
			r.Times.End = tsPtr(end)
		}
	}
	rec, _ := json.Marshal(r)
	now := in.now().UnixNano()
	if _, err := tx.ExecContext(ctx, "UPDATE connections SET record_json = ?, probe_id = coalesce(probe_id, ?), proto = ?, ended_ns = ?, updated_ns = ?, requests = ? WHERE conn_id = ?",
		string(rec), r.ProbeID, r.Proto, nullIfZero(endNs), now, r.Requests, id); err != nil {
		return err
	}
	in.liveConn(LiveConnUpdated, summaryFrom(r), now)
	in.pubConn(event.StageUpdated, now, rec, &r)
	return nil
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// adoptEventOnly é chamado quando os pacotes criam uma conexão com o ID de uma conexão só de eventos: a linha já
// existe, e o estado de aplicação vem de app_events.
func (in *Ingestor) adoptEventOnly(ctx context.Context, tx *sql.Tx, c *conn, k flowKey) (bool, error) {
	eo := in.eventOnly[k]
	if eo == nil || eo.id != c.id {
		return false, nil
	}
	in.setEventOnly(k, nil)
	// O registro passa a ser o dos pacotes (a linha foi substituída): o que estava sujo não vale mais.
	delete(in.dirty, c.id)
	a := eo.app
	if a == nil {
		var err error
		in.appReloads++
		if a, err = loadAppState(ctx, tx, c.id); err != nil {
			return false, err
		}
	}
	in.flows.setApp(c, a)
	return true, nil
}
