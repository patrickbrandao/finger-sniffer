package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
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
}

// openFor devolve a conexão aberta da 5-tupla que contém ts (com folga antes do início).
func (t *flowTable) openFor(k flowKey, ts int64) (target, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.conns[k]
	if c == nil || ts < c.started-eventSlack.Nanoseconds() {
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
	return probeSet, before, c.app.proto(l4), true
}

// setApp troca o estado de aplicação de uma conexão aberta (reconstruído de app_events).
func (t *flowTable) setApp(c *conn, a *appState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c.app = a
}

// claimReserved consome a reserva de conn_id da 5-tupla, se houver, ou gera um ID novo.
func (t *flowTable) claimReserved(k flowKey, ts int64) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.takeReserved(k, ts)
}

// reserveFor reserva um ID já usado (conexão só de eventos) para os pacotes que chegarem atrasados.
func (t *flowTable) reserveFor(k flowKey, id string, now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reserved[k] = reservation{id: id, expires: now + eventOnlyIdle.Nanoseconds()}
}

// locate acha a conexão de um evento: aberta na tabela, criada só por eventos, ou já gravada (até a retenção).
func (in *Ingestor) locate(ctx context.Context, tx *sql.Tx, ev appEvent) (target, bool, error) {
	k := ev.key()
	if tg, ok := in.flows.openFor(k, ev.ts); ok {
		return tg, true, nil
	}
	if eo := in.eventOnly[k]; eo != nil && ev.ts >= eo.started-eventSlack.Nanoseconds() && ev.ts <= eo.last+eventOnlyIdle.Nanoseconds() {
		return target{id: eo.id, degraded: eo.degraded, eventOnly: true}, true, nil
	}
	var tg target
	var degraded int
	err := tx.QueryRowContext(ctx, `SELECT conn_id, degraded FROM connections
		WHERE l4 = ? AND src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ? AND started_ns <= ? AND ended_ns IS NOT NULL
		AND ended_ns >= ? ORDER BY started_ns DESC LIMIT 1`,
		l4Name(ev.l4), ev.client.Addr().String(), int(ev.client.Port()), ev.server.Addr().String(), int(ev.server.Port()),
		ev.ts+eventSlack.Nanoseconds(), ev.ts-lateSlack.Nanoseconds()).Scan(&tg.id, &degraded)
	if errors.Is(err, sql.ErrNoRows) {
		return target{}, false, nil
	}
	if err != nil {
		return target{}, false, err
	}
	tg.degraded = degraded == 1
	return tg, true, nil
}

// appMessage trata uma mensagem de aplicação dentro da transação do lote.
func (in *Ingestor) appMessage(ctx context.Context, tx *sql.Tx, subject string, data []byte) error {
	ev, err := parseAppEvent(subject, data)
	if err != nil {
		in.log.Warn("bad app event", "subject", subject, "err", err)
		in.metrics.Add("store_bad_events_total", 1)
		return nil
	}
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
		in.pending = append(in.pending, pendingEvent{ev: ev, arrived: in.now().UnixNano()})
		return nil
	}
	tg, ok, err := in.locate(ctx, tx, ev)
	if err != nil {
		return err
	}
	if !ok {
		in.pending = append(in.pending, pendingEvent{ev: ev, arrived: in.now().UnixNano()})
		in.metrics.Add("store_pending_events_total", 1)
		return nil
	}
	return in.applyEvent(ctx, tx, ev, tg)
}

func (in *Ingestor) hasPending(k flowKey) bool {
	for _, p := range in.pending {
		if p.ev.key() == k {
			return true
		}
	}
	return false
}

// flushPending tenta de novo os eventos pendentes; os que passaram de pendingWait criam a conexão só com os
// eventos. Também expira as conexões só de eventos ociosas.
func (in *Ingestor) flushPending(ctx context.Context, tx *sql.Tx) error {
	now := in.now().UnixNano()
	for k, eo := range in.eventOnly {
		if now-eo.last > eventOnlyIdle.Nanoseconds() {
			delete(in.eventOnly, k)
		}
	}
	if len(in.pending) == 0 {
		return nil
	}
	list := in.pending
	in.pending = nil
	blocked := map[flowKey]bool{} // 5-tuplas que continuam esperando (preserva a ordem)
	for _, p := range list {
		k := p.ev.key()
		if blocked[k] {
			in.pending = append(in.pending, p)
			continue
		}
		tg, ok, err := in.locate(ctx, tx, p.ev)
		if err != nil {
			return err
		}
		if !ok {
			if now-p.arrived < pendingWait.Nanoseconds() {
				blocked[k] = true
				in.pending = append(in.pending, p)
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
	now := in.now().UnixNano()
	id := in.flows.claimReserved(k, ev.ts)
	rec, _ := json.Marshal(eventOnlyRecord(id, ev, ev.ts))
	if _, err := tx.ExecContext(ctx, `INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port,
		proto, started_ns, ended_ns, degraded, record_json, updated_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, l4Name(ev.l4), familyOf(ev), ev.client.Addr().String(), int(ev.client.Port()), ev.server.Addr().String(),
		int(ev.server.Port()), l4Name(ev.l4), ev.ts, ev.ts, string(rec), ev.ts); err != nil {
		return target{}, fmt.Errorf("insert event-only connection: %w", err)
	}
	in.eventOnly[k] = &eventOnlyConn{id: id, started: ev.ts, last: ev.ts}
	// Pacotes que chegarem atrasados com a mesma 5-tupla ficam com o mesmo ID.
	in.flows.reserveFor(k, id, now)
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
	ev, keep, err := in.storeStream(ctx, tx, ev, tg)
	if err != nil {
		return err
	}
	if !keep {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO app_events (conn_id, ts_ns, subject, payload_json) VALUES (?, ?, ?, ?)",
		tg.id, ev.ts, ev.subject, string(ev.data)); err != nil {
		return fmt.Errorf("insert app event: %w", err)
	}
	if ev.subject == event.SubjectDNSQuery {
		id := tg.id
		if err := in.insertDNS(ctx, tx, ev, &id); err != nil {
			return err
		}
	}
	if ev.env.ProbeID != nil && *ev.env.ProbeID != "" {
		if err := upsertProbe(ctx, tx, *ev.env.ProbeID, ev.ts); err != nil {
			return err
		}
	}
	if tg.open {
		probeSet, before, after, ok := in.flows.addApp(tg.id, ev)
		if ok {
			// As colunas usadas por /connections e /probes acompanham o estado em memória.
			if probeSet || before != after {
				_, err := tx.ExecContext(ctx, "UPDATE connections SET probe_id = coalesce(probe_id, ?), proto = ? WHERE conn_id = ?", ev.env.ProbeID, after, tg.id)
				return err
			}
			return nil
		}
	}
	end := int64(0)
	if tg.eventOnly {
		end = ev.ts
		if eo := in.eventOnly[ev.key()]; eo != nil && eo.id == tg.id && ev.ts > eo.last {
			eo.last = ev.ts
		}
	}
	return in.rebuildStored(ctx, tx, tg.id, end)
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
		if ev, err := parseAppEvent(subject, []byte(data)); err == nil {
			a.add(ev)
		}
	}
	return a, rows.Err()
}

// rebuildStored refaz as camadas de aplicação de uma conexão já gravada (evento tardio ou conexão só de eventos).
// end > 0 estende o fim da conexão só de eventos.
func (in *Ingestor) rebuildStored(ctx context.Context, tx *sql.Tx, id string, end int64) error {
	a, err := loadAppState(ctx, tx, id)
	if err != nil {
		return err
	}
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
	_, err = tx.ExecContext(ctx, "UPDATE connections SET record_json = ?, probe_id = coalesce(probe_id, ?), proto = ?, ended_ns = ?, updated_ns = ? WHERE conn_id = ?",
		string(rec), r.ProbeID, r.Proto, nullIfZero(endNs), in.now().UnixNano(), id)
	return err
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// adoptEventOnly é chamado quando os pacotes criam uma conexão com o ID de uma conexão só de eventos: a linha já
// existe, e o estado de aplicação vem de app_events.
func (in *Ingestor) adoptEventOnly(ctx context.Context, tx *sql.Tx, c *conn, k flowKey) error {
	eo := in.eventOnly[k]
	if eo == nil || eo.id != c.id {
		return nil
	}
	delete(in.eventOnly, k)
	a, err := loadAppState(ctx, tx, c.id)
	if err != nil {
		return err
	}
	in.flows.setApp(c, a)
	return nil
}
