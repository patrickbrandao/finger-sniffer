package agg

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ipRow é o delta de uma hora de ip_hourly a gravar.
type ipRow struct {
	h     *hourAcc
	ip    [16]byte
	site  string
	hour  int64
	total counters // total no instante do snapshot (vira flushed se a transação passar)
	delta counters
}

// fpRow é o delta de uma fingerprint do dia a gravar.
type fpRow struct {
	acc                  *fpAcc
	k                    fpKey
	requests, bot, human int64 // totais do snapshot
	ips                  int64 // estimativa do snapshot
	dIPs                 int64
}

// Flush grava o que mudou desde o último flush numa transação (upsert somando). Em erro, os acumuladores ficam como
// estão e o próximo flush grava o delta inteiro; o crescimento é limitado pelo teto de entradas. Depois do flush
// (com ou sem erro) fecha as horas passadas no cache de comportamento e expira o que passou da janela.
func (a *Aggregator) Flush(ctx context.Context, db *sql.DB, now time.Time) error {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()

	a.mu.Lock()
	var ips []ipRow
	for k, b := range a.sites {
		for hr, h := range b.open {
			if h.cur == h.flushed {
				continue
			}
			ips = append(ips, ipRow{h: h, ip: k.ip, site: k.site, hour: hr, total: h.cur, delta: h.cur.sub(h.flushed)})
		}
	}
	var fps []fpRow
	for k, f := range a.fps {
		est := f.ips.estimate()
		if f.requests == f.flushedRequests && f.bot == f.flushedBot && f.human == f.flushedHuman && est <= f.flushedIPs {
			continue
		}
		fps = append(fps, fpRow{
			acc: f, k: k, requests: f.requests, bot: f.bot, human: f.human, ips: max(est, f.flushedIPs),
			dIPs: max(0, est-f.flushedIPs),
		})
	}
	a.mu.Unlock()

	var err error
	if len(ips)+len(fps) > 0 {
		err = write(ctx, db, ips, fps)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		for _, r := range ips {
			r.h.flushed = r.total
		}
		for _, r := range fps {
			r.acc.flushedRequests, r.acc.flushedBot, r.acc.flushedHuman = r.requests, r.bot, r.human
			r.acc.flushedIPs = r.ips
		}
	}
	a.maintain(now)
	return err
}

func write(ctx context.Context, db *sql.DB, ips []ipRow, fps []fpRow) error {
	if db == nil {
		return fmt.Errorf("bot: agg flush: no database")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("bot: agg flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if len(ips) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO ip_hourly (ip, site, hour, requests, conns, reused, paths,
			statics, iv_n, iv_sum, iv_sq_sum, class_human, class_bot, class_suspect, class_good_bot, class_unknown)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (ip, site, hour) DO UPDATE SET requests = requests + excluded.requests,
			conns = conns + excluded.conns, reused = reused + excluded.reused, paths = paths + excluded.paths,
			statics = statics + excluded.statics, iv_n = iv_n + excluded.iv_n, iv_sum = iv_sum + excluded.iv_sum,
			iv_sq_sum = iv_sq_sum + excluded.iv_sq_sum, class_human = class_human + excluded.class_human,
			class_bot = class_bot + excluded.class_bot, class_suspect = class_suspect + excluded.class_suspect,
			class_good_bot = class_good_bot + excluded.class_good_bot,
			class_unknown = class_unknown + excluded.class_unknown`)
		if err != nil {
			return fmt.Errorf("bot: agg flush: %w", err)
		}
		defer func() { _ = st.Close() }()
		for _, r := range ips {
			d := r.delta
			if _, err := st.ExecContext(ctx, r.ip[:], r.site, r.hour, d.requests, d.conns, d.reused, d.paths,
				d.statics, d.iv.N, d.iv.Sum, d.iv.SqSum, d.class[0], d.class[1], d.class[2], d.class[3],
				d.class[4]); err != nil {
				return fmt.Errorf("bot: agg flush: %w", err)
			}
		}
	}
	if len(fps) > 0 {
		st, err := tx.PrepareContext(ctx, `INSERT INTO fp_daily (kind, value, day, ua_family, requests, ips,
			class_bot, class_human) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (kind, value, day, ua_family) DO UPDATE SET requests = requests + excluded.requests,
			ips = ips + excluded.ips, class_bot = class_bot + excluded.class_bot,
			class_human = class_human + excluded.class_human`)
		if err != nil {
			return fmt.Errorf("bot: agg flush: %w", err)
		}
		defer func() { _ = st.Close() }()
		for _, r := range fps {
			f := r.acc
			if _, err := st.ExecContext(ctx, r.k.kind, r.k.value, r.k.day, r.k.ua, r.requests-f.flushedRequests,
				r.dIPs, r.bot-f.flushedBot, r.human-f.flushedHuman); err != nil {
				return fmt.Errorf("bot: agg flush: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bot: agg flush: %w", err)
	}
	return nil
}

// Load preenche o cache de comportamento com as horas gravadas das últimas 24 h (início do serviço). Respeita o teto
// de entradas.
func (a *Aggregator) Load(ctx context.Context, db *sql.DB, now time.Time) error {
	first := floorDiv(now.Unix(), 3600) - BehaviorHours + 1
	rows, err := db.QueryContext(ctx, `SELECT ip, site, hour, requests, conns, reused, paths, statics, iv_n, iv_sum,
		iv_sq_sum, class_human, class_bot, class_suspect, class_good_bot, class_unknown FROM ip_hourly WHERE hour >= ?`,
		first)
	if err != nil {
		return fmt.Errorf("bot: agg load: %w", err)
	}
	defer func() { _ = rows.Close() }()
	a.mu.Lock()
	defer a.mu.Unlock()
	for rows.Next() {
		var (
			ip []byte
			k  siteKey
			s  hourStats
			c  = &s.c
		)
		if err := rows.Scan(&ip, &k.site, &s.hour, &c.requests, &c.conns, &c.reused, &c.paths, &c.statics, &c.iv.N,
			&c.iv.Sum, &c.iv.SqSum, &c.class[0], &c.class[1], &c.class[2], &c.class[3], &c.class[4]); err != nil {
			return fmt.Errorf("bot: agg load: %w", err)
		}
		if len(ip) != 16 {
			continue
		}
		copy(k.ip[:], ip)
		b := a.sites[k]
		if b == nil {
			if a.entries+1 > a.maxEntries {
				break
			}
			b = &behavior{open: map[int64]*hourAcc{}}
			a.sites[k] = b
			a.entries++
		}
		b.addPast(s)
	}
	return rows.Err()
}
