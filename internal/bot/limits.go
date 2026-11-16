package bot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// Limiter aplica o balde de fichas e a cota diária de cada chave (ADR 0051 item 4). O uso do dia fica em memória
// e vai ao banco (key_usage_daily) no Flush; ao ver a chave pela primeira vez no dia, lê o que já foi gravado,
// para a cota sobreviver ao reinício.
type Limiter struct {
	db  *sql.DB
	now func() time.Time

	mu      sync.Mutex
	keys    map[string]*keyLimit
	pending map[usageKey]usage
}

type keyLimit struct {
	tokens   float64
	last     time.Time
	day      int64
	requests int64 // atendidas no dia (gravadas + pendentes)
}

type usageKey struct {
	keyID string
	day   int64
}

type usage struct{ requests, limited int64 }

// NewLimiter cria o limitador; db pode ser nil nos testes (sem persistência).
func NewLimiter(db *sql.DB, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{db: db, now: now, keys: map[string]*keyLimit{}, pending: map[usageKey]usage{}}
}

// Allow conta uma requisição da chave. Se passou do limite, devolve false e os segundos do Retry-After.
func (l *Limiter) Allow(ctx context.Context, k *Key) (bool, int) {
	now := l.now()
	day := now.Unix() / 86400
	l.mu.Lock()
	defer l.mu.Unlock()
	kl := l.keys[k.ID]
	if kl == nil {
		kl = &keyLimit{tokens: float64(k.BurstSize()), last: now, day: -1}
		l.keys[k.ID] = kl
	}
	if kl.day != day {
		kl.day, kl.requests = day, l.storedRequests(ctx, k.ID, day)+l.pending[usageKey{k.ID, day}].requests
	}
	rate, burst := float64(k.Rate()), float64(k.BurstSize())
	if el := now.Sub(kl.last).Seconds(); el > 0 {
		kl.tokens = math.Min(burst, kl.tokens+el*rate)
	}
	kl.last = now
	uk := usageKey{k.ID, day}
	u := l.pending[uk]
	if kl.requests >= int64(k.Quota()) {
		u.limited++
		l.pending[uk] = u
		next := time.Unix((day+1)*86400, 0)
		return false, max(1, int(math.Ceil(next.Sub(now).Seconds())))
	}
	if kl.tokens < 1 {
		u.limited++
		l.pending[uk] = u
		return false, max(1, int(math.Ceil((1-kl.tokens)/rate)))
	}
	kl.tokens--
	kl.requests++
	u.requests++
	l.pending[uk] = u
	return true, 0
}

// storedRequests lê o uso já gravado da chave no dia (0 sem banco ou em erro).
func (l *Limiter) storedRequests(ctx context.Context, keyID string, day int64) int64 {
	if l.db == nil {
		return 0
	}
	var n int64
	err := l.db.QueryRowContext(ctx, "SELECT requests FROM key_usage_daily WHERE key_id = ? AND day = ?", keyID, day).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0
	}
	return n
}

// Flush grava o uso pendente numa transação; em erro, devolve o pendente para a próxima vez.
func (l *Limiter) Flush(ctx context.Context) error {
	l.mu.Lock()
	batch := l.pending
	l.pending = map[usageKey]usage{}
	l.mu.Unlock()
	if len(batch) == 0 || l.db == nil {
		return nil
	}
	err := l.write(ctx, batch)
	if err != nil {
		l.mu.Lock()
		for k, u := range batch {
			p := l.pending[k]
			p.requests += u.requests
			p.limited += u.limited
			l.pending[k] = p
		}
		l.mu.Unlock()
	}
	return err
}

func (l *Limiter) write(ctx context.Context, batch map[usageKey]usage) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("bot: usage flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for k, u := range batch {
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_usage_daily (key_id, day, requests, limited) VALUES (?, ?, ?, ?)
			ON CONFLICT (key_id, day) DO UPDATE SET requests = requests + excluded.requests, limited = limited + excluded.limited`,
			k.keyID, k.day, u.requests, u.limited); err != nil {
			return fmt.Errorf("bot: usage flush: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bot: usage flush: %w", err)
	}
	return nil
}
