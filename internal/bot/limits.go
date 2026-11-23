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
	// records e recordsLast são o balde de registros do ingest da 9002 (ADR 0073 item 3.1); recordsInit marca que
	// o balde já foi enchido na primeira vez.
	records     float64
	recordsLast time.Time
	recordsInit bool
}

type usageKey struct {
	keyID string
	day   int64
}

type usage struct{ requests, limited, records int64 }

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

// AllowRecords tira n fichas do balde de registros da chave de uma vez (ingest da 9002, ADR 0073 item 3.1). Sem
// fichas para o lote inteiro, nada é tirado, o 429 conta em limited e devolve os segundos até haver as n fichas.
func (l *Limiter) AllowRecords(k *Key, n int) (bool, int) {
	if n <= 0 {
		return true, 0
	}
	now := l.now()
	day := now.Unix() / 86400
	l.mu.Lock()
	defer l.mu.Unlock()
	kl := l.keys[k.ID]
	if kl == nil {
		kl = &keyLimit{tokens: float64(k.BurstSize()), last: now, day: -1}
		l.keys[k.ID] = kl
	}
	rate, burst := float64(k.IngestRateOrDefault()), float64(k.IngestBurstOrDefault())
	if !kl.recordsInit {
		kl.records, kl.recordsLast, kl.recordsInit = burst, now, true
	}
	if el := now.Sub(kl.recordsLast).Seconds(); el > 0 {
		kl.records = math.Min(burst, kl.records+el*rate)
	}
	kl.recordsLast = now
	if kl.records < float64(n) {
		uk := usageKey{k.ID, day}
		u := l.pending[uk]
		u.limited++
		l.pending[uk] = u
		return false, max(1, int(math.Ceil((float64(n)-kl.records)/rate)))
	}
	kl.records -= float64(n)
	return true, 0
}

// AddRecords soma registros aceitos do ingest ao uso do dia da chave (key_usage_daily.records), nas duas portas.
func (l *Limiter) AddRecords(k *Key, n int) {
	if n <= 0 {
		return
	}
	day := l.now().Unix() / 86400
	l.mu.Lock()
	defer l.mu.Unlock()
	uk := usageKey{k.ID, day}
	u := l.pending[uk]
	u.records += int64(n)
	l.pending[uk] = u
}

// Count grava uma requisição da chave no uso do dia sem aplicar balde nem cota (9003, ADR 0073 item 4).
func (l *Limiter) Count(k *Key) {
	day := l.now().Unix() / 86400
	l.mu.Lock()
	defer l.mu.Unlock()
	uk := usageKey{k.ID, day}
	u := l.pending[uk]
	u.requests++
	l.pending[uk] = u
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
			p.records += u.records
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_usage_daily (key_id, day, requests, limited, records)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT (key_id, day) DO UPDATE SET requests = requests + excluded.requests,
			limited = limited + excluded.limited, records = records + excluded.records`,
			k.keyID, k.day, u.requests, u.limited, u.records); err != nil {
			return fmt.Errorf("bot: usage flush: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bot: usage flush: %w", err)
	}
	return nil
}
