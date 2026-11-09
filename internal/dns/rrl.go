package dns

import (
	"net/netip"
	"sync"
	"time"
)

// Limites do RRL.
const (
	// rrlMaxEntries limita a memória do RRL (um balde por IP de origem).
	rrlMaxEntries = 65536
	// rrlIdle é quanto tempo um balde parado fica antes de ser descartado.
	rrlIdle = 10 * time.Second
)

// RRL limita as respostas por IP de origem com um balde de fichas (spec 007 RF-04): taxa de perSec respostas
// por segundo e rajada do mesmo tamanho. perSec <= 0 desliga o limite.
type RRL struct {
	perSec float64
	now    func() time.Time

	mu        sync.Mutex
	buckets   map[netip.Addr]*bucket
	lastPrune time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRRL cria o limitador (now nil = time.Now).
func NewRRL(perSec int, now func() time.Time) *RRL {
	if now == nil {
		now = time.Now
	}
	return &RRL{perSec: float64(perSec), now: now, buckets: map[netip.Addr]*bucket{}}
}

// Allow informa se o IP ainda pode receber uma resposta completa agora e consome uma ficha.
func (r *RRL) Allow(ip netip.Addr) bool {
	if r == nil || r.perSec <= 0 {
		return true
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	b := r.buckets[ip]
	if b == nil {
		if len(r.buckets) >= rrlMaxEntries {
			// Tabela cheia (ataque com muitas origens): não limita em vez de crescer sem fim.
			return true
		}
		b = &bucket{tokens: r.perSec, last: now}
		r.buckets[ip] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(r.perSec, b.tokens+el*r.perSec)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// pruneLocked descarta, no máximo uma vez por segundo, os baldes parados há mais de rrlIdle (já cheios).
func (r *RRL) pruneLocked(now time.Time) {
	if now.Sub(r.lastPrune) < time.Second {
		return
	}
	r.lastPrune = now
	for ip, b := range r.buckets {
		if now.Sub(b.last) > rrlIdle {
			delete(r.buckets, ip)
		}
	}
}
