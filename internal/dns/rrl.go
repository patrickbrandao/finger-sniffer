package dns

import (
	"net/netip"
	"sync"
	"time"
)

// Limites do RRL.
const (
	// rrlMaxEntries limita a memória do RRL (um balde por origem); o balde de transbordo é a única entrada além
	// desse teto.
	rrlMaxEntries = 65536
	// rrlV6Prefix é o prefixo que agrega as origens IPv6 num balde (um cliente controla o /64 inteiro).
	rrlV6Prefix = 64
	// rrlIdle é quanto tempo um balde parado fica antes de ser descartado.
	rrlIdle = 10 * time.Second
)

// RRL limita as respostas UDP por origem com um balde de fichas (spec 007 RF-04, ADR 0035): taxa de perSec
// respostas por segundo e rajada do mesmo tamanho. A origem é o IP em IPv4 e o /64 em IPv6; com a tabela cheia, as
// origens sem balde próprio dividem o balde de transbordo. perSec <= 0 desliga o limite.
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

// overflowKey é a chave do balde de transbordo; nenhuma origem real vira o endereço zero.
var overflowKey netip.Addr

// rrlKey devolve a chave do balde da origem: o IPv4 inteiro (também quando vem mapeado em IPv6) ou o prefixo
// /64 do IPv6, sem zona.
func rrlKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		if p, err := ip.Prefix(rrlV6Prefix); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// Allow informa se a origem ainda pode receber uma resposta completa agora e consome uma ficha.
func (r *RRL) Allow(ip netip.Addr) bool {
	if r == nil || r.perSec <= 0 {
		return true
	}
	key := rrlKey(ip)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	b := r.buckets[key]
	if b == nil {
		if len(r.buckets) >= rrlMaxEntries {
			// Tabela cheia (ataque com muitas origens): as origens sem balde próprio dividem o balde de
			// transbordo, em vez de passar sem limite ou de a tabela crescer sem fim.
			key = overflowKey
			b = r.buckets[key]
		}
		if b == nil {
			b = &bucket{tokens: r.perSec, last: now}
			r.buckets[key] = b
		}
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
