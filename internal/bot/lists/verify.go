package lists

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Resultado da verificação de robô (ADR 0050 item 4).
const (
	VerifyPassed  = "passed"
	VerifyFailed  = "failed"
	VerifyUnknown = "unknown"
)

// Parâmetros da verificação.
const (
	verifyTTL      = 24 * time.Hour
	verifyMaxCache = 50000
	verifyTimeout  = 3 * time.Second
)

// Resolver é o pedaço de net.Resolver usado na verificação (falso nos testes).
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type verifyKey struct {
	robot string
	ip    netip.Addr
}

type verifyEntry struct {
	result string
	host   string
	at     time.Time
}

// Verifier confirma por DNS reverso e direto que um IP é do robô que diz ser, com cache de 24 h.
type Verifier struct {
	resolver Resolver
	now      func() time.Time
	maxCache int

	mu    sync.Mutex
	cache map[verifyKey]verifyEntry
}

// NewVerifier cria o verificador (resolver nil = net.DefaultResolver; now nil = time.Now).
func NewVerifier(r Resolver, now func() time.Time) *Verifier {
	if r == nil {
		r = net.DefaultResolver
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{resolver: r, now: now, maxCache: verifyMaxCache, cache: map[verifyKey]verifyEntry{}}
}

// Verify devolve passed, failed ou unknown e o nome reverso aceito (vazio fora de passed). Robô sem sufixo
// publicado dá unknown sem consultar o DNS; erro temporário de DNS dá unknown e não entra no cache.
func (v *Verifier) Verify(ctx context.Context, robot string, ip netip.Addr) (string, string) {
	suffixes := robotSuffixes[robot]
	ip = ip.Unmap().WithZone("")
	if len(suffixes) == 0 || !ip.IsValid() {
		return VerifyUnknown, ""
	}
	key := verifyKey{robot, ip}
	now := v.now()
	v.mu.Lock()
	e, ok := v.cache[key]
	v.mu.Unlock()
	if ok && now.Sub(e.at) < verifyTTL {
		return e.result, e.host
	}
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	result, host := v.resolve(ctx, suffixes, ip)
	if result == VerifyUnknown {
		return result, ""
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= v.maxCache {
		v.evictLocked(now)
	}
	v.cache[key] = verifyEntry{result: result, host: host, at: now}
	return result, host
}

// Cached devolve o resultado em cache da verificação (sem DNS); ok=false quando não há resultado válido no cache
// ou o robô não tem sufixo publicado. É o caminho do forwardAuth: quem chama dispara Verify em segundo plano.
func (v *Verifier) Cached(robot string, ip netip.Addr) (result, host string, ok bool) {
	ip = ip.Unmap().WithZone("")
	if len(robotSuffixes[robot]) == 0 || !ip.IsValid() {
		return VerifyUnknown, "", false
	}
	now := v.now()
	v.mu.Lock()
	e, found := v.cache[verifyKey{robot, ip}]
	v.mu.Unlock()
	if !found || now.Sub(e.at) >= verifyTTL {
		return VerifyUnknown, "", false
	}
	return e.result, e.host, true
}

// HasDNS diz se o robô tem sufixo de DNS reverso publicado (verificável por DNS).
func HasDNS(robot string) bool { return len(robotSuffixes[robot]) > 0 }

func (v *Verifier) resolve(ctx context.Context, suffixes []string, ip netip.Addr) (string, string) {
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		if isNotFound(err) {
			return VerifyFailed, ""
		}
		return VerifyUnknown, ""
	}
	tempErr := false
	for _, n := range names {
		host := strings.ToLower(strings.TrimSuffix(n, "."))
		if !hasSuffix(host, suffixes) {
			continue
		}
		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			if !isNotFound(err) {
				tempErr = true
			}
			continue
		}
		for _, a := range addrs {
			if got, ok := netip.AddrFromSlice(a.IP); ok && got.Unmap() == ip {
				return VerifyPassed, host
			}
		}
	}
	if tempErr {
		return VerifyUnknown, ""
	}
	return VerifyFailed, ""
}

func hasSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// evictLocked tira as entradas vencidas e, se ainda estiver cheio, metade do cache (as mais antigas não são
// rastreadas: a ordem do mapa basta para um teto de memória).
func (v *Verifier) evictLocked(now time.Time) {
	for k, e := range v.cache {
		if now.Sub(e.at) >= verifyTTL {
			delete(v.cache, k)
		}
	}
	for k := range v.cache {
		if len(v.cache) < v.maxCache/2 {
			break
		}
		delete(v.cache, k)
	}
}

// Forget apaga do cache os IPs dentro do prefixo (forget da CLI, ADR 0056 item 2); devolve quantos.
func (v *Verifier) Forget(p netip.Prefix) int {
	p = normalizePrefix(p)
	if !p.IsValid() {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for k := range v.cache {
		if p.Contains(k.ip) {
			delete(v.cache, k)
			n++
		}
	}
	return n
}

// Len é o tamanho do cache.
func (v *Verifier) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.cache)
}
