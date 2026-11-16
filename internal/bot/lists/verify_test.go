package lists

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeResolver responde do mapa e conta as consultas.
type fakeResolver struct {
	mu      sync.Mutex
	ptr     map[string][]string
	ptrErr  map[string]error
	fwd     map[string][]string
	fwdErr  map[string]error
	lookups int
}

func (r *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if err := r.ptrErr[addr]; err != nil {
		return nil, err
	}
	names, ok := r.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.fwdErr[host]; err != nil {
		return nil, err
	}
	ips, ok := r.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, len(ips))
	for i, s := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(s)}
	}
	return out, nil
}

func (r *fakeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newResolver() *fakeResolver {
	return &fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1":   {"crawl-66-249-66-1.googlebot.com."},
			"192.0.2.10":    {"evil.googlebot.com.attacker.example."},
			"192.0.2.11":    {"crawl-fake.googlebot.com."},
			"2001:db8::bb":  {"msnbot-1.search.msn.com."},
			"192.0.2.12":    {"other.example.", "x.search.msn.com."},
			"17.58.1.1":     {"17-58-1-1.applebot.apple.com."},
			"203.0.113.250": {"crawl.googlebot.com."},
		},
		ptrErr: map[string]error{"192.0.2.99": &net.DNSError{Err: "timeout", IsTimeout: true}},
		fwd: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"crawl-fake.googlebot.com":        {"66.249.66.2"},
			"msnbot-1.search.msn.com":         {"2001:db8::bb"},
			"x.search.msn.com":                {"192.0.2.12"},
			"17-58-1-1.applebot.apple.com":    {"17.58.1.1"},
		},
		fwdErr: map[string]error{"crawl.googlebot.com": errors.New("servfail")},
	}
}

// Verificação por DNS reverso e direto: passou, falhou e desconhecido.
func TestVerify(t *testing.T) {
	r := newResolver()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	v := NewVerifier(r, c.Now)
	ctx := context.Background()
	cases := []struct {
		robot, ip, want, host string
	}{
		{"googlebot", "66.249.66.1", VerifyPassed, "crawl-66-249-66-1.googlebot.com"},
		{"googlebot", "::ffff:66.249.66.1", VerifyPassed, "crawl-66-249-66-1.googlebot.com"},
		{"googlebot", "192.0.2.10", VerifyFailed, ""}, // sufixo falso
		{"googlebot", "192.0.2.11", VerifyFailed, ""}, // direto não volta ao IP
		{"googlebot", "192.0.2.50", VerifyFailed, ""}, // sem PTR
		{"bingbot", "2001:db8::bb", VerifyPassed, "msnbot-1.search.msn.com"},
		{"bingbot", "66.249.66.1", VerifyFailed, ""}, // nome de outro robô
		{"bingbot", "192.0.2.12", VerifyPassed, "x.search.msn.com"},
		{"applebot", "17.58.1.1", VerifyPassed, "17-58-1-1.applebot.apple.com"},
		{"googlebot", "192.0.2.99", VerifyUnknown, ""},    // timeout no reverso
		{"googlebot", "203.0.113.250", VerifyUnknown, ""}, // erro no direto
		{"gptbot", "66.249.66.1", VerifyUnknown, ""},      // robô sem sufixo publicado
		{"nao-existe", "66.249.66.1", VerifyUnknown, ""},
	}
	for _, tc := range cases {
		got, host := v.Verify(ctx, tc.robot, netip.MustParseAddr(tc.ip))
		if got != tc.want || host != tc.host {
			t.Errorf("%s %s: %s %q, quer %s %q", tc.robot, tc.ip, got, host, tc.want, tc.host)
		}
	}
}

// Cache de 24 h: a segunda consulta não vai ao DNS; depois de 24 h vai; unknown não entra no cache; Forget apaga
// o prefixo.
func TestVerifyCache(t *testing.T) {
	r := newResolver()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	v := NewVerifier(r, c.Now)
	ctx := context.Background()
	ip := netip.MustParseAddr("66.249.66.1")
	v.Verify(ctx, "googlebot", ip)
	v.Verify(ctx, "googlebot", ip)
	if r.count() != 1 {
		t.Fatalf("consultas %d, quer 1 (cache)", r.count())
	}
	c.Advance(24*time.Hour + time.Second)
	v.Verify(ctx, "googlebot", ip)
	if r.count() != 2 {
		t.Fatalf("consultas %d depois de 24 h", r.count())
	}
	v.Verify(ctx, "googlebot", netip.MustParseAddr("192.0.2.99"))
	v.Verify(ctx, "googlebot", netip.MustParseAddr("192.0.2.99"))
	if r.count() != 4 {
		t.Fatalf("unknown no cache: consultas %d", r.count())
	}
	v.Verify(ctx, "googlebot", netip.MustParseAddr("192.0.2.10"))
	v.Verify(ctx, "bingbot", netip.MustParseAddr("2001:db8::bb"))
	if v.Len() != 3 {
		t.Fatalf("cache %d", v.Len())
	}
	if n := v.Forget(netip.MustParsePrefix("66.249.0.0/16")); n != 1 {
		t.Errorf("Forget v4 %d", n)
	}
	if n := v.Forget(netip.MustParsePrefix("::ffff:192.0.2.0/120")); n != 1 {
		t.Errorf("Forget mapeado %d", n)
	}
	if n := v.Forget(netip.MustParsePrefix("2001:db8::/32")); n != 1 {
		t.Errorf("Forget v6 %d", n)
	}
	if v.Len() != 0 {
		t.Errorf("cache depois do Forget %d", v.Len())
	}
}

// O teto do cache segura a memória.
func TestVerifyCacheCap(t *testing.T) {
	r := &fakeResolver{ptr: map[string][]string{}}
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	v := NewVerifier(r, c.Now)
	v.maxCache = 10
	for i := range 50 {
		v.Verify(context.Background(), "googlebot", netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	if v.Len() > 10 {
		t.Errorf("cache %d > teto", v.Len())
	}
}
