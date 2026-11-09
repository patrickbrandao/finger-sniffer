// Package dns é o serviço dns: autoritativo de FS_DNS_ZONE em UDP e TCP 53 (spec 007), com o TXT do DNS-01
// definido pelo web por request/reply NATS (spec 015).
package dns

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Valores fixos do serviço.
const (
	// DefaultNS é o servidor de nomes da zona (delegação no udns, ADR 0008).
	DefaultNS = "vps602.tmsoft.com.br."
	// ACMEValueTTL é por quanto tempo cada valor TXT do DNS-01 fica vivo após o set (spec 007).
	ACMEValueTTL = 10 * time.Minute
	// DefaultPort é a porta do autoritativo.
	DefaultPort = 53
)

// Config é a configuração do dns.
type Config struct {
	// Zone é a zona servida, FQDN em minúsculas com ponto final.
	Zone string
	// NS é o servidor de nomes publicado no apex (FQDN).
	NS string
	// TTL dos registros servidos (FS_DNS_TTL).
	TTL time.Duration
	// IPv4 e IPv6 são os IPs públicos do espelho (FS_LISTEN_IPV4/FS_LISTEN_IPV6); inválidos = desligados.
	IPv4 netip.Addr
	IPv6 netip.Addr
	// Port é a porta UDP/TCP dos listeners (53; outra só em teste).
	Port int
	// RRLPerIP é o limite de respostas por segundo por IP de origem (FS_DNS_RRL_PER_IP, task 028).
	RRLPerIP int
	// ACMETTL é a validade de cada valor TXT do DNS-01.
	ACMETTL time.Duration
	// H3 diz se o web atende UDP 443 (FS_WEB_UDP_PORTS contém 443): o HTTPS RR anuncia alpn="h3,h2"; senão
	// alpn="h2" (spec 007 RF-02, ADR 0019). Lido só na partida.
	H3 bool
}

// LoadConfig lê a configuração das variáveis FS_* (modelo em .env.example).
func LoadConfig() (Config, error) {
	c := Config{NS: DefaultNS, Port: DefaultPort, ACMETTL: ACMEValueTTL}
	var err error
	c.Zone = mdns.CanonicalName(service.Env("FS_DNS_ZONE", "dns-monitor.tmsoft.com.br"))
	if _, ok := mdns.IsDomainName(c.Zone); !ok || c.Zone == "." {
		return c, fmt.Errorf("dns: FS_DNS_ZONE invalid: %q", c.Zone)
	}
	if c.TTL, err = service.EnvDuration("FS_DNS_TTL", 5*time.Second); err != nil {
		return c, err
	}
	if c.RRLPerIP, err = service.EnvInt("FS_DNS_RRL_PER_IP", 20); err != nil {
		return c, err
	}
	if c.IPv4, err = parseIP("FS_LISTEN_IPV4", true); err != nil {
		return c, err
	}
	if c.IPv6, err = parseIP("FS_LISTEN_IPV6", false); err != nil {
		return c, err
	}
	if c.H3, err = webUDP443(); err != nil {
		return c, err
	}
	if !c.IPv4.IsValid() && !c.IPv6.IsValid() {
		return c, fmt.Errorf("dns: FS_LISTEN_IPV4 and FS_LISTEN_IPV6 are both empty")
	}
	return c, nil
}

// webUDP443 diz se FS_WEB_UDP_PORTS (env compartilhado com o web) contém a porta 443. Ausente vale o padrão do
// web (443); presente e vazio quer dizer que o web não escuta UDP.
func webUDP443() (bool, error) {
	v, ok := os.LookupEnv("FS_WEB_UDP_PORTS")
	if !ok {
		return true, nil
	}
	found := false
	for f := range strings.SplitSeq(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return false, fmt.Errorf("dns: FS_WEB_UDP_PORTS invalid: %q", v)
		}
		found = found || n == 443
	}
	return found, nil
}

// parseIP lê um IP opcional da família pedida.
func parseIP(key string, v4 bool) (netip.Addr, error) {
	s := strings.TrimSpace(service.Env(key, ""))
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4() != v4 || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("dns: %s invalid: %q", key, s)
	}
	return a, nil
}

// ttlSeconds devolve o TTL em segundos para os RRs (mínimo 0).
func (c Config) ttlSeconds() uint32 {
	return clampU32(int64(c.TTL / time.Second))
}

// listenAddrs devolve os endereços IP:porta dos listeners, na ordem IPv4, IPv6.
func (c Config) listenAddrs() []string {
	var out []string
	for _, a := range []netip.Addr{c.IPv4, c.IPv6} {
		if a.IsValid() {
			out = append(out, net.JoinHostPort(a.String(), strconv.Itoa(c.Port)))
		}
	}
	return out
}

// clampU32 limita v ao intervalo de um uint32.
func clampU32(v int64) uint32 {
	switch {
	case v <= 0:
		return 0
	case v > int64(^uint32(0)):
		return ^uint32(0)
	}
	return uint32(v) //nolint:gosec // limitado acima
}
