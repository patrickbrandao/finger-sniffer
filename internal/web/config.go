// Package web é o serviço web (spec 005): portas TCP capturadas com detecção do protocolo pelos primeiros
// bytes, TLS com captura do ClientHello (spec 008), HTTP/1 sem normalização (spec 009), rotas do espelho,
// arquivos de FS_HTDOCS (spec 014) e eventos de aplicação no NATS com os tetos da ADR 0018.
package web

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/detect"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Padrões de .env.example.
const (
	DefaultTCPPorts    = "80,443,8080,8443"
	DefaultHtdocs      = "/finger-sniffer/htdocs"
	DefaultIdle        = 120 * time.Second
	DefaultIdleMax     = 600 * time.Second
	DefaultMaxConns    = 200
	defaultRetryListen = 10 * time.Second
)

// Config é a configuração do serviço web.
type Config struct {
	// TCPPorts são as portas TCP atendidas (FS_WEB_TCP_PORTS).
	TCPPorts []int
	// ListenIPv4 e ListenIPv6 são os IPs públicos (FS_LISTEN_IPV4/FS_LISTEN_IPV6); inválido = desligado.
	ListenIPv4 netip.Addr
	ListenIPv6 netip.Addr
	// MaxConns limita as conexões simultâneas (FS_MAX_CONNS).
	MaxConns int
	// Htdocs é a pasta do site estático (FS_HTDOCS).
	Htdocs string
	// IdleDefault é a ociosidade mantida pelo servidor antes de fechar (FS_IDLE_DEFAULT, spec 005 RF-08).
	IdleDefault time.Duration
	// IdleMax é o teto do controle idle= (FS_IDLE_MAX).
	IdleMax time.Duration
	// Limits são os tetos dos controles de resposta (FS_SIZE_MAX, FS_DELAY_MAX, FS_HSIZE_MAX).
	Limits ControlLimits
	// DetectBytes e DetectTimeout limitam a detecção pelos primeiros bytes (spec 005: 24 bytes ou 2 s).
	DetectBytes   int
	DetectTimeout time.Duration
	// EventInlineMax é o teto de bytes crus por campo inline (FS_EVENT_INLINE_MAX, ADR 0018).
	EventInlineMax int
	// RawBodyMax é o teto do corpo cru inline (FS_RAW_BODY_MAX_BYTES), nunca acima de EventInlineMax.
	RawBodyMax int
	// RawStreamMax é o teto do fluxo de aplicação por sentido e conexão (FS_RAW_STREAM_MAX_BYTES).
	RawStreamMax int
	// MaxHeadBytes é o teto do cabeçalho de requisição (spec 009 RF-10, 1 MiB).
	MaxHeadBytes int
	// ProxyRules é a lista de campos que indicam proxy (FS_WEB_PROXY_FIELDS; vazio = lista padrão).
	ProxyRules []h1.ProxyRule
	// H2Limits são os tetos do parser passivo do h2 (FS_MAX_H2_PRIORITY_FRAMES, spec 010 RF-03).
	H2Limits h2passive.Limits
	// Zones são as zonas dos probes no SNI e no Host.
	Zones []string
	// RetryListen é o intervalo entre tentativas de abrir um listener que falhou.
	RetryListen time.Duration
	// Warnings são avisos da carga (ex.: FS_RAW_BODY_MAX_BYTES reduzido), logados na partida.
	Warnings []string
}

// LoadConfig lê a configuração do web das variáveis FS_*; base traz os tetos comuns de pkg/service.
func LoadConfig(base service.Config) (Config, error) {
	c := Config{
		EventInlineMax: base.EventInlineMax,
		RawStreamMax:   base.RawStreamMaxBytes,
		DetectBytes:    detect.DefaultMaxBytes,
		DetectTimeout:  detect.DefaultTimeout,
		MaxHeadBytes:   h1.DefaultMaxHeadBytes,
		Zones:          probe.DefaultZones,
		RetryListen:    defaultRetryListen,
	}
	var err error
	if c.TCPPorts, err = parsePorts(service.Env("FS_WEB_TCP_PORTS", DefaultTCPPorts)); err != nil {
		return c, err
	}
	if c.ListenIPv4, err = parseIP("FS_LISTEN_IPV4", true); err != nil {
		return c, err
	}
	if c.ListenIPv6, err = parseIP("FS_LISTEN_IPV6", false); err != nil {
		return c, err
	}
	if !c.ListenIPv4.IsValid() && !c.ListenIPv6.IsValid() {
		return c, fmt.Errorf("web: FS_LISTEN_IPV4 and FS_LISTEN_IPV6 are both empty")
	}
	if c.MaxConns, err = service.EnvInt("FS_MAX_CONNS", DefaultMaxConns); err != nil {
		return c, err
	}
	if c.MaxConns <= 0 {
		return c, fmt.Errorf("web: FS_MAX_CONNS must be > 0")
	}
	c.Htdocs = service.Env("FS_HTDOCS", DefaultHtdocs)
	if c.IdleDefault, err = service.EnvDuration("FS_IDLE_DEFAULT", DefaultIdle); err != nil {
		return c, err
	}
	if c.IdleMax, err = service.EnvDuration("FS_IDLE_MAX", DefaultIdleMax); err != nil {
		return c, err
	}
	if c.IdleDefault <= 0 || c.IdleMax < c.IdleDefault {
		return c, fmt.Errorf("web: need 0 < FS_IDLE_DEFAULT <= FS_IDLE_MAX")
	}
	if c.Limits, err = loadControlLimits(); err != nil {
		return c, err
	}
	if c.RawBodyMax, err = service.EnvInt("FS_RAW_BODY_MAX_BYTES", h1.DefaultRawBodyMax); err != nil {
		return c, err
	}
	// ADR 0018: o corpo cru inline nunca passa do teto inline (o env da vps602 ainda pode ter 1 MiB).
	if c.RawBodyMax > c.EventInlineMax {
		c.Warnings = append(c.Warnings, fmt.Sprintf("FS_RAW_BODY_MAX_BYTES=%d above FS_EVENT_INLINE_MAX; using %d",
			c.RawBodyMax, c.EventInlineMax))
		c.RawBodyMax = c.EventInlineMax
	}
	if c.H2Limits, err = h2passive.LimitsFromEnv(); err != nil {
		return c, err
	}
	if list := service.Env("FS_WEB_PROXY_FIELDS", ""); list != "" {
		if c.ProxyRules, err = h1.ParseProxyRules(list); err != nil {
			return c, fmt.Errorf("web: FS_WEB_PROXY_FIELDS: %w", err)
		}
	}
	return c, nil
}

// parsePorts lê uma lista de portas separadas por vírgula.
func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("web: FS_WEB_TCP_PORTS: invalid port %q", p)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("web: FS_WEB_TCP_PORTS is empty")
	}
	return out, nil
}

// parseIP lê um IP opcional da família pedida.
func parseIP(key string, v4 bool) (netip.Addr, error) {
	s := strings.TrimSpace(service.Env(key, ""))
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4() != v4 || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("web: %s invalid: %q", key, s)
	}
	return a, nil
}

// listenAddrs devolve os endereços TCP a abrir (IPv4 e IPv6 × portas).
func (c Config) listenAddrs() []string {
	var out []string
	for _, ip := range []netip.Addr{c.ListenIPv4, c.ListenIPv6} {
		if !ip.IsValid() {
			continue
		}
		for _, p := range c.TCPPorts {
			out = append(out, netip.AddrPortFrom(ip, uint16(p)).String()) //nolint:gosec // portas validadas em parsePorts (1..65535)
		}
	}
	return out
}
