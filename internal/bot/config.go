// Package bot é o serviço de vereditos de bot (specs 018 e 020, ADRs 0047–0053). Nesta primeira entrega
// (task 267): configuração, banco em disco, chaves de API, API 9002/9003, ingest do traefik e índice das
// conexões vistas pelo store; sinais, veredito, listas e agregados vêm na segunda onda.
package bot

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// ServiceName é o nome do serviço no envelope e no heartbeat (asyncapi 0.6.0, enum `service`).
const ServiceName = "bot"

// MaxAggRetention é o teto da retenção dos agregados (ADR 0052 item 1).
const MaxAggRetention = 7 * 24 * time.Hour

// Config é a configuração FS_BOT_* do serviço (spec 018 "Interfaces e contratos").
type Config struct {
	// PublicIPs são os IPs da 9002 (FS_LISTEN_IPV4/FS_LISTEN_IPV6); vazio desliga a porta pública.
	PublicIPs  []netip.Addr
	PublicPort int // FS_BOT_PUBLIC_PORT
	// InternalListen é o IP do host na bridge do traefik (FS_BOT_INTERNAL_LISTEN), além de 127.0.0.1.
	InternalListen netip.Addr
	InternalPort   int // FS_BOT_INTERNAL_PORT
	// InternalAllow são as redes de origem aceitas na 9003, além do loopback (FS_BOT_INTERNAL_ALLOW).
	InternalAllow []netip.Prefix

	DBPath        string        // FS_BOT_DB
	MaxBytes      int64         // FS_BOT_MAX_BYTES
	FlushInterval time.Duration // FS_BOT_FLUSH_INTERVAL
	AggRetention  time.Duration // FS_BOT_AGG_RETENTION
	ConnTTL       time.Duration // FS_BOT_CONN_TTL
	MaxConns      int           // FS_BOT_MAX_CONNS
	IndexMaxBytes int64         // FS_BOT_INDEX_MAX_BYTES (teto aproximado do índice, ADR 0057 item 2)
	ViewWait      time.Duration // FS_BOT_VIEW_WAIT
	RateHigh      int           // FS_BOT_RATE_HIGH
	ListRefreshAt time.Duration // FS_BOT_LIST_REFRESH_AT (HH:MM UTC, como deslocamento desde 00:00)
	JA4DBURL      string        // FS_BOT_JA4DB_URL (padrão https://ja4db.com/api/read/)
	JA4DBEnable   bool          // FS_BOT_JA4DB_ENABLE (padrão false até a P4, ADR 0056 item 1)
	// ListURLs troca a URL de uma lista do catálogo (FS_BOT_LIST_<NOME>_URL), por nome.
	ListURLs map[string]string
	// ListsDir é a pasta das cópias das listas (var/bot/lists, ao lado do banco); vazio desliga os downloads.
	ListsDir string
	// P0FPath é o p0f.fp do palpite de SO da visão TCP do traefix (FS_BOT_P0F_DB, o mesmo do store; ADR 0063
	// item 5); vazio desliga o palpite.
	P0FPath string
}

// interfacePrefix acha a sub-rede da interface que tem o IP (variável para os testes).
var interfacePrefix = func(ip netip.Addr) (netip.Prefix, bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Prefix{}, false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(n.String())
		if err == nil && p.Addr().Unmap() == ip {
			return p.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

// LoadConfig lê as variáveis FS_BOT_* (padrões da spec 018).
func LoadConfig() (Config, error) {
	c := Config{}
	var err error
	if c.PublicIPs, err = publicIPs(); err != nil {
		return c, err
	}
	if c.PublicPort, err = envPort("FS_BOT_PUBLIC_PORT", 9002); err != nil {
		return c, err
	}
	if c.InternalPort, err = envPort("FS_BOT_INTERNAL_PORT", 9003); err != nil {
		return c, err
	}
	var listenPrefix netip.Prefix
	if s := strings.TrimSpace(service.Env("FS_BOT_INTERNAL_LISTEN", "")); s != "" {
		// Aceita "IP" ou "IP/len"; com o comprimento, a rede vira o padrão de FS_BOT_INTERNAL_ALLOW.
		if p, perr := netip.ParsePrefix(s); perr == nil {
			c.InternalListen, listenPrefix = p.Addr(), p.Masked()
		} else if a, aerr := netip.ParseAddr(s); aerr == nil {
			c.InternalListen = a
		} else {
			return c, fmt.Errorf("bot: FS_BOT_INTERNAL_LISTEN invalid: %q", s)
		}
		if c.InternalListen.IsUnspecified() || c.InternalListen.Zone() != "" {
			return c, fmt.Errorf("bot: FS_BOT_INTERNAL_LISTEN must be a host address: %q", s)
		}
	}
	if s := strings.TrimSpace(service.Env("FS_BOT_INTERNAL_ALLOW", "")); s != "" {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			p, perr := netip.ParsePrefix(part)
			if perr != nil {
				return c, fmt.Errorf("bot: FS_BOT_INTERNAL_ALLOW invalid: %q", part)
			}
			c.InternalAllow = append(c.InternalAllow, p.Masked())
		}
	} else if c.InternalListen.IsValid() {
		// Padrão: a sub-rede de FS_BOT_INTERNAL_LISTEN (spec 020 RF-01); sem como saber, só o próprio IP.
		switch {
		case listenPrefix.IsValid():
			c.InternalAllow = []netip.Prefix{listenPrefix}
		default:
			if p, ok := interfacePrefix(c.InternalListen); ok {
				c.InternalAllow = []netip.Prefix{p}
			} else {
				c.InternalAllow = []netip.Prefix{netip.PrefixFrom(c.InternalListen, c.InternalListen.BitLen())}
			}
		}
	}
	c.DBPath = service.Env("FS_BOT_DB", "/finger-sniffer/var/bot/bot.db")
	maxBytes, err := service.EnvInt("FS_BOT_MAX_BYTES", 2<<30)
	if err != nil {
		return c, err
	}
	c.MaxBytes = int64(maxBytes)
	if c.FlushInterval, err = service.EnvDuration("FS_BOT_FLUSH_INTERVAL", 5*time.Second); err != nil {
		return c, err
	}
	if c.AggRetention, err = service.EnvDuration("FS_BOT_AGG_RETENTION", MaxAggRetention); err != nil {
		return c, err
	}
	if c.ConnTTL, err = service.EnvDuration("FS_BOT_CONN_TTL", 10*time.Minute); err != nil {
		return c, err
	}
	if c.MaxConns, err = service.EnvInt("FS_BOT_MAX_CONNS", 100000); err != nil {
		return c, err
	}
	indexMax, err := service.EnvInt("FS_BOT_INDEX_MAX_BYTES", DefaultIndexMaxBytes)
	if err != nil {
		return c, err
	}
	c.IndexMaxBytes = int64(indexMax)
	if c.ViewWait, err = service.EnvDuration("FS_BOT_VIEW_WAIT", 100*time.Millisecond); err != nil {
		return c, err
	}
	if c.RateHigh, err = service.EnvInt("FS_BOT_RATE_HIGH", 120); err != nil {
		return c, err
	}
	if c.ListRefreshAt, err = parseClock(service.Env("FS_BOT_LIST_REFRESH_AT", "04:00")); err != nil {
		return c, err
	}
	c.JA4DBURL = service.Env("FS_BOT_JA4DB_URL", lists.JA4DBDefaultURL)
	if c.JA4DBEnable, err = strconv.ParseBool(service.Env("FS_BOT_JA4DB_ENABLE", "false")); err != nil {
		return c, fmt.Errorf("bot: FS_BOT_JA4DB_ENABLE must be true or false: %w", err)
	}
	c.ListURLs = map[string]string{}
	for _, src := range lists.Catalog {
		if u := strings.TrimSpace(service.Env(lists.EnvKey(src.Name), "")); u != "" {
			c.ListURLs[src.Name] = u
		}
	}
	c.ListsDir = filepath.Join(filepath.Dir(c.DBPath), "lists")
	c.P0FPath = strings.TrimSpace(service.Env("FS_BOT_P0F_DB", "/finger-sniffer/etc/p0f.fp"))
	return c, c.validate()
}

// Teto de bytes do índice (FS_BOT_INDEX_MAX_BYTES, ADR 0057 item 2): 320 MiB por padrão (ADR 0079), nunca abaixo
// de 16 MiB.
const (
	DefaultIndexMaxBytes = 320 << 20
	MinIndexMaxBytes     = 16 << 20
)

func (c Config) validate() error {
	switch {
	case c.MaxBytes <= 0:
		return errors.New("bot: FS_BOT_MAX_BYTES must be positive")
	case c.FlushInterval <= 0:
		return errors.New("bot: FS_BOT_FLUSH_INTERVAL must be positive")
	case c.AggRetention <= 0 || c.AggRetention > MaxAggRetention:
		return fmt.Errorf("bot: FS_BOT_AGG_RETENTION must be between 1ns and %s", MaxAggRetention)
	case c.ConnTTL <= 0:
		return errors.New("bot: FS_BOT_CONN_TTL must be positive")
	case c.MaxConns <= 0:
		return errors.New("bot: FS_BOT_MAX_CONNS must be positive")
	case c.IndexMaxBytes < MinIndexMaxBytes:
		return fmt.Errorf("bot: FS_BOT_INDEX_MAX_BYTES must be at least %d (16 MiB)", MinIndexMaxBytes)
	case c.ViewWait < 0 || c.ViewWait > time.Second:
		return errors.New("bot: FS_BOT_VIEW_WAIT must be between 0 and 1s")
	case c.RateHigh <= 0:
		return errors.New("bot: FS_BOT_RATE_HIGH must be positive")
	case c.JA4DBURL != "" && !isHTTPS(c.JA4DBURL):
		return fmt.Errorf("bot: FS_BOT_JA4DB_URL must be https: %q", c.JA4DBURL)
	}
	for name, u := range c.ListURLs {
		if !isHTTPS(u) {
			return fmt.Errorf("bot: %s must be https: %q", lists.EnvKey(name), u)
		}
	}
	return nil
}

// isHTTPS: as listas só são baixadas por HTTPS (ADR 0050 item 5).
func isHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// publicIPs lê FS_LISTEN_IPV4 e FS_LISTEN_IPV6 (vazio = família ausente), nunca "*" (ADR 0023).
func publicIPs() ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, k := range []struct {
		key string
		v4  bool
	}{{"FS_LISTEN_IPV4", true}, {"FS_LISTEN_IPV6", false}} {
		s := strings.TrimSpace(service.Env(k.key, ""))
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Is4() != k.v4 || a.Zone() != "" || a.IsUnspecified() {
			return nil, fmt.Errorf("bot: %s invalid: %q", k.key, s)
		}
		ips = append(ips, a)
	}
	return ips, nil
}

func envPort(key string, def int) (int, error) {
	p, err := service.EnvInt(key, def)
	if err != nil {
		return 0, err
	}
	if p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bot: %s out of range: %d", key, p)
	}
	return p, nil
}

// parseClock lê HH:MM (UTC).
func parseClock(s string) (time.Duration, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("bot: FS_BOT_LIST_REFRESH_AT must be HH:MM: %q", s)
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}
