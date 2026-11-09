// Package raw implementa o serviço raw (spec 006): portas TCP cruas com os modos echo, banner, sink e source,
// linha PROBE opcional, teste de meio-fechamento e publicação dos bytes de cada sentido no NATS.
package raw

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Modos com TLS (spec 006 RF-02): terminam TLS antes de aplicar o modo de dentro.
const (
	ModeTLSEcho   = "tls-echo"
	ModeTLSBanner = "tls-banner"
	ModeTLSSink   = "tls-sink"
	ModeTLSSource = "tls-source"
)

// DefaultPorts é o valor padrão de FS_RAW_PORTS (spec 006 RF-01).
const DefaultPorts = "7:echo,21:banner,22:banner,25:banner,110:banner,143:banner,587:banner,993:tls-banner"

// Valores padrão.
const (
	DefaultIdle        = 120 * time.Second
	DefaultSourceBytes = 1 << 20
	DefaultStreamMax   = event.DefaultRawStreamMaxBytes
	// GenericBanner é o banner das portas em modo banner que não têm um banner próprio na spec.
	GenericBanner = "220 finger-sniffer ready\r\n"
	// HalfCloseMessage é o que o servidor manda depois do FIN do cliente (spec 006 RF-05).
	HalfCloseMessage = "half-close test\r\n"
)

// banners são os banners da tabela da spec 006 RF-01.
var banners = map[int]string{
	21:  "220 finger-sniffer FTP ready\r\n",
	22:  "SSH-2.0-finger-sniffer\r\n",
	25:  "220 finger-sniffer ESMTP ready\r\n",
	587: "220 finger-sniffer ESMTP ready\r\n",
	110: "+OK finger-sniffer POP3 ready\r\n",
	143: "* OK finger-sniffer IMAP ready\r\n",
	993: "* OK finger-sniffer IMAP ready\r\n",
}

// BannerFor devolve o banner da porta (o da spec, ou o genérico).
func BannerFor(port int) string {
	if b, ok := banners[port]; ok {
		return b
	}
	return GenericBanner
}

// PortSpec é uma porta de FS_RAW_PORTS.
type PortSpec struct {
	Port int
	// Mode é o modo de dentro (echo, banner, sink, source), já sem o prefixo tls-.
	Mode string
	// TLS é true nos modos tls-*.
	TLS bool
	// Banner é o banner usado quando o modo (da porta ou da linha PROBE) é banner.
	Banner string
}

// Name devolve o modo como escrito em FS_RAW_PORTS.
func (p PortSpec) Name() string {
	if p.TLS {
		return "tls-" + p.Mode
	}
	return p.Mode
}

// ParsePorts interpreta FS_RAW_PORTS: lista "porta:modo" separada por vírgulas.
func ParsePorts(s string) ([]PortSpec, error) {
	var out []PortSpec
	seen := map[int]bool{}
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		ps, ms, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("raw: FS_RAW_PORTS: %q: want port:mode", item)
		}
		port, err := strconv.Atoi(strings.TrimSpace(ps))
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("raw: FS_RAW_PORTS: invalid port %q", ps)
		}
		// Porta 0 (efêmera) só faz sentido em teste, e pode repetir.
		if port != 0 && seen[port] {
			return nil, fmt.Errorf("raw: FS_RAW_PORTS: duplicate port %d", port)
		}
		seen[port] = true
		spec := PortSpec{Port: port, Banner: BannerFor(port)}
		mode := strings.TrimSpace(ms)
		if inner, isTLS := strings.CutPrefix(mode, "tls-"); isTLS {
			spec.TLS, mode = true, inner
		}
		switch mode {
		case probe.ModeEcho, probe.ModeBanner, probe.ModeSink, probe.ModeSource:
			spec.Mode = mode
		default:
			return nil, fmt.Errorf("raw: FS_RAW_PORTS: invalid mode %q", ms)
		}
		out = append(out, spec)
	}
	if len(out) == 0 {
		return nil, errors.New("raw: FS_RAW_PORTS: empty")
	}
	return out, nil
}

// Config é a configuração do serviço raw.
type Config struct {
	// ListenHost é o endereço de escuta ("" = todos).
	ListenHost string
	Ports      []PortSpec
	// Idle é a ociosidade máxima sem atividade (FS_IDLE_DEFAULT, spec 006 RF-07).
	Idle time.Duration
	// SourceBytes é o padrão de bytes do modo source (n= da linha PROBE muda).
	SourceBytes int64
	// StreamMax é o teto de bytes publicados por sentido (FS_RAW_STREAM_MAX_BYTES, ADR 0018).
	StreamMax int64
	// ProbeWait é quanto o modo source espera pela linha PROBE antes de começar a mandar.
	ProbeWait time.Duration
	// TLS é a configuração do servidor TLS (pkg/certs, a mesma do web); nil desliga o TLS: as portas tls-*
	// atendem em claro e não há TLS automático.
	TLS *tls.Config
	// EventInlineMax é o teto do ClientHello inline no evento (FS_EVENT_INLINE_MAX, ADR 0018).
	EventInlineMax int
}

// LoadConfig lê a configuração das variáveis FS_*.
func LoadConfig() (Config, error) {
	c := Config{
		ListenHost:  service.Env("FS_RAW_LISTEN_HOST", ""),
		SourceBytes: DefaultSourceBytes,
		ProbeWait:   time.Second,
	}
	var err error
	if c.Ports, err = ParsePorts(service.Env("FS_RAW_PORTS", DefaultPorts)); err != nil {
		return c, err
	}
	if c.Idle, err = service.EnvDuration("FS_IDLE_DEFAULT", DefaultIdle); err != nil {
		return c, err
	}
	if c.Idle <= 0 {
		return c, errors.New("raw: FS_IDLE_DEFAULT must be positive")
	}
	streamMax, err := service.EnvInt(event.EnvRawStreamMaxBytes, DefaultStreamMax)
	if err != nil {
		return c, err
	}
	if streamMax <= 0 {
		return c, errors.New("raw: FS_RAW_STREAM_MAX_BYTES must be positive")
	}
	c.StreamMax = int64(streamMax)
	return c, nil
}
