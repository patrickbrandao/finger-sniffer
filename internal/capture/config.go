package capture

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Config do capture (FS_CAPTURE_*).
type Config struct {
	Iface        string
	Snaplen      int
	Exclude      []uint16
	BlockTimeout time.Duration
	BatchMax     int
	BatchWait    time.Duration
	NetStatus    string
}

// DefaultExcludePorts é o padrão de FS_CAPTURE_EXCLUDE_PORTS (spec 003 RF-02): ssh e snmp de gerência, API do
// store (9000/9001) e API do bot (9002/9003, ADR 0047). Vazio também vale o padrão; para não excluir porta nenhuma,
// use ",".
const DefaultExcludePorts = "48022,48161,9000,9001,9002,9003"

// LoadConfig lê a configuração do capture.
func LoadConfig() (Config, error) {
	c := Config{
		Iface:     service.Env("FS_CAPTURE_IFACE", "ens192"),
		NetStatus: service.Env("FS_NET_STATUS_FILE", "/run/finger-sniffer/net-status.json"),
	}
	var err error
	if c.Snaplen, err = service.EnvInt("FS_CAPTURE_SNAPLEN", 65535); err != nil {
		return c, err
	}
	if c.Snaplen < 64 || c.Snaplen > maxSnap {
		return c, fmt.Errorf("capture: FS_CAPTURE_SNAPLEN must be between 64 and %d", maxSnap)
	}
	if c.BatchMax, err = service.EnvInt("FS_CAPTURE_BATCH_MAX", 256); err != nil {
		return c, err
	}
	// Zero ou negativo fecharia um lote por pacote.
	if c.BatchMax < 1 {
		return c, fmt.Errorf("capture: FS_CAPTURE_BATCH_MAX must be at least 1")
	}
	if c.BatchWait, err = service.EnvDuration("FS_CAPTURE_BATCH_WAIT", 5*time.Millisecond); err != nil {
		return c, err
	}
	// BatchWait é também o prazo do poll, em ms inteiros: abaixo de 1 ms vira poll(…, 0) e o laço gira sem pausa;
	// negativo vira poll sem prazo e o lote parcial fica preso até o próximo pacote.
	if c.BatchWait < time.Millisecond {
		return c, fmt.Errorf("capture: FS_CAPTURE_BATCH_WAIT must be at least 1ms")
	}
	if c.BlockTimeout, err = service.EnvDuration("FS_CAPTURE_BLOCK_TIMEOUT", 10*time.Millisecond); err != nil {
		return c, err
	}
	if c.Exclude, err = ParsePorts(service.Env("FS_CAPTURE_EXCLUDE_PORTS", DefaultExcludePorts)); err != nil {
		return c, err
	}
	return c, nil
}

// ParsePorts lê uma lista de portas separadas por vírgula.
func ParsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("capture: invalid port %q", f)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}
