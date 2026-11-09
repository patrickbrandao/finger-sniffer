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

// LoadConfig lê a configuração do capture.
func LoadConfig() (Config, error) {
	c := Config{
		Iface:     service.Env("FS_CAPTURE_IFACE", "eth0"),
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
	if c.BatchWait, err = service.EnvDuration("FS_CAPTURE_BATCH_WAIT", 5*time.Millisecond); err != nil {
		return c, err
	}
	if c.BlockTimeout, err = service.EnvDuration("FS_CAPTURE_BLOCK_TIMEOUT", 10*time.Millisecond); err != nil {
		return c, err
	}
	if c.Exclude, err = ParsePorts(service.Env("FS_CAPTURE_EXCLUDE_PORTS", "48022,48161,9000,9001")); err != nil {
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
