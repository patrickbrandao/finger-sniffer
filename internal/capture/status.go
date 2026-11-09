package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// aggregatingFeatures são os offloads que juntam pacotes na recepção (ADR 0011).
var aggregatingFeatures = []string{"generic-receive-offload", "large-receive-offload", "rx-gro-hw"}

// Health calcula o estado do capture para o heartbeat (spec 003 RF-06/RF-07).
type Health struct {
	iface     string
	netStatus string
	// features lê o estado atual dos offloads ("nome: on|off"); padrão: ethtool -k.
	features func(ctx context.Context, iface string) (string, error)
	// aggregating guarda a última leitura dos offloads de agregação (true = algum ligado).
	aggregating atomic.Bool

	mu        sync.Mutex
	drops     uint64 // total acumulado do kernel
	lastDrops uint64 // total no último heartbeat
	suspect   uint64
	lastSusp  uint64
}

// NewHealth cria o avaliador.
func NewHealth(iface, netStatus string) *Health {
	return &Health{iface: iface, netStatus: netStatus, features: ethtoolFeatures}
}

func ethtoolFeatures(ctx context.Context, iface string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ethtool", "-k", iface).Output() //nolint:gosec // nome da interface da config
	return string(out), err
}

// ObserveDrops registra o total acumulado de perdas do kernel.
func (h *Health) ObserveDrops(total uint64) {
	h.mu.Lock()
	h.drops = total
	h.mu.Unlock()
}

// ObserveSuspect soma frames maiores que MTU + 14.
func (h *Health) ObserveSuspect(n uint64) {
	h.mu.Lock()
	h.suspect += n
	h.mu.Unlock()
}

// Status implementa service.StatusFunc. Consulta os offloads atuais (ethtool), cai para o arquivo gravado no
// boot pela unit de rede quando o ethtool não responde, e marca perdas e frames suspeitos desde o último heartbeat.
func (h *Health) Status() (string, []string) {
	var reasons []string
	if on, err := h.Refresh(); err != nil {
		reasons = append(reasons, err.Error())
	} else if len(on) > 0 {
		reasons = append(reasons, "aggregating offload on: "+strings.Join(on, ","))
	}

	h.mu.Lock()
	newDrops, newSuspect := h.drops-h.lastDrops, h.suspect-h.lastSusp
	h.lastDrops, h.lastSusp = h.drops, h.suspect
	h.mu.Unlock()
	if newDrops > 0 {
		reasons = append(reasons, fmt.Sprintf("kernel dropped %d packets", newDrops))
	}
	if newSuspect > 0 {
		reasons = append(reasons, fmt.Sprintf("%d frames larger than MTU+14", newSuspect))
	}

	if len(reasons) > 0 {
		return event.StatusDegraded, reasons
	}
	return event.StatusOK, nil
}

// Refresh relê os offloads de agregação, guarda o resultado para Aggregating e devolve os que estão ligados. Sem
// leitura possível, mantém o último estado conhecido.
func (h *Health) Refresh() ([]string, error) {
	on, err := h.aggregatingNow()
	if err == nil {
		h.aggregating.Store(len(on) > 0)
	}
	return on, err
}

// Aggregating informa se, na última leitura, algum offload de agregação estava ligado (custo de um load atômico;
// chamado a cada pacote).
func (h *Health) Aggregating() bool { return h.aggregating.Load() }

func (h *Health) aggregatingNow() ([]string, error) {
	if out, err := h.features(context.Background(), h.iface); err == nil {
		var on []string
		for _, line := range strings.Split(out, "\n") {
			name, val, ok := strings.Cut(strings.TrimSpace(line), ": ")
			if ok && contains(aggregatingFeatures, name) && strings.HasPrefix(val, "on") {
				on = append(on, name)
			}
		}
		return on, nil
	}
	raw, err := os.ReadFile(h.netStatus)
	if err != nil {
		return nil, fmt.Errorf("offload state unavailable")
	}
	var ns struct {
		Offloads map[string]string `json:"offloads"`
	}
	if json.Unmarshal(raw, &ns) != nil {
		return nil, fmt.Errorf("net status invalid")
	}
	var on []string
	for _, f := range aggregatingFeatures {
		if ns.Offloads[f] == "on" {
			on = append(on, f)
		}
	}
	return on, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
