package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/certs"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// DefaultDownAfter é o tempo sem heartbeat para considerar um serviço "down" (spec 004 RF-09).
const DefaultDownAfter = 15 * time.Second

// Health é a resposta de /api/v1/health (schema Health do openapi.yaml).
type Health struct {
	OK            bool                     `json:"ok"`
	Version       string                   `json:"version"`
	VersionsMatch bool                     `json:"versions_match"`
	Services      map[string]ServiceHealth `json:"services"`
	Host          *HostHealth              `json:"host,omitempty"`
}

// ServiceHealth é o estado de um serviço.
type ServiceHealth struct {
	Status        string             `json:"status"`
	Version       string             `json:"version,omitempty"`
	Commit        string             `json:"commit,omitempty"`
	LastHeartbeat *string            `json:"last_heartbeat"`
	Reasons       []string           `json:"reasons,omitempty"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
}

// HostHealth é o estado da máquina.
type HostHealth struct {
	Kernel             string               `json:"kernel,omitempty"`
	Iface              string               `json:"iface,omitempty"`
	MTU                int                  `json:"mtu,omitempty"`
	Offloads           map[string]string    `json:"offloads,omitempty"`
	AggregatingOffload bool                 `json:"aggregating_offload"`
	Sysctls            map[string]string    `json:"sysctls,omitempty"`
	SyncookiesSent     int64                `json:"syncookies_sent"`
	ConntrackLoaded    bool                 `json:"conntrack_loaded"`
	NFTRulesetLines    int                  `json:"nft_ruleset_lines"`
	NTPSynchronized    bool                 `json:"ntp_synchronized"`
	TLSServer          *certs.TLSServerInfo `json:"tls_server,omitempty"`
	Certificates       []certJSON           `json:"certificates,omitempty"`
	Store              *DBHealth            `json:"store,omitempty"`
}

// DBHealth é o estado do banco.
type DBHealth struct {
	DBBytes     int64   `json:"db_bytes"`
	MaxBytes    int64   `json:"max_bytes"`
	Retention   string  `json:"retention"`
	Connections int64   `json:"connections"`
	Oldest      *string `json:"oldest"`
}

type seen struct {
	at      time.Time
	version string
	hb      event.Heartbeat
}

// Tracker guarda o último heartbeat de cada serviço.
type Tracker struct {
	expected  []string
	downAfter time.Duration
	mu        sync.Mutex
	last      map[string]seen
}

// NewTracker cria o rastreador para os serviços esperados.
func NewTracker(expected []string, downAfter time.Duration) *Tracker {
	return &Tracker{expected: expected, downAfter: downAfter, last: map[string]seen{}}
}

// Observe registra um heartbeat recebido.
func (t *Tracker) Observe(data []byte, now time.Time) error {
	env, err := event.Decode(data)
	if err != nil {
		return err
	}
	var hb event.Heartbeat
	if err := json.Unmarshal(env.Payload, &hb); err != nil {
		return err
	}
	t.mu.Lock()
	t.last[env.Service] = seen{at: now, version: env.ServiceVersion, hb: hb}
	t.mu.Unlock()
	return nil
}

// Services devolve o estado de cada serviço esperado (e de qualquer outro que mandou heartbeat), se todos
// estão no ar e se as versões batem com storeVersion.
func (t *Tracker) Services(now time.Time, storeVersion string) (map[string]ServiceHealth, bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := append([]string(nil), t.expected...)
	for n := range t.last {
		if !contains(names, n) {
			names = append(names, n)
		}
	}
	out := make(map[string]ServiceHealth, len(names))
	allUp, match := true, true
	for _, n := range names {
		s, ok := t.last[n]
		if !ok {
			out[n] = ServiceHealth{Status: event.StatusDown, Reasons: []string{"no heartbeat"}}
			allUp = false
			continue
		}
		at := event.FormatTime(s.at)
		h := ServiceHealth{
			Status: s.hb.Status, Version: s.version, Commit: s.hb.Commit, LastHeartbeat: &at,
			Reasons: s.hb.Reasons, Metrics: s.hb.Metrics,
		}
		if now.Sub(s.at) > t.downAfter {
			h.Status = event.StatusDown
			h.Reasons = append([]string{"heartbeat older than " + t.downAfter.String()}, h.Reasons...)
		}
		if h.Status == event.StatusDown {
			allUp = false
		}
		if s.version != storeVersion {
			match = false
			// Versão desencontrada é motivo visível de degradação (ADR 0002, "alerta no health").
			h.Reasons = append(h.Reasons[:len(h.Reasons):len(h.Reasons)], "version "+s.version+" differs from store "+storeVersion)
			if h.Status == event.StatusOK {
				h.Status = event.StatusDegraded
			}
		}
		out[n] = h
	}
	return out, allUp, match
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// HostPaths são os arquivos lidos para o estado do host (substituíveis nos testes).
type HostPaths struct {
	NetStatus   string // escrito pela unit finger-sniffer-net (deploy/net)
	SysctlFile  string // deploy/sysctl/90-finger-sniffer.conf
	ProcSys     string // /proc/sys
	ProcNetstat string // /proc/net/netstat
	TimesyncOK  string // /run/systemd/timesync/synchronized
	ProcModules string // /proc/modules ("" = não confere ao vivo)
}

// DefaultHostPaths são os caminhos reais na vps602.
var DefaultHostPaths = HostPaths{
	NetStatus:   "/run/finger-sniffer/net-status.json",
	SysctlFile:  "/finger-sniffer/deploy/sysctl/90-finger-sniffer.conf",
	ProcSys:     "/proc/sys",
	ProcNetstat: "/proc/net/netstat",
	TimesyncOK:  "/run/systemd/timesync/synchronized",
	ProcModules: "/proc/modules",
}

// netStatus é o JSON gravado por deploy/net/finger-sniffer-net.sh.
type netStatus struct {
	Iface              string            `json:"iface"`
	MTU                int               `json:"mtu"`
	Kernel             string            `json:"kernel"`
	Offloads           map[string]string `json:"offloads"`
	AggregatingOffload bool              `json:"aggregating_offload"`
	NFTRulesetLines    int               `json:"nft_ruleset_lines"`
	ConntrackLoaded    bool              `json:"conntrack_loaded"`
}

// ReadHost monta o HostHealth; arquivos ausentes deixam os campos vazios e entram em reasons.
func ReadHost(p HostPaths) (*HostHealth, []string) {
	h := &HostHealth{}
	var reasons []string

	if raw, err := os.ReadFile(p.NetStatus); err != nil {
		reasons = append(reasons, "net status unavailable")
	} else {
		var ns netStatus
		if err := json.Unmarshal(raw, &ns); err != nil {
			reasons = append(reasons, "net status invalid")
		} else {
			h.Iface, h.MTU, h.Kernel, h.Offloads = ns.Iface, ns.MTU, ns.Kernel, ns.Offloads
			h.AggregatingOffload, h.NFTRulesetLines, h.ConntrackLoaded = ns.AggregatingOffload, ns.NFTRulesetLines, ns.ConntrackLoaded
			if ns.AggregatingOffload {
				reasons = append(reasons, "aggregating offload on")
			}
			if ns.ConntrackLoaded {
				reasons = append(reasons, "conntrack loaded")
			}
			if ns.NFTRulesetLines > 0 {
				reasons = append(reasons, "nftables has rules")
			}
		}
	}

	var sysReasons []string
	h.Sysctls, sysReasons = readSysctls(p.SysctlFile, p.ProcSys)
	reasons = append(reasons, sysReasons...)
	// conntrack ao vivo (/proc/modules): o net-status é foto do boot e não vê um módulo carregado depois.
	if !h.ConntrackLoaded && p.ProcModules != "" && moduleLoaded(p.ProcModules, "nf_conntrack") {
		h.ConntrackLoaded = true
		reasons = append(reasons, "conntrack loaded")
	}
	h.SyncookiesSent = readNetstat(p.ProcNetstat, "TcpExt", "SyncookiesSent")
	if _, err := os.Stat(p.TimesyncOK); err == nil {
		h.NTPSynchronized = true
	} else {
		reasons = append(reasons, "ntp not synchronized")
	}
	return h, reasons
}

// readSysctls lê as chaves do arquivo de sysctl do projeto e devolve os valores efetivos do kernel e um motivo
// de degradação para cada valor efetivo diferente do arquivo (spec 016 CA-2). Chave que o kernel não expõe fica
// de fora, sem motivo.
func readSysctls(file, procSys string) (map[string]string, []string) {
	f, err := os.Open(file) //nolint:gosec // caminho da configuração
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	var reasons []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, want, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		raw, err := os.ReadFile(filepath.Join(procSys, strings.ReplaceAll(key, ".", "/"))) //nolint:gosec // /proc/sys
		if err != nil {
			continue
		}
		got := strings.Join(strings.Fields(string(raw)), " ")
		out[key] = got
		if want = strings.Join(strings.Fields(want), " "); got != want {
			reasons = append(reasons, "sysctl "+key+" is "+got+", want "+want)
		}
	}
	return out, reasons
}

// moduleLoaded informa se o módulo aparece em /proc/modules.
func moduleLoaded(path, name string) bool {
	raw, err := os.ReadFile(path) //nolint:gosec // /proc
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if mod, _, _ := strings.Cut(line, " "); mod == name {
			return true
		}
	}
	return false
}

// readNetstat lê um contador de /proc/net/netstat (linhas pareadas cabeçalho/valores por prefixo).
func readNetstat(path, prefix, name string) int64 {
	raw, err := os.ReadFile(path) //nolint:gosec // /proc
	if err != nil {
		return 0
	}
	lines := strings.Split(string(raw), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], prefix+":") || !strings.HasPrefix(lines[i+1], prefix+":") {
			continue
		}
		keys, vals := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for j := 1; j < len(keys) && j < len(vals); j++ {
			if keys[j] == name {
				n, _ := strconv.ParseInt(vals[j], 10, 64)
				return n
			}
		}
		i++
	}
	return 0
}
