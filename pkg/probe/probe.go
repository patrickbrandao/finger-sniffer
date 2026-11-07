// Package probe extrai o probe ID que o cliente usa para achar as suas conexões (spec 001 "Correlação").
//
// Lugares onde o ID aparece:
//   - rótulo mais à esquerda do host em <id>.dns-monitor.tmsoft.com.br (SNI, Host, :authority, CONNECT,
//     qname DNS), com rótulos de controle opcionais à direita (spec 007 RF-03);
//   - caminho /p/<id>/... (inclusive em alvos absolute-form);
//   - primeira linha "PROBE <id>[ mode=...][ n=N]\r\n" das portas cruas (spec 006 RF-04).
package probe

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Limites do probe ID: [a-z0-9]{8,32}.
const (
	MinLen = 8
	MaxLen = 32
)

// DefaultZones são as zonas em que o rótulo mais à esquerda é tratado como probe (ADR 0008).
var DefaultZones = []string{"dns-monitor.tmsoft.com.br", "vps602.tmsoft.com.br"}

// Rótulos de controle do DNS (spec 007 RF-03).
const (
	ControlNoH3   = "noh3"
	ControlV4     = "v4"
	ControlV6     = "v6"
	ControlNoData = "nodata"
	ControlNX     = "nx"
)

var controlLabels = map[string]bool{
	ControlNoH3: true, ControlV4: true, ControlV6: true, ControlNoData: true, ControlNX: true,
}

// Valid informa se s é um probe ID válido (já em minúsculas).
func Valid(s string) bool {
	if len(s) < MinLen || len(s) > MaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// HostInfo é o resultado da análise de um nome dentro de uma zona dos probes.
type HostInfo struct {
	// ID é o probe ID em minúsculas ("" se o rótulo mais à esquerda não é um probe válido).
	ID string
	// Zone é a zona reconhecida (em minúsculas).
	Zone string
	// Controls são os rótulos de controle conhecidos, na ordem em que aparecem.
	Controls []string
	// Unknown são os demais rótulos entre o probe e a zona (registrados, mas sem efeito).
	Unknown []string
}

// Has informa se o controle c está presente.
func (h HostInfo) Has(c string) bool {
	for _, x := range h.Controls {
		if x == c {
			return true
		}
	}
	return false
}

// Extractor reconhece probes em nomes de host de um conjunto de zonas.
type Extractor struct {
	zones []string
}

// NewExtractor cria um extrator para as zonas dadas (padrão: DefaultZones).
func NewExtractor(zones ...string) *Extractor {
	if len(zones) == 0 {
		zones = DefaultZones
	}
	e := &Extractor{}
	for _, z := range zones {
		z = strings.Trim(strings.ToLower(z), ".")
		if z != "" {
			e.zones = append(e.zones, z)
		}
	}
	return e
}

// Host analisa um nome de host (SNI, Host, :authority, alvo de CONNECT ou qname DNS). Aceita porta, ponto
// final e qualquer caixa. ok é false se o nome não pertence a nenhuma zona; dentro da zona, HostInfo.ID
// pode vir vazio (apex, ou rótulo mais à esquerda que não é probe).
func (e *Extractor) Host(host string) (HostInfo, bool) {
	name := stripPort(host)
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || net.ParseIP(name) != nil {
		return HostInfo{}, false
	}

	for _, zone := range e.zones {
		if name == zone {
			return HostInfo{Zone: zone}, true
		}
		if !strings.HasSuffix(name, "."+zone) {
			continue
		}
		labels := strings.Split(strings.TrimSuffix(name, "."+zone), ".")
		info := HostInfo{Zone: zone}
		rest := labels
		if Valid(labels[0]) && !controlLabels[labels[0]] {
			info.ID = labels[0]
			rest = labels[1:]
		}
		for _, l := range rest {
			if controlLabels[l] {
				info.Controls = append(info.Controls, l)
			} else {
				info.Unknown = append(info.Unknown, l)
			}
		}
		return info, true
	}
	return HostInfo{}, false
}

// stripPort remove ":porta" e colchetes de IPv6, quando presentes.
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// FromTarget extrai o probe do alvo de uma requisição HTTP: origin-form ("/p/<id>/..."), absolute-form
// ("http://host/p/<id>/...") ou só o caminho. A query é ignorada. O ID no caminho precisa estar em
// minúsculas (caminho diferencia caixa).
func FromTarget(target string) (string, bool) {
	path := target
	if !strings.HasPrefix(target, "/") {
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" {
			return "", false
		}
		path = u.EscapedPath()
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	rest, ok := strings.CutPrefix(path, "/p/")
	if !ok {
		return "", false
	}
	id, _, _ := strings.Cut(rest, "/")
	if !Valid(id) {
		return "", false
	}
	return id, true
}

// Modos das portas cruas (spec 006 RF-02).
const (
	ModeEcho   = "echo"
	ModeBanner = "banner"
	ModeSink   = "sink"
	ModeSource = "source"
)

// MaxLineLen é o tamanho máximo da linha PROBE, terminador incluído.
const MaxLineLen = 256

// Line é a primeira linha "PROBE" de uma porta crua.
type Line struct {
	ID string
	// Mode é o modo pedido ("" = manter o da porta).
	Mode string
	// N é o número de bytes do modo source (0 = padrão do serviço).
	N int64
	// Terminator é "crlf" ou "lf".
	Terminator string
}

// Erros de ParseLine.
var (
	ErrNotProbeLine = errors.New("probe: not a PROBE line")
	ErrIncomplete   = errors.New("probe: line without terminator")
	ErrTooLong      = errors.New("probe: line too long")
)

// ParseLine interpreta uma linha completa "PROBE <id>[ mode=<modo>][ n=<N>]" terminada em CRLF ou LF.
func ParseLine(line []byte) (Line, error) {
	if len(line) > MaxLineLen {
		return Line{}, ErrTooLong
	}
	s := string(line)
	if !strings.HasPrefix(s, "PROBE ") {
		return Line{}, ErrNotProbeLine
	}
	var res Line
	switch {
	case strings.HasSuffix(s, "\r\n"):
		res.Terminator, s = "crlf", strings.TrimSuffix(s, "\r\n")
	case strings.HasSuffix(s, "\n"):
		res.Terminator, s = "lf", strings.TrimSuffix(s, "\n")
	default:
		return Line{}, ErrIncomplete
	}

	fields := strings.Split(strings.TrimPrefix(s, "PROBE "), " ")
	if !Valid(fields[0]) {
		return Line{}, fmt.Errorf("probe: invalid id %q", fields[0])
	}
	res.ID = fields[0]

	for _, f := range fields[1:] {
		key, val, ok := strings.Cut(f, "=")
		if !ok {
			return Line{}, fmt.Errorf("probe: invalid option %q", f)
		}
		switch key {
		case "mode":
			switch val {
			case ModeEcho, ModeBanner, ModeSink, ModeSource:
				res.Mode = val
			default:
				return Line{}, fmt.Errorf("probe: invalid mode %q", val)
			}
		case "n":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n <= 0 {
				return Line{}, fmt.Errorf("probe: invalid n %q", val)
			}
			res.N = n
		default:
			return Line{}, fmt.Errorf("probe: unknown option %q", key)
		}
	}
	return res, nil
}
