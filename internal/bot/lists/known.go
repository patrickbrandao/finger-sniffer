// Package lists carrega as listas de referência do bot (spec 018 RF-07, ADRs 0050 e 0056): a base própria
// embutida (known_clients.json), a ja4db da FoxIO (desligada por padrão) e as listas de IP de robôs e nuvens,
// com atualização diária, validação, árvore de prefixos e verificação de robô por DNS.
package lists

import (
	"bytes"
	"crypto/sha256"
	_ "embed" // base própria embutida no binário
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// KnownClientsName é o nome da base própria no health, nas métricas e no lists_version.
const KnownClientsName = "known_clients"

//go:embed known_clients.json
var knownClientsJSON []byte

// KnownClient é uma medida da base própria (formato da spec 018, contrato com o tester).
type KnownClient struct {
	Client        string   `json:"client"`
	ClientVersion string   `json:"client_version"`
	OS            string   `json:"os"`
	Proto         string   `json:"proto"`
	JA4           string   `json:"ja4"`
	JA4R          string   `json:"ja4_r"`
	Akamai        *string  `json:"akamai"`
	JA4HAB        *string  `json:"ja4h_ab"`
	JA4T          *string  `json:"ja4t"`
	P0fOS         *string  `json:"p0f_os"`
	TTLInitial    *int     `json:"ttl_initial"`
	ALPN          []string `json:"alpn"`
	MeasuredAt    string   `json:"measured_at"`
	Commit        string   `json:"commit"`
}

// Family é o conjunto das impressões medidas de uma família de cliente (o campo `client`).
type Family struct {
	JA4    map[string]bool
	Akamai map[string]bool
	JA4HAB map[string]bool
	JA4T   map[string]bool
}

// KnownClients é a base própria carregada e indexada.
type KnownClients struct {
	Version  string // SHA-256 (hex) do arquivo
	Measured []KnownClient
	families map[string]*Family
	byJA4    map[string][]int
}

var (
	ja4Pattern    = regexp.MustCompile(`^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	ja4hABPattern = regexp.MustCompile(`^[a-z]{2}[0-9]{2}[cn][rn][0-9]{2}[0-9a-z]{4}_[0-9a-f]{12}$`)
	ja4tPattern   = regexp.MustCompile(`^[0-9]+_[0-9-]+_[0-9]+_[0-9]+$`)
	protos        = map[string]bool{"h1": true, "h2": true, "h3": true}
)

// LoadKnownClients valida e indexa o arquivo embutido.
func LoadKnownClients() (*KnownClients, error) { return ParseKnownClients(knownClientsJSON) }

// ParseKnownClients valida e indexa uma base no formato da spec 018.
func ParseKnownClients(b []byte) (*KnownClients, error) {
	var doc struct {
		Version  int           `json:"version"`
		Measured []KnownClient `json:"measured"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("lists: known_clients: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("lists: known_clients: version %d unsupported", doc.Version)
	}
	if len(doc.Measured) == 0 {
		return nil, errors.New("lists: known_clients: no measurements")
	}
	sum := sha256.Sum256(b)
	k := &KnownClients{
		Version: hex.EncodeToString(sum[:]), Measured: doc.Measured,
		families: map[string]*Family{}, byJA4: map[string][]int{},
	}
	for i, m := range doc.Measured {
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("lists: known_clients[%d]: %w", i, err)
		}
		f := k.families[m.Client]
		if f == nil {
			f = &Family{JA4: map[string]bool{}, Akamai: map[string]bool{}, JA4HAB: map[string]bool{}, JA4T: map[string]bool{}}
			k.families[m.Client] = f
		}
		f.JA4[m.JA4] = true
		if m.Akamai != nil {
			f.Akamai[*m.Akamai] = true
		}
		if m.JA4HAB != nil {
			f.JA4HAB[*m.JA4HAB] = true
		}
		if m.JA4T != nil {
			f.JA4T[*m.JA4T] = true
		}
		k.byJA4[m.JA4] = append(k.byJA4[m.JA4], i)
	}
	return k, nil
}

func (m KnownClient) validate() error {
	switch {
	case m.Client == "":
		return errors.New("client empty")
	case !protos[m.Proto]:
		return fmt.Errorf("proto %q invalid", m.Proto)
	case !ja4Pattern.MatchString(m.JA4):
		return fmt.Errorf("ja4 %q invalid", m.JA4)
	case m.JA4HAB != nil && !ja4hABPattern.MatchString(*m.JA4HAB):
		return fmt.Errorf("ja4h_ab %q invalid", *m.JA4HAB)
	case m.JA4T != nil && !ja4tPattern.MatchString(*m.JA4T):
		return fmt.Errorf("ja4t %q invalid", *m.JA4T)
	case m.Proto == "h2" && m.Akamai == nil:
		return errors.New("h2 without akamai")
	case m.Proto != "h2" && m.Akamai != nil:
		return errors.New("akamai outside h2")
	case m.TTLInitial != nil && (*m.TTLInitial <= 0 || *m.TTLInitial > 255):
		return fmt.Errorf("ttl_initial %d invalid", *m.TTLInitial)
	}
	if _, err := time.Parse(time.RFC3339, m.MeasuredAt); err != nil {
		return fmt.Errorf("measured_at %q invalid", m.MeasuredAt)
	}
	return nil
}

// Entries é o número de medidas.
func (k *KnownClients) Entries() int { return len(k.Measured) }

// Families lista as famílias medidas, em ordem.
func (k *KnownClients) Families() []string {
	out := make([]string, 0, len(k.families))
	for f := range k.families {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// Family devolve os conjuntos de impressões de uma família (nil se não medida).
func (k *KnownClients) Family(client string) *Family { return k.families[client] }

// ByJA4 devolve as medidas com aquele JA4.
func (k *KnownClients) ByJA4(ja4 string) []KnownClient {
	idx := k.byJA4[ja4]
	out := make([]KnownClient, len(idx))
	for i, j := range idx {
		out[i] = k.Measured[j]
	}
	return out
}

// Observed são as impressões de uma requisição para o casamento com a base (vazio = ausente).
type Observed struct {
	JA4, Akamai, JA4HAB, JA4T string
}

// Coherent devolve a primeira medida da família cujas impressões presentes batem todas com as observadas (JA4
// obrigatório; Akamai, JA4H a+b e JA4T só quando os dois lados têm o valor). O JA4T compara sem o campo do MSS
// (janela, opções e escala; rules v1.2, ADR 0058 item 4): o grampo de MSS no caminho não muda o cliente, e o MSS
// reduzido é do sinal tunnel_mss. Sem medida coerente: ok=false.
func (k *KnownClients) Coherent(client string, o Observed) (KnownClient, bool) {
	for _, i := range k.byJA4[o.JA4] {
		m := k.Measured[i]
		if m.Client != client {
			continue
		}
		if o.Akamai != "" && m.Akamai != nil && *m.Akamai != o.Akamai {
			continue
		}
		if o.JA4HAB != "" && m.JA4HAB != nil && *m.JA4HAB != o.JA4HAB {
			continue
		}
		if o.JA4T != "" && m.JA4T != nil && JA4TWithoutMSS(*m.JA4T) != JA4TWithoutMSS(o.JA4T) {
			continue
		}
		return m, true
	}
	return KnownClient{}, false
}

// JA4TWithoutMSS tira o campo do MSS (o terceiro) do JA4T `janela_opções_mss_escala`, deixando
// `janela_opções_escala`. Valor fora desse formato volta inteiro (só casa consigo mesmo).
func JA4TWithoutMSS(ja4t string) string {
	p := strings.Split(ja4t, "_")
	if len(p) != 4 {
		return ja4t
	}
	return p[0] + "_" + p[1] + "_" + p[3]
}
