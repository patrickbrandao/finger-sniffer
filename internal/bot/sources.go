package bot

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// Adaptadores das listas (task 278) para as interfaces das regras (task 276, rules.Sources).

// robotOperator liga o robô de uma lista good_bot do catálogo (lists.Source.Robot) ao operador das regras.
var robotOperator = map[string]string{
	"googlebot":     rules.OperatorGoogle,
	"bingbot":       rules.OperatorBing,
	"applebot":      rules.OperatorApple,
	"gptbot":        rules.OperatorOpenAI,
	"oai-searchbot": rules.OperatorOpenAI,
	"chatgpt-user":  rules.OperatorOpenAI,
	"duckduckbot":   rules.OperatorDuckDuckGo,
	"duckassistbot": rules.OperatorDuckDuckGo,
}

// operatorDNSRobot é o robô cujos sufixos de DNS reverso verificam o operador (só os operadores provados por DNS;
// OpenAI e DuckDuckGo são provados pela lista, ADR 0057 item 1).
var operatorDNSRobot = map[string]string{
	rules.OperatorGoogle: "googlebot",
	rules.OperatorBing:   "bingbot",
	rules.OperatorApple:  "applebot",
}

// newRuleSources monta as fontes das regras a partir do gerenciador das listas (nil: só sem listas).
func newRuleSources(m *lists.Manager, ja4dbEnabled bool, bg *bgVerifier) rules.Sources {
	if m == nil {
		return rules.Sources{}
	}
	src := rules.Sources{
		Known:    newKnownSource(m.Known()),
		IPs:      ipSource{m},
		Verifier: verifierSource{v: m.Verifier(), bg: bg},
	}
	if ja4dbEnabled {
		src.JA4DB = ja4dbSource{m}
	}
	return src
}

// knownSource é a base própria indexada pelos tipos de impressão das regras.
type knownSource struct {
	k        *lists.KnownClients
	byKind   map[rules.FPKind]map[string][]string // valor → famílias (em ordem, sem repetição)
	measured map[string]map[rules.FPKind]bool
}

func newKnownSource(k *lists.KnownClients) *knownSource {
	s := &knownSource{k: k, byKind: map[rules.FPKind]map[string][]string{}, measured: map[string]map[rules.FPKind]bool{}}
	add := func(kind rules.FPKind, value *string, client string) {
		if value == nil || *value == "" {
			return
		}
		m := s.byKind[kind]
		if m == nil {
			m = map[string][]string{}
			s.byKind[kind] = m
		}
		if !slices.Contains(m[*value], client) {
			m[*value] = append(m[*value], client)
			slices.Sort(m[*value])
		}
		if s.measured[client] == nil {
			s.measured[client] = map[rules.FPKind]bool{}
		}
		s.measured[client][kind] = true
	}
	for i := range k.Measured {
		m := &k.Measured[i]
		add(rules.KindJA4, &m.JA4, m.Client)
		add(rules.KindAkamai, m.Akamai, m.Client)
		add(rules.KindJA4HAB, m.JA4HAB, m.Client)
		add(rules.KindJA4T, m.JA4T, m.Client)
	}
	return s
}

// Families implementa rules.KnownClients (a fatia devolvida é somente leitura).
func (s *knownSource) Families(kind rules.FPKind, value string) []string {
	if value == "" {
		return nil
	}
	return s.byKind[kind][value]
}

// Measured implementa rules.KnownClients.
func (s *knownSource) Measured(family string, kind rules.FPKind) bool {
	return s.measured[family][kind]
}

// Coherent implementa rules.KnownClients com o casamento da base (lists.KnownClients.Coherent).
func (s *knownSource) Coherent(ja4, akamai, ja4t string) []string {
	if ja4 == "" {
		return nil
	}
	var out []string
	for _, client := range s.byKind[rules.KindJA4][ja4] {
		if _, ok := s.k.Coherent(client, lists.Observed{JA4: ja4, Akamai: akamai, JA4T: ja4t}); ok {
			out = append(out, client)
		}
	}
	return out
}

// label devolve o rótulo da base própria para uma impressão da API de fingerprints (famílias por vírgula).
func (s *knownSource) label(kind, value string) *string {
	var fams []string
	switch kind {
	case "ja4":
		fams = s.Families(rules.KindJA4, value)
	case "akamai":
		fams = s.Families(rules.KindAkamai, value)
	case "ja4t":
		fams = s.Families(rules.KindJA4T, value)
	case "ja4h":
		// a base guarda só as partes a e b do JA4H
		if p := strings.SplitN(value, "_", 3); len(p) >= 2 {
			fams = s.Families(rules.KindJA4HAB, p[0]+"_"+p[1])
		}
	}
	if len(fams) == 0 {
		return nil
	}
	return ptr(strings.Join(fams, ","))
}

// ja4dbSource é a ja4db (só com FS_BOT_JA4DB_ENABLE=true, ADR 0056 item 1).
type ja4dbSource struct{ m *lists.Manager }

// Label implementa rules.JA4DB: rótulo de navegador primeiro (o JA4 de navegador não vira `ja4db_match` por um
// registro de biblioteca que o imita), depois biblioteca e aplicação.
func (s ja4dbSource) Label(ja4 string) (rules.JA4DBLabel, bool) {
	ls := s.m.JA4DB(ja4)
	if len(ls) == 0 {
		return rules.JA4DBLabel{}, false
	}
	pick := ls[0]
	for _, l := range ls {
		if l.Kind == "browser" {
			pick = l
			break
		}
	}
	switch pick.Kind {
	case "browser":
		return rules.JA4DBLabel{Name: pick.Application, Kind: rules.JA4DBBrowser}, true
	case "library":
		return rules.JA4DBLabel{Name: pick.Library, Kind: rules.JA4DBLibrary}, true
	}
	return rules.JA4DBLabel{Name: pick.Application, Kind: rules.JA4DBTool}, true
}

// labelText é o ja4db_label da API de fingerprints.
func (s ja4dbSource) labelText(ja4 string) *string {
	l, ok := s.Label(ja4)
	if !ok {
		return nil
	}
	return ptr(l.Kind + " " + l.Name)
}

// ipSource são as listas de IP.
type ipSource struct{ m *lists.Manager }

// Cloud implementa rules.IPLists: a primeira lista de nuvem que contém o IP.
func (s ipSource) Cloud(ip netip.Addr) (string, bool) {
	for _, x := range s.m.Lookup(ip) {
		if x.Kind == lists.KindCloud {
			return x.List, true
		}
	}
	return "", false
}

// Crawler implementa rules.IPLists: o operador da primeira lista de robô que contém o IP (inclusive OpenAI e
// DuckDuckGo, provados só pela lista, ADR 0057 item 1).
func (s ipSource) Crawler(ip netip.Addr) (string, bool) {
	for _, x := range s.m.Lookup(ip) {
		if op := robotOperator[x.Robot]; x.Kind == lists.KindGoodBot && op != "" {
			return op, true
		}
	}
	return "", false
}

// verifierSource é a verificação por DNS sem bloquear: devolve o cache e, sem ele, pede a verificação em segundo
// plano e responde desconhecido (spec 020 RF-05: a verificação nunca segura o forwardAuth).
type verifierSource struct {
	v  *lists.Verifier
	bg *bgVerifier
}

// Verified implementa rules.CrawlerVerifier.
func (s verifierSource) Verified(ip netip.Addr, operator string) rules.Verification {
	robot := operatorDNSRobot[operator]
	if robot == "" || s.v == nil {
		return rules.VerifyUnknown
	}
	res, _, ok := s.v.Cached(robot, ip)
	if !ok {
		s.bg.start(s.v, robot, ip)
		return rules.VerifyUnknown
	}
	switch res {
	case lists.VerifyPassed:
		return rules.VerifyPassed
	case lists.VerifyFailed:
		return rules.VerifyFailed
	}
	return rules.VerifyUnknown
}

// maxBackgroundVerify é quantas verificações por DNS rodam ao mesmo tempo; acima, o pedido é ignorado (a próxima
// requisição do mesmo IP pede de novo).
const maxBackgroundVerify = 8

// bgVerifier roda as verificações de robô em segundo plano, uma por robô + IP de cada vez.
type bgVerifier struct {
	mu       sync.Mutex
	inflight map[string]bool
	sem      chan struct{}
	wg       sync.WaitGroup
}

func newBGVerifier() *bgVerifier {
	return &bgVerifier{inflight: map[string]bool{}, sem: make(chan struct{}, maxBackgroundVerify)}
}

func (b *bgVerifier) start(v *lists.Verifier, robot string, ip netip.Addr) {
	if b == nil {
		return
	}
	key := robot + "|" + ip.Unmap().String()
	b.mu.Lock()
	if b.inflight[key] {
		b.mu.Unlock()
		return
	}
	select {
	case b.sem <- struct{}{}:
	default:
		b.mu.Unlock()
		return
	}
	b.inflight[key] = true
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		v.Verify(context.Background(), robot, ip) // prazo próprio de 3 s (lists.verifyTimeout)
		b.mu.Lock()
		delete(b.inflight, key)
		<-b.sem
		b.mu.Unlock()
	}()
}

// Wait espera as verificações em andamento (desligamento e testes).
func (b *bgVerifier) Wait() { b.wg.Wait() }
