package lists

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
)

// parsed é o conteúdo de uma lista depois do parser.
type parsed struct {
	prefixes []netip.Prefix          // listas de IP, sem repetição
	ja4      map[string][]JA4DBLabel // ja4db
	entries  int
}

// errFormat marca conteúdo fora do formato esperado.
var errFormat = errors.New("format")

// parse escolhe o parser do formato.
func parse(format string, b []byte) (parsed, error) {
	switch format {
	case FormatGoogle:
		return parseGoogle(b)
	case FormatAWS:
		return parseAWS(b)
	case FormatAzure:
		return parseAzure(b)
	case FormatOracle:
		return parseOracle(b)
	case FormatCSV:
		return parseCSV(b)
	case FormatCloudflare:
		return parseCloudflare(b)
	case FormatJA4DB:
		return parseJA4DB(b)
	}
	return parsed{}, fmt.Errorf("%w: unknown format %q", errFormat, format)
}

// prefixSet acumula prefixos sem repetição.
type prefixSet struct {
	seen map[netip.Prefix]bool
	out  []netip.Prefix
}

func (s *prefixSet) add(raw string) error {
	raw = strings.TrimSpace(raw)
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		// IP sem comprimento vale como host único.
		a, aerr := netip.ParseAddr(raw)
		if aerr != nil {
			return fmt.Errorf("%w: prefix %q", errFormat, raw)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = normalizePrefix(p)
	if !p.IsValid() {
		return fmt.Errorf("%w: prefix %q", errFormat, raw)
	}
	if s.seen == nil {
		s.seen = map[netip.Prefix]bool{}
	}
	if !s.seen[p] {
		s.seen[p] = true
		s.out = append(s.out, p)
	}
	return nil
}

func (s *prefixSet) result() parsed { return parsed{prefixes: s.out, entries: len(s.out)} }

func decodeJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", errFormat, err)
	}
	return nil
}

func parseGoogle(b []byte) (parsed, error) {
	var doc struct {
		Prefixes *[]struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := decodeJSON(b, &doc); err != nil {
		return parsed{}, err
	}
	if doc.Prefixes == nil {
		return parsed{}, fmt.Errorf("%w: no prefixes", errFormat)
	}
	var s prefixSet
	for _, p := range *doc.Prefixes {
		raw := p.IPv4
		if raw == "" {
			raw = p.IPv6
		}
		if err := s.add(raw); err != nil {
			return parsed{}, err
		}
	}
	return s.result(), nil
}

func parseAWS(b []byte) (parsed, error) {
	var doc struct {
		Prefixes *[]struct {
			IP string `json:"ip_prefix"`
		} `json:"prefixes"`
		IPv6 []struct {
			IP string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := decodeJSON(b, &doc); err != nil {
		return parsed{}, err
	}
	if doc.Prefixes == nil {
		return parsed{}, fmt.Errorf("%w: no prefixes", errFormat)
	}
	var s prefixSet
	for _, p := range *doc.Prefixes {
		if err := s.add(p.IP); err != nil {
			return parsed{}, err
		}
	}
	for _, p := range doc.IPv6 {
		if err := s.add(p.IP); err != nil {
			return parsed{}, err
		}
	}
	return s.result(), nil
}

// azureTag é a etiqueta de serviço que reúne todas as faixas públicas da Azure.
const azureTag = "AzureCloud"

func parseAzure(b []byte) (parsed, error) {
	var doc struct {
		Values *[]struct {
			Name       string `json:"name"`
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := decodeJSON(b, &doc); err != nil {
		return parsed{}, err
	}
	if doc.Values == nil {
		return parsed{}, fmt.Errorf("%w: no values", errFormat)
	}
	// Só AzureCloud (todas as faixas públicas); sem ela, a união de todas as etiquetas.
	hasCloud := false
	for _, v := range *doc.Values {
		if v.Name == azureTag {
			hasCloud = true
		}
	}
	var s prefixSet
	for _, v := range *doc.Values {
		if hasCloud && v.Name != azureTag {
			continue
		}
		for _, p := range v.Properties.AddressPrefixes {
			if err := s.add(p); err != nil {
				return parsed{}, err
			}
		}
	}
	return s.result(), nil
}

// azureLinkPattern acha o JSON semanal na página de download da Azure (o nome muda toda semana).
var azureLinkPattern = regexp.MustCompile(`https://download\.microsoft\.com/download/[A-Za-z0-9/_.-]+/ServiceTags_Public_[0-9]{8}\.json`)

// azureLink devolve o link do JSON quando o corpo é a página HTML de download.
func azureLink(b []byte) (string, bool) {
	t := bytes.TrimSpace(b)
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		return "", false
	}
	m := azureLinkPattern.Find(b)
	return string(m), m != nil
}

func parseOracle(b []byte) (parsed, error) {
	var doc struct {
		Regions *[]struct {
			CIDRs []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := decodeJSON(b, &doc); err != nil {
		return parsed{}, err
	}
	if doc.Regions == nil {
		return parsed{}, fmt.Errorf("%w: no regions", errFormat)
	}
	var s prefixSet
	for _, r := range *doc.Regions {
		for _, c := range r.CIDRs {
			if err := s.add(c.CIDR); err != nil {
				return parsed{}, err
			}
		}
	}
	return s.result(), nil
}

func parseCSV(b []byte) (parsed, error) {
	var s prefixSet
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := csv.NewReader(strings.NewReader(line))
		rec, err := r.Read()
		if err != nil && !errors.Is(err, io.EOF) {
			return parsed{}, fmt.Errorf("%w: csv: %v", errFormat, err)
		}
		if len(rec) == 0 {
			continue
		}
		if err := s.add(rec[0]); err != nil {
			return parsed{}, err
		}
	}
	if err := sc.Err(); err != nil {
		return parsed{}, fmt.Errorf("%w: %v", errFormat, err)
	}
	return s.result(), nil
}

func parseCloudflare(b []byte) (parsed, error) {
	var doc struct {
		Success bool `json:"success"`
		Result  *struct {
			IPv4 []string `json:"ipv4_cidrs"`
			IPv6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := decodeJSON(b, &doc); err != nil {
		return parsed{}, err
	}
	if !doc.Success || doc.Result == nil {
		return parsed{}, fmt.Errorf("%w: success=false", errFormat)
	}
	var s prefixSet
	for _, p := range append(doc.Result.IPv4, doc.Result.IPv6...) {
		if err := s.add(p); err != nil {
			return parsed{}, err
		}
	}
	return s.result(), nil
}

// JA4DBLabel é o rótulo de um JA4 na ja4db (ADR 0050 item 2).
type JA4DBLabel struct {
	Kind        string `json:"kind"` // application | library | browser
	Application string `json:"application,omitempty"`
	Library     string `json:"library,omitempty"`
	OS          string `json:"os,omitempty"`
	Verified    bool   `json:"verified"`
}

// maxLabelsPerJA4 limita os rótulos guardados por JA4 (o mesmo JA4 aparece em muitos registros).
const maxLabelsPerJA4 = 4

// browserWords marcam um registro da ja4db como navegador.
var browserWords = []string{"browser", "chrome", "chromium", "firefox", "safari", "edge", "opera", "brave"}

func parseJA4DB(b []byte) (parsed, error) {
	var recs []struct {
		Application *string `json:"application"`
		Library     *string `json:"library"`
		OS          *string `json:"os"`
		Verified    bool    `json:"verified"`
		JA4         *string `json:"ja4_fingerprint"`
	}
	if err := decodeJSON(b, &recs); err != nil {
		return parsed{}, err
	}
	out := parsed{ja4: map[string][]JA4DBLabel{}}
	for _, r := range recs {
		if r.JA4 == nil || !ja4Pattern.MatchString(*r.JA4) {
			continue
		}
		l := JA4DBLabel{Application: deref(r.Application), Library: deref(r.Library), OS: deref(r.OS), Verified: r.Verified}
		if l.Application == "" && l.Library == "" {
			continue
		}
		l.Kind = "application"
		app := strings.ToLower(l.Application)
		switch {
		case l.Application == "":
			l.Kind = "library"
		case containsAny(app, browserWords):
			l.Kind = "browser"
		}
		out.entries++
		cur := out.ja4[*r.JA4]
		if len(cur) < maxLabelsPerJA4 && !containsLabel(cur, l) {
			out.ja4[*r.JA4] = append(cur, l)
		}
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func containsLabel(ls []JA4DBLabel, l JA4DBLabel) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}
