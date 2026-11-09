package ja4plus

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// JA4HField é um campo de cabeçalho da requisição, na ordem e na caixa recebidas.
type JA4HField struct {
	Name  string
	Value string
}

// JA4HInput é a entrada genérica do JA4H, comum a HTTP/1.x e HTTP/2 (e HTTP/3).
type JA4HInput struct {
	// Method é o método como veio (ex.: GET).
	Method string
	// Version é a versão: "HTTP/1.0", "HTTP/1.1", "HTTP/2" ou "HTTP/3".
	Version string
	// Fields são todos os campos na ordem; pseudo-cabeçalhos (`:method`…) são ignorados.
	Fields []JA4HField
}

// JA4HResult traz as quatro formas do JA4H, com os nomes da saída da ferramenta `ja4`: ja4h (cookies
// ordenados, com hash), ja4h_r (ordenados, cru), ja4h_o (ordem original, com hash) e ja4h_ro.
type JA4HResult struct {
	JA4H   string
	JA4HR  string
	JA4HO  string
	JA4HRO string
}

type cookiePair struct {
	name     string
	value    string
	hasValue bool
}

// JA4H calcula o fingerprint HTTP do cliente. As regras reproduzem a ferramenta oficial `ja4` (Rust,
// rust/ja4/src/http.rs), que lê os campos do tshark:
//
//   - método: duas primeiras letras em minúsculas (co, de, ge, he, op, pa, po, pu, tr);
//   - versão: 10, 11, 20 ou 30 (00 para outras);
//   - `c`/`n` se há Cookie, `r`/`n` se há Referer;
//   - número de campos sem Cookie, Referer e pseudo-cabeçalhos, com dois dígitos e teto 99;
//   - idioma: do primeiro Accept-Language, até a primeira vírgula, sem `-`, minúsculas, 4 caracteres
//     completados com `0`;
//   - hash12 (SHA-256 truncado em 12 hex, `000000000000` se vazio) dos nomes dos campos na ordem, dos nomes
//     dos cookies e dos pares nome=valor dos cookies.
//
// Cookies: no HTTP/1.x vale só o primeiro campo Cookie, separado por "; " (o `http.cookie` do tshark); no
// HTTP/2 e no HTTP/3 cada campo `cookie` é um par (RFC 9113 seção 8.2.3). Nomes de campo são comparados
// sem caixa nos dois casos (a ferramenta compara o h2 com caixa, mas campo h2 em maiúsculas é malformado).
// Diferença deliberada: métodos fora da lista usam as duas primeiras letras, como a implementação Python,
// enquanto a Rust não emite JA4H.
func JA4H(in JA4HInput) JA4HResult {
	h2 := in.Version == "HTTP/2" || in.Version == "HTTP/2.0" || in.Version == "HTTP/3" || in.Version == "HTTP/3.0"
	var (
		names               []string
		hasCookie, hasRefer bool
		lang                string
		langSet, cookieSet  bool
		cookies             []cookiePair
	)
	for _, f := range in.Fields {
		if strings.HasPrefix(f.Name, ":") {
			continue
		}
		switch {
		case strings.EqualFold(f.Name, "cookie"):
			hasCookie = true
			if h2 {
				cookies = append(cookies, splitCookie(f.Value))
			} else if !cookieSet {
				cookieSet = true
				for _, c := range strings.Split(f.Value, "; ") {
					cookies = append(cookies, splitCookie(c))
				}
			}
			continue
		case strings.EqualFold(f.Name, "referer"):
			hasRefer = true
			continue
		case strings.EqualFold(f.Name, "accept-language") && !langSet:
			langSet = true
			lang = f.Value
		}
		names = append(names, f.Name)
	}

	var a strings.Builder
	a.WriteString(methodCode(in.Method))
	a.WriteString(versionCode(in.Version))
	a.WriteByte(marker(hasCookie, 'c'))
	a.WriteByte(marker(hasRefer, 'r'))
	n := min(len(names), 99)
	if n < 10 {
		a.WriteByte('0')
	}
	a.WriteString(strconv.Itoa(n))
	a.WriteString(primaryLanguage(lang))
	first := a.String()
	headers := strings.Join(names, ",")

	sorted := make([]cookiePair, len(cookies))
	copy(sorted, cookies)
	sort.SliceStable(sorted, func(i, j int) bool { return cookieLess(sorted[i], sorted[j]) })

	build := func(cs []cookiePair) (raw, hashed string) {
		cn, cv := joinCookies(cs)
		raw = first + "_" + headers + "_" + cn + "_" + cv
		hashed = first + "_" + hash12(headers) + "_" + hash12(cn) + "_" + hash12(cv)
		return raw, hashed
	}
	var r JA4HResult
	r.JA4HR, r.JA4H = build(sorted)
	r.JA4HRO, r.JA4HO = build(cookies)
	return r
}

func marker(set bool, c byte) byte {
	if set {
		return c
	}
	return 'n'
}

// splitCookie separa nome e valor no primeiro `=`; sem `=` o cookie não tem valor.
func splitCookie(s string) cookiePair {
	name, value, ok := strings.Cut(s, "=")
	return cookiePair{name: name, value: value, hasValue: ok}
}

// cookieLess ordena como o `sort_unstable` de (String, Option<String>) do Rust: nome, depois sem valor
// antes de com valor, depois valor, tudo por bytes.
func cookieLess(a, b cookiePair) bool {
	if a.name != b.name {
		return a.name < b.name
	}
	if a.hasValue != b.hasValue {
		return !a.hasValue
	}
	return a.value < b.value
}

func joinCookies(cs []cookiePair) (names, pairs string) {
	var n, p strings.Builder
	for i, c := range cs {
		if i > 0 {
			n.WriteByte(',')
			p.WriteByte(',')
		}
		n.WriteString(c.name)
		p.WriteString(c.name)
		if c.hasValue {
			p.WriteByte('=')
			p.WriteString(c.value)
		}
	}
	return n.String(), p.String()
}

func methodCode(m string) string {
	r := []rune(strings.ToLower(m))
	switch len(r) {
	case 0:
		return "00"
	case 1:
		return string(r) + "0"
	}
	return string(r[:2])
}

func versionCode(v string) string {
	switch v {
	case "HTTP/1.0":
		return "10"
	case "HTTP/1.1":
		return "11"
	case "HTTP/2", "HTTP/2.0":
		return "20"
	case "HTTP/3", "HTTP/3.0":
		return "30"
	}
	return "00"
}

// primaryLanguage reproduz primary_language + truncate_to(4) da ferramenta: o `;` não é removido.
func primaryLanguage(v string) string {
	v = strings.TrimLeft(v, " \t\r\n\v\f")
	v, _, _ = strings.Cut(v, ",")
	r := []rune(strings.ToLower(strings.ReplaceAll(v, "-", "")))
	if len(r) > 4 {
		r = r[:4]
	}
	s := string(r)
	return s + strings.Repeat("0", 4-len(r))
}

// hash12 é o SHA-256 truncado em 12 caracteres hex; cadeia vazia vira 12 zeros.
func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
