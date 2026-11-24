package rules

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
)

// Ordens de campo reais dos clientes de biblioteca da base própria (as que dão o `ja4h_ab` medido; conferidas
// em TestJA4HWithoutContextBase) e as do e2e da F8 com Origin (test/e2e/f8_bot_test.go: o curl e o requests
// acrescentam o campo depois dos padrões; o Go h2 escreve os campos da requisição antes de accept-encoding e
// user-agent).
var (
	curlH1Fields   = []string{"Host", "User-Agent", "Accept"}
	curlH2Fields   = []string{"user-agent", "accept"}
	goH1Fields     = []string{"Host", "User-Agent", "Accept-Encoding"}
	goH2Fields     = []string{"accept-encoding", "user-agent"}
	pythonH1Fields = []string{"Host", "User-Agent", "Accept-Encoding", "Accept", "Connection"}

	curlProbeFields   = []string{"user-agent", "accept", "origin"}
	goProbeFields     = []string{"origin", "accept-encoding", "user-agent"}
	pythonProbeFields = []string{"Host", "User-Agent", "Accept-Encoding", "Accept", "Connection", "Origin"}
	// navegadores pela página local (iframe): Referer na posição em que cada um o põe
	chromeProbeFields = []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding",
		"accept-language", "priority",
	}
	firefoxProbeFields = []string{
		"user-agent", "accept", "accept-language", "accept-encoding", "referer", "upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority", "te",
	}
)

// libraryFields é a ordem real de cada medida de biblioteca da base (cliente/proto).
var libraryFields = map[string][]string{
	"curl/h1": curlH1Fields, "curl/h2": curlH2Fields, "curl/h3": curlH2Fields,
	"go/h1": goH1Fields, "go/h2": goH2Fields, "go/h3": goH2Fields,
	"python/h1": pythonH1Fields,
}

var ja4hVersion = map[string]string{"h1": "HTTP/1.1", "h2": "HTTP/2", "h3": "HTTP/3"}

// measuredJA4H é o JA4H que o espelho calcula para os campos (valores só onde mudam o JA4H).
func measuredJA4H(method, proto string, names []string) string {
	fs := make([]ja4plus.JA4HField, 0, len(names))
	for _, n := range names {
		v := "x"
		switch strings.ToLower(n) {
		case "accept-language":
			v = "pt-BR,pt;q=0.9"
		case "cookie":
			v = "a=1"
		}
		fs = append(fs, ja4plus.JA4HField{Name: n, Value: v})
	}
	return ja4plus.JA4H(ja4plus.JA4HInput{Method: method, Version: ja4hVersion[proto], Fields: fs}).JA4H
}

func insertAt(s []string, i int, v string) []string {
	return slices.Insert(slices.Clone(s), i, v)
}

// withoutContext tira da ordem os campos de contexto da ADR 0060 item 1 (Origin, Referer, Cookie) e os pseudo.
func withoutContext(names []string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool {
		return strings.EqualFold(n, "origin") || strings.EqualFold(n, "referer") || strings.EqualFold(n, "cookie") ||
			strings.HasPrefix(n, ":")
	})
}

// TestJA4HWithoutContextBase: critério da task 295 — para cada medida de biblioteca da base própria, a mesma
// requisição com Origin (no início, no meio e no fim) e com Referer dá o `ja4h_ab` recalculado igual ao da base e
// igual a `ja4plus.JA4H` da requisição sem esses campos.
func TestJA4HWithoutContextBase(t *testing.T) {
	base := loadKnownClients(t)
	known := fakeKnown{base.Measured}
	seen := 0
	for _, e := range base.Measured {
		ab := deref(e.JA4HAB)
		if ab == "" || firstLibrary(known.Families(KindJA4HAB, ab)) == "" {
			continue
		}
		key := e.Client + "/" + e.Proto
		fields, ok := libraryFields[key]
		if !ok {
			t.Errorf("%s: medida de biblioteca sem a ordem de campos no teste", key)
			continue
		}
		seen++
		if got := ja4hAB(measuredJA4H("GET", e.Proto, fields)); got != ab {
			t.Fatalf("%s: ordem %v dá %s, a base tem %s", key, fields, got, ab)
		}
		variants := map[string][]string{
			"origin_start":  insertAt(fields, 0, "Origin"),
			"origin_middle": insertAt(fields, 1, "origin"),
			"origin_end":    append(slices.Clone(fields), "Origin"),
			"referer":       insertAt(fields, 1, "Referer"),
			"both":          append(insertAt(fields, 1, "referer"), "origin"),
		}
		if e.Proto != "h1" {
			// pseudo-cabeçalhos na ordem (o store já os tira; a função ignora se vierem)
			variants["pseudo"] = append([]string{":method", ":authority", ":scheme", ":path"}, append(slices.Clone(fields), "origin")...)
		}
		for name, v := range variants {
			measured := ja4hAB(measuredJA4H("GET", e.Proto, v))
			if strings.Contains(name, "origin") && measured == ab {
				t.Errorf("%s/%s: o JA4H medido com Origin já casava (%s)", key, name, measured)
			}
			got := ja4hABWithoutContext(measured, v)
			if got != ab {
				t.Errorf("%s/%s: recalculado %s, base %s (medido %s)", key, name, got, ab, measured)
			}
			if ref := ja4hAB(measuredJA4H("GET", e.Proto, withoutContext(v))); got != ref {
				t.Errorf("%s/%s: recalculado %s, ja4plus sem os campos %s", key, name, got, ref)
			}
		}
	}
	if seen < len(libraryFields) {
		t.Errorf("%d medidas de biblioteca na base, %d ordens no teste", seen, len(libraryFields))
	}
}

// TestJA4HWithoutContextEqualsJA4Plus: o recálculo segue `ja4plus.JA4H` (contagem com teto 99, hash12 dos nomes na
// caixa recebida, comparação sem caixa, `000000000000` sem nenhum campo) com qualquer mistura de nomes, inclusive
// com cookie (o sinalizador `c` vem do medido) e sem Accept-Language.
func TestJA4HWithoutContextEqualsJA4Plus(t *testing.T) {
	pool := []string{
		"Host", "host", "User-Agent", "user-agent", "Accept", "accept-encoding", "Connection", "x-custom", "Origin",
		"ORIGIN", "origin", "Referer", "REFERER", "referer", "Cookie", "cookie", ":path", "te", "priority",
	}
	r := rand.New(rand.NewPCG(295, 60))
	for i := range 2000 {
		n := r.IntN(130)
		if i < 3 {
			n = []int{0, 1, 120}[i]
		}
		names := make([]string, n)
		for j := range names {
			names[j] = pool[r.IntN(len(pool))]
			if i%7 == 0 {
				names[j] = fmt.Sprintf("x-f%d", j)
			}
		}
		method, proto := []string{"GET", "POST", "HEAD"}[i%3], []string{"h1", "h2", "h3"}[i%3]
		measured := ja4hAB(measuredJA4H(method, proto, names))
		ref := measuredJA4H(method, proto, withoutContext(names))
		want := ja4hAB(ref)
		// o sinalizador de cookie é o do medido (a referência ficou sem o Cookie)
		want = want[:4] + measured[4:5] + want[5:]
		got := ja4hABWithoutContext(measured, names)
		if len(names) == 0 {
			if got != "" {
				t.Fatalf("sem ordem de campos: %q", got)
			}
			continue
		}
		if got != want {
			t.Fatalf("caso %d %v: %s, quer %s", i, names, got, want)
		}
	}
}

func TestJA4HWithoutContextMalformed(t *testing.T) {
	for _, ab := range []string{"", "ge20nn030000", "ge20nn03000_abc", "ge20nn0300000_abc"} {
		if got := ja4hABWithoutContext(ab, []string{"user-agent"}); got != "" {
			t.Errorf("%q: %q", ab, got)
		}
	}
}

// TestJA4HLibraryNormalized: o medido casa sem `(normalized)`; só o recalculado casa com `(normalized)`; sem
// FieldOrder (forwardAuth, resumo antigo) só o medido; com Accept-Language a regra não vale.
func TestJA4HLibraryNormalized(t *testing.T) {
	base := loadKnownClients(t)
	en := Engine{Sources: Sources{Known: fakeKnown{base.Measured}}}
	probe := measuredJA4H("GET", "h2", curlProbeFields)
	if !strings.HasPrefix(probe, "ge20nn030000_ba3fe9136eb1_") {
		t.Fatalf("JA4H do curl com Origin %s (ADR 0060: ge20nn030000_ba3fe9136eb1)", probe)
	}
	detail := func(h *HTTP) string {
		for _, s := range en.Evaluate(Input{HTTP: h, View: View{HTTP: true}}).Signals {
			if s.ID == SignalJA4HLibrary {
				return s.Detail
			}
		}
		return ""
	}
	cases := []struct {
		name string
		h    *HTTP
		want string
	}{
		{
			"measured", &HTTP{UserAgent: "curl/8.23.0", JA4H: measuredJA4H("GET", "h2", curlH2Fields), FieldOrder: curlH2Fields},
			"ja4h ge20nn020000_5594a17e7e7e of curl, no accept-language",
		},
		{
			"normalized", &HTTP{UserAgent: "curl/8.23.0", JA4H: probe, FieldOrder: curlProbeFields},
			"ja4h ge20nn020000_5594a17e7e7e of curl, no accept-language (normalized)",
		},
		{"no_field_order", &HTTP{UserAgent: "curl/8.23.0", JA4H: probe}, ""},
		{"accept_language", &HTTP{UserAgent: "curl/8.23.0", JA4H: probe, FieldOrder: curlProbeFields, HasAcceptLanguage: true}, ""},
		{"other_order", &HTTP{UserAgent: "curl/8.23.0", JA4H: probe, FieldOrder: []string{"accept", "user-agent", "origin"}}, ""},
	}
	for _, c := range cases {
		if got := detail(c.h); got != c.want {
			t.Errorf("%s: detail %q, quer %q", c.name, got, c.want)
		}
	}
}
