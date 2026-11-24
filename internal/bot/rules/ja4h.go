package rules

import (
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
)

// Tamanho da parte a do JA4H: método (2), versão (2), cookie (1), referer (1), contagem (2) e idioma (4).
const (
	ja4hPartALen   = 12
	ja4hMethodVer  = 4 // método e versão
	ja4hCookieFlag = 4 // posição do sinalizador de cookie
)

// ja4hABWithoutContext recalcula as partes a e b do JA4H sem Origin, Referer, Cookie e pseudo-cabeçalhos (ADR 0060
// item 1), a partir do `ja4h_ab` medido (método, versão e sinalizador de cookie) e da ordem dos campos. A parte a
// leva o sinalizador de referer `n` e o idioma `0000` (a regra só vale sem Accept-Language). O cálculo é o de
// `ja4plus.JA4HAB`, no pacote isolado da FoxIO License 1.1 (ADR 0010, task 403); aqui só sai o Origin, que é
// contexto da navegação e não da biblioteca (Cookie, Referer e pseudo o JA4HAB já tira). Devolve "" sem a ordem dos
// campos ou com a parte a medida malformada.
func ja4hABWithoutContext(measuredAB string, fieldOrder []string) string {
	if len(fieldOrder) == 0 {
		return ""
	}
	a, _, ok := strings.Cut(measuredAB, "_")
	if !ok || len(a) != ja4hPartALen {
		return ""
	}
	names := make([]string, 0, len(fieldOrder))
	for _, n := range fieldOrder {
		if n == "" || strings.EqualFold(n, "origin") {
			continue
		}
		names = append(names, n)
	}
	return ja4plus.JA4HAB(a[:ja4hMethodVer], a[ja4hCookieFlag] == 'c', false, names, "")
}

// ja4hLibrary avalia `ja4h_library` (spec 018, ADR 0060 item 1): o `ja4h_ab` medido ou o recalculado sem os campos
// de contexto é de uma família de biblioteca na base própria. Quem chama já conferiu a ausência de Accept-Language.
func (en Engine) ja4hLibrary(ev *eval, h *HTTP) {
	ab := ja4hAB(h.JA4H)
	if ab == "" {
		return
	}
	if lib := firstLibrary(en.Sources.Known.Families(KindJA4HAB, ab)); lib != "" {
		ev.add(SignalJA4HLibrary, "ja4h "+ab+" of "+lib+", no accept-language")
		return
	}
	n := ja4hABWithoutContext(ab, h.FieldOrder)
	if n == "" || n == ab {
		return
	}
	if lib := firstLibrary(en.Sources.Known.Families(KindJA4HAB, n)); lib != "" {
		ev.add(SignalJA4HLibrary, "ja4h "+n+" of "+lib+", no accept-language (normalized)")
	}
}
