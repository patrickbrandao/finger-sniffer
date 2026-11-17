package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Tamanho da parte a do JA4H: método (2), versão (2), cookie (1), referer (1), contagem (2) e idioma (4).
const (
	ja4hPartALen   = 12
	ja4hMarkersEnd = 5 // método, versão e o sinalizador de cookie
	ja4hMaxCount   = 99
	ja4hHashBytes  = 6 // 12 caracteres hex
)

// ja4hContextField diz se o campo é de contexto da navegação (ADR 0060 item 1): Origin e Referer dizem de onde a
// requisição partiu, não qual biblioteca a fez; o Cookie já fica fora da contagem e do hash no próprio JA4H.
func ja4hContextField(name string) bool {
	return strings.EqualFold(name, "origin") || strings.EqualFold(name, "referer") || strings.EqualFold(name, "cookie")
}

// ja4hABWithoutContext recalcula as partes a e b do JA4H sem Origin, Referer, Cookie e pseudo-cabeçalhos (ADR 0060
// item 1), a partir do `ja4h_ab` medido (método, versão e sinalizador de cookie) e da ordem dos campos. A parte a
// leva o sinalizador de referer `n` e o idioma `0000` (a regra só vale sem Accept-Language). Contagem e hash seguem
// `ja4plus.JA4H` (teto 99, nomes na caixa recebida unidos por vírgula, SHA-256 em 12 hex, `000000000000` sem
// nenhum); o pacote fica só com a stdlib, e o teste prova a igualdade com `ja4plus.JA4H`. Devolve "" sem a ordem
// dos campos ou com a parte a medida malformada.
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
		if n == "" || strings.HasPrefix(n, ":") || ja4hContextField(n) {
			continue
		}
		names = append(names, n)
	}
	return fmt.Sprintf("%sn%02d0000_%s", a[:ja4hMarkersEnd], min(len(names), ja4hMaxCount), ja4hHash12(strings.Join(names, ",")))
}

// ja4hHash12 é o hash12 do JA4H: SHA-256 truncado em 12 hex; cadeia vazia vira 12 zeros.
func ja4hHash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:ja4hHashBytes])
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
