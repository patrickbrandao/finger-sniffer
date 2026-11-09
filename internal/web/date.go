package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// dateValue é o Date em IMF-fixdate UTC (RFC 9110 §5.6.7).
func dateValue(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

// hasDateField informa se a lista já tem um Date (h=Date:<valor>, em qualquer caixa).
func hasDateField(fields []h1.HeaderField) bool {
	for _, f := range fields {
		if strings.EqualFold(f.Name, "Date") {
			return true
		}
	}
	return false
}

// withDate põe o Date automático como primeiro campo de uma resposta final (ADR 0021, spec 005
// RF-07a). As 1xx não levam Date; date=0 (noDate) omite; um h=Date:<valor> já na lista vale no lugar do
// automático, na posição e na caixa pedidas.
func withDate(status int, fields []h1.HeaderField, noDate bool, now time.Time) []h1.HeaderField {
	if status < 200 || noDate || hasDateField(fields) {
		return fields
	}
	out := make([]h1.HeaderField, 0, len(fields)+1)
	out = append(out, h1.HeaderField{Name: "Date", Value: dateValue(now)})
	return append(out, fields...)
}

// h2KeepCanonical são as chaves que o x/net procura pela forma canônica e que não podem ir para
// minúsculas: Content-Length (vira o campo depois do mapa), Trailer (declara os trailers) e Connection
// (vira GOAWAY e sai do cabeçalho). Todas ordenam depois de "Date" ou não são escritas.
var h2KeepCanonical = map[string]bool{"Content-Length": true, "Trailer": true, "Connection": true}

// h2PrepareHeader ajusta o cabeçalho h2 antes do WriteHeader da resposta final para o date sair como
// primeiro campo regular depois de :status (ADR 0021). O x/net escreve as chaves do mapa em ordem de
// bytes e acrescenta o date no fim quando falta a chave "Date". Por isso: as demais chaves vão para
// minúsculas (o h2 manda os nomes em minúsculas de qualquer jeito) e "Date", com maiúscula, ordena antes
// de todas. "Content-Type" fica presente e vazia, só para o x/net não farejar o tipo (a chave em
// minúsculas leva o valor). date=0 deixa "Date" presente e vazia: o x/net não acrescenta e nada sai.
func h2PrepareHeader(hdr http.Header, status int, noDate bool, now time.Time) {
	var userDate []string
	for k, vv := range hdr {
		if strings.EqualFold(k, "Date") {
			userDate = append(userDate, vv...)
			delete(hdr, k)
		}
	}
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	for _, k := range keys {
		lk := strings.ToLower(k)
		if lk == k || h2KeepCanonical[k] {
			continue
		}
		hdr[lk] = append(hdr[lk], hdr[k]...)
		delete(hdr, k)
	}
	if vv, ok := hdr["content-type"]; ok && len(vv) > 0 { //nolint:staticcheck // chave em minúsculas de propósito (ver acima)
		hdr["Content-Type"] = []string{}
	}
	switch {
	case len(userDate) > 0:
		hdr["Date"] = userDate
	case noDate || status < 200:
		hdr["Date"] = nil
	default:
		hdr["Date"] = []string{dateValue(now)}
	}
}
