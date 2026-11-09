//go:build ignore

// gentables gera tables.go a partir das cópias XML dos registros IANA de TLS.
//
// Uso (na pasta pkg/iana):
//
//	curl -sfLO https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
//	curl -sfLO https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml
//	go run gentables.go -params tls-parameters.xml -ext tls-extensiontype-values.xml
//	gofumpt -w tables.go
//
// Os XML não ficam no repositório; a data de atualização de cada registro vai anotada em tables.go.
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type record struct {
	Value       string `xml:"value"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
}

type registry struct {
	ID      string     `xml:"id,attr"`
	Title   string     `xml:"title"`
	Records []record   `xml:"record"`
	Subs    []registry `xml:"registry"`
}

type root struct {
	Updated string     `xml:"updated"`
	Subs    []registry `xml:"registry"`
}

// tabela gerada: nome da variável, id do registro, largura (8 ou 16 bits)
type table struct {
	varName string
	regID   string
	bits    int
	comment string
}

var tables = []table{
	{"cipherSuites", "tls-parameters-4", 16, "TLS Cipher Suites"},
	{"alerts", "tls-parameters-6", 8, "TLS Alerts"},
	{"handshakeTypes", "tls-parameters-7", 8, "TLS HandshakeType"},
	{"supportedGroups", "tls-parameters-8", 16, "TLS Supported Groups"},
	{"ecPointFormats", "tls-parameters-9", 8, "TLS EC Point Formats"},
	{"legacySignatures", "tls-parameters-16", 8, "TLS SignatureAlgorithm (TLS 1.2)"},
	{"legacyHashes", "tls-parameters-18", 8, "TLS HashAlgorithm (TLS 1.2)"},
	{"signatureSchemes", "tls-signaturescheme", 16, "TLS SignatureScheme"},
	{"pskKeyExchangeModes", "tls-pskkeyexchangemode", 8, "TLS PskKeyExchangeMode"},
	{"extensions", "tls-extensiontype-values-1", 16, "TLS ExtensionType Values"},
	{"certCompressionAlgorithms", "tls-certificate-compression-algorithm-ids", 16, "TLS Certificate Compression Algorithm IDs"},
}

func main() {
	params := flag.String("params", "tls-parameters.xml", "cópia de tls-parameters.xml")
	ext := flag.String("ext", "tls-extensiontype-values.xml", "cópia de tls-extensiontype-values.xml")
	out := flag.String("out", "tables.go", "arquivo gerado")
	flag.Parse()

	regs := map[string]registry{}
	dates := map[string]string{}
	for _, p := range []string{*params, *ext} {
		b, err := os.ReadFile(p)
		if err != nil {
			log.Fatal(err)
		}
		var r root
		if err := xml.Unmarshal(b, &r); err != nil {
			log.Fatalf("%s: %v", p, err)
		}
		dates[p] = r.Updated
		var walk func([]registry)
		walk = func(rs []registry) {
			for _, s := range rs {
				regs[s.ID] = s
				walk(s.Subs)
			}
		}
		walk(r.Subs)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// Código gerado por gentables.go; NÃO EDITE.\n\n")
	fmt.Fprintf(&buf, "package iana\n\n")
	fmt.Fprintf(&buf, "// Fonte: registros IANA de TLS (https://www.iana.org/assignments/tls-parameters/ e\n")
	fmt.Fprintf(&buf, "// https://www.iana.org/assignments/tls-extensiontype-values/).\n")
	fmt.Fprintf(&buf, "// Cópia de tls-parameters.xml atualizada em %s; tls-extensiontype-values.xml em %s.\n\n",
		dates[*params], dates[*ext])

	for _, t := range tables {
		reg, ok := regs[t.regID]
		if !ok {
			log.Fatalf("registro %s ausente", t.regID)
		}
		entries := map[int]string{}
		for _, rec := range reg.Records {
			name := strings.TrimSpace(rec.Name)
			if name == "" {
				name = strings.TrimSpace(rec.Description)
			}
			name = strings.Join(strings.Fields(name), " ")
			// "supported_groups (renamed from "elliptic_curves")" → "supported_groups"
			if i := strings.Index(name, " (renamed from"); i > 0 {
				name = name[:i]
			}
			if skipName(name) {
				continue
			}
			v, ok := parseValue(rec.Value)
			if !ok {
				continue
			}
			entries[v] = name
		}
		keys := make([]int, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		typ := "uint16"
		fmtv := "0x%04x"
		if t.bits == 8 {
			typ = "uint8"
			fmtv = "%d"
		}
		fmt.Fprintf(&buf, "// %s (registro %s).\n", t.comment, t.regID)
		fmt.Fprintf(&buf, "var %s = map[%s]string{\n", t.varName, typ)
		for _, k := range keys {
			fmt.Fprintf(&buf, "\t"+fmtv+": %s,\n", k, strconv.Quote(entries[k]))
		}
		fmt.Fprintf(&buf, "}\n\n")
	}

	src, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
}

// skipName descarta faixas não atribuídas e reservadas (GREASE é reconhecido por regra, não por tabela).
func skipName(n string) bool {
	l := strings.ToLower(n)
	return n == "" || strings.HasPrefix(l, "unassigned") || strings.HasPrefix(l, "reserved") ||
		strings.Contains(l, "private use") || strings.Contains(l, "experimental")
}

// parseValue aceita "23", "0x0403" e "0x13,0x01"; recusa faixas.
func parseValue(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "-") || strings.Contains(v, "*") {
		return 0, false
	}
	if a, b, ok := strings.Cut(v, ","); ok {
		hi, err1 := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(a), "0x"), 16, 8)
		lo, err2 := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(b), "0x"), 16, 8)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return int(hi<<8 | lo), true
	}
	n, err := strconv.ParseUint(v, 0, 16)
	if err != nil {
		return 0, false
	}
	return int(n), true
}
