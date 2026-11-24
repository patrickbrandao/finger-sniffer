package tlsparse

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestInfoParseIssues: extensão repetida, extensão malformada e cipher_suites ímpar saem em extension_errors e
// field_errors com os códigos estáveis do schema TLSParseIssue (duplicate, malformed, odd_length), campo e
// posição do ParseError, nunca o texto do erro Go (task 386).
func TestInfoParseIssues(t *testing.T) {
	exts := ext(ExtALPN, 0, 3, 2, 'h', '2')
	exts = append(exts, ext(ExtSupportedGroups, 0)...)
	exts = append(exts, ext(ExtALPN, 0, 3, 2, 'x', '1')...)
	msg := buildHello(exts)
	// troca "0, 2, 0x13, 0x01" por "0, 3, 0x13, 0x01, 0xff" no cipher_suites e corrige o tamanho
	i := handshakeHeaderLen + 2 + 32 + 1
	body := append(append([]byte{}, msg[handshakeHeaderLen:i]...), 0, 3, 0x13, 0x01, 0xff)
	body = append(body, msg[i+4:]...)
	n := len(body)
	msg = append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	ch, err := ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	in := NewInfo(ch, msg, 0)
	if len(in.ExtensionErrors) != 2 || len(in.FieldErrors) != 1 || in.ListsTruncated {
		t.Fatalf("extension_errors=%v field_errors=%v truncated=%v", in.ExtensionErrors, in.FieldErrors, in.ListsTruncated)
	}
	var pe [2]*ParseError
	if !errors.As(ch.ExtensionErrors[0], &pe[0]) || !errors.As(ch.ExtensionErrors[1], &pe[1]) {
		t.Fatal(ch.ExtensionErrors)
	}
	want := []ParseIssue{
		{Field: fmt.Sprintf("extension 0x%04x", ExtSupportedGroups), Offset: pe[0].Offset, Error: IssueMalformed},
		{Field: fmt.Sprintf("extension 0x%04x", ExtALPN), Offset: pe[1].Offset, Error: IssueDuplicate},
	}
	if !slices.Equal(in.ExtensionErrors, want) || pe[0].Offset == 0 || pe[1].Offset <= pe[0].Offset {
		t.Fatalf("extension_errors=%v, want %v", in.ExtensionErrors, want)
	}
	if fe := in.FieldErrors[0]; fe != (ParseIssue{Field: "cipher_suites", Offset: i, Error: IssueOddLength}) {
		t.Fatalf("field_errors=%v", in.FieldErrors)
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	ee, _ := m["extension_errors"].([]any)
	fe, _ := m["field_errors"].([]any)
	if len(ee) != 2 || len(fe) != 1 || strings.Contains(string(b), "duplicate extension") {
		t.Fatalf("JSON: %s", b)
	}
	if e0, _ := ee[1].(map[string]any); e0["field"] != "extension 0x0010" || e0["error"] != "duplicate" {
		t.Fatalf("JSON: %v", ee[1])
	}

	// sem erro: as chaves ficam ausentes (omitempty)
	ch, err = ParseMessage(buildHello(ext(ExtALPN, 0, 3, 2, 'h', '2')))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(NewInfo(ch, nil, 0))
	if strings.Contains(string(b), "extension_errors") || strings.Contains(string(b), "field_errors") {
		t.Fatalf("JSON sem erro: %s", b)
	}
}

// TestInfoParseIssuesCap: mais de 64 extensões repetidas viram 64 itens em extension_errors e lists_truncated.
func TestInfoParseIssuesCap(t *testing.T) {
	var exts []byte
	for range MaxParseIssues + 10 {
		exts = append(exts, ext(ExtALPN, 0, 3, 2, 'h', '2')...)
	}
	ch, err := ParseMessage(buildHello(exts))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.ExtensionErrors) != MaxParseIssues+9 {
		t.Fatalf("ExtensionErrors=%d", len(ch.ExtensionErrors))
	}
	in := NewInfo(ch, nil, 0)
	if len(in.ExtensionErrors) != MaxParseIssues || !in.ListsTruncated || in.FieldErrors != nil {
		t.Fatalf("extension_errors=%d truncated=%v", len(in.ExtensionErrors), in.ListsTruncated)
	}
	for _, it := range in.ExtensionErrors {
		if it.Error != IssueDuplicate || it.Field != "extension 0x0010" || it.Offset == 0 {
			t.Fatalf("item %v", it)
		}
	}
	// exatamente 64: sem corte
	ch.ExtensionErrors = ch.ExtensionErrors[:MaxParseIssues]
	if in := NewInfo(ch, nil, 0); len(in.ExtensionErrors) != MaxParseIssues || in.ListsTruncated {
		t.Fatalf("64 itens: %d truncated=%v", len(in.ExtensionErrors), in.ListsTruncated)
	}
}

// TestInfoFitParseIssues: a redução do Fit também encurta as listas de erros, marcando lists_truncated.
func TestInfoFitParseIssues(t *testing.T) {
	in := &Info{
		CipherSuites:    make([]CodeName, 40),
		ExtensionErrors: make([]ParseIssue, 40),
		FieldErrors:     make([]ParseIssue, 40),
	}
	in.limitLists(10)
	if len(in.ExtensionErrors) != 10 || len(in.FieldErrors) != 10 || !in.ListsTruncated || in.longestList() != 10 {
		t.Fatalf("extension_errors=%d field_errors=%d truncated=%v", len(in.ExtensionErrors), len(in.FieldErrors), in.ListsTruncated)
	}
}
