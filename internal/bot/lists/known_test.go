package lists

import (
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
)

// TestKnownClientsStable: a base embutida carrega com o stable de cada medida derivado do ja4_r, e o casamento pelo
// stable aceita o mesmo ClientHello com pre_shared_key (retomada TLS 1.3, ADR 0072 itens 1.1 e 1.5).
func TestKnownClientsStable(t *testing.T) {
	k, err := LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range k.Measured {
		full, stable, ok := ja4.FromRaw(m.JA4R)
		if !ok || full != m.JA4 || m.JA4Stable != stable || stable == "" {
			t.Errorf("medida %d (%s/%s): stable %q, FromRaw %q %q %v", i, m.Client, m.Proto, m.JA4Stable, full, stable, ok)
		}
	}
	var chrome KnownClient
	for _, m := range k.Measured {
		if m.Client == "chrome" && m.Proto == "h2" {
			chrome = m
		}
	}
	if chrome.JA4 == "" {
		t.Fatal("base sem chrome/h2")
	}
	// o stable casa sem comparar o JA4 completo; o JA4 de outra conexão não casa
	if _, ok := k.Coherent("chrome", Observed{JA4: "t13d1518h2_8daaf6152771_000000000000", JA4Stable: chrome.JA4Stable, Akamai: *chrome.Akamai}); !ok {
		t.Error("stable do chrome não casa")
	}
	if _, ok := k.Coherent("chrome", Observed{JA4: "t13d1518h2_8daaf6152771_000000000000", Akamai: *chrome.Akamai}); ok {
		t.Error("JA4 completo de outra conexão casou")
	}
	if _, ok := k.Coherent("chrome", Observed{JA4Stable: chrome.JA4Stable, Akamai: "1:1|2|0|m,a,s,p"}); ok {
		t.Error("stable com Akamai de outra pilha casou")
	}
	if _, ok := k.Coherent("firefox", Observed{JA4Stable: chrome.JA4Stable}); ok || !strings.HasPrefix(chrome.JA4Stable, "t13d") {
		t.Error("stable do chrome casou com firefox")
	}
}
