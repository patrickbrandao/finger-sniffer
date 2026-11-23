package bot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// TestProbeVerdictOriginNormalized: task 295 (ADR 0060 item 1) — o probe aberto pelo curl com Origin de um domínio
// da chave tem o JA4H medido com o campo a mais (ge20nn030000_ba3fe9136eb1, fora da base própria); o bot recalcula
// sem Origin pela ordem do resumo do store e dá `ja4h_library` (normalized) e `bot` 70, como pelo traefix. O JA4H
// publicado no veredito continua o medido.
func TestProbeVerdictOriginNormalized(t *testing.T) {
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "k", Domains: []string{"fs-e2e.example"}})
	const measured = "ge20nn030000_ba3fe9136eb1_000000000000_000000000000"
	stream := map[string]any{
		"stream_id": 1, "pseudo_order": []string{":method", ":path", ":scheme", ":authority"},
		"fields": []map[string]any{
			{"name": ":method", "value": "GET"},
			{"name": ":path", "value": "/p/probe2950/"},
			{"name": ":scheme", "value": "https"},
			{"name": ":authority", "value": "probe2950.example"},
			{"name": "user-agent", "value": "curl/8.23.0"},
			{"name": "accept", "value": "*/*"},
			{"name": "origin", "value": "https://fs-e2e.example"},
		},
		"ja4h": measured,
	}
	msg := storeMessageWith(t, "01JC0X3K8V2T7Q9N4M6P1R5S95", "probe2950", 4295, map[string]any{
		"http2": map[string]any{"streams": []any{stream}},
		"tcp":   map[string]any{"ja4t": ja4tMac, "os_guess": "Mac OS X"},
	})
	if err := f.srv.feed.Handle(msg); err != nil {
		t.Fatal(err)
	}
	code, _, b := f.do(f.public, "GET", "/bot/v1/probes/probe2950/verdict", key, nil, "")
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var detail string
	for _, s := range v.Signals {
		if s.ID == "ja4h_library" {
			detail = s.Detail
		}
	}
	if v.Class != ClassBot || v.Score != 70 || !strings.HasSuffix(detail, "(normalized)") ||
		!strings.Contains(detail, "ge20nn020000_5594a17e7e7e") {
		t.Fatalf("veredito %s %d %v (ja4h_library %q): %s", v.Class, v.Score, signalIDList(v.Signals), detail, b)
	}
	if v.Fingerprints == nil || v.Fingerprints.JA4H == nil || *v.Fingerprints.JA4H != measured {
		t.Errorf("JA4H publicado %v, quer o medido %s", v.Fingerprints, measured)
	}
	if v.RulesVersion != rules.RulesVersion {
		t.Errorf("rules_version %q", v.RulesVersion)
	}
}
