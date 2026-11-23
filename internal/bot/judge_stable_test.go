package bot

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// TestJudgeStoreStable: o `tls.ja4_stable` do registro do store entra nas regras (ADR 0072 item 1.1). Um Chrome
// retomado (JA4 completo diferente do medido, sem o ja4_r) com o stable do medido ganha o known_client; sem o stable
// (nem o ja4_r), não ganha, e a parte b igual não dá ua_tls_mismatch.
func TestJudgeStoreStable(t *testing.T) {
	f := newFixture(t)
	k, err := lists.LoadKnownClients()
	if err != nil {
		t.Fatal(err)
	}
	var chrome lists.KnownClient
	for _, m := range k.Measured {
		if m.Client == "chrome" && m.Proto == "h2" {
			chrome = m
		}
	}
	resumedJA4 := "t13d1518h2_8daaf6152771_000000000000"
	record := func(stable string) json.RawMessage {
		tls := map[string]any{"ja4": resumedJA4, "alpn": []string{"h2", "http/1.1"}}
		if stable != "" {
			tls["ja4_stable"] = stable
		}
		b, err := json.Marshal(map[string]any{"tls": tls, "http2": map[string]any{"akamai": *chrome.Akamai}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	for _, c := range []struct {
		stable string
		want   []string
	}{
		{chrome.JA4Stable, []string{rules.SignalKnownClient}},
		{"", []string{}},
	} {
		vw := views{
			ip: netip.MustParseAddr("192.0.2.10"), proto: "h2",
			store: &StoreConn{L4: "tcp", Proto: "h2", Record: record(c.stable)},
			http:  &rules.HTTP{UserAgent: ua, Version: "2", HasAcceptLanguage: true},
		}
		v, _ := f.srv.judge.evaluate(vw, Subject{})
		if got := signalIDList(v.Signals); !slices.Equal(got, c.want) {
			t.Errorf("stable %q: sinais %v, quer %v", c.stable, got, c.want)
		}
	}
}
