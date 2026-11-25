//go:build load

package main

import (
	"strings"
	"testing"
)

// cleanServer é uma janela em que o espelho não acompanhou nada (todas as condições do servidor atendidas).
func cleanServer() genFailureIn {
	return genFailureIn{
		Errors: map[string]int{}, H3Family: "6", FlowsDropped: 0,
		Conntrack:  map[string]int64{"drop": 0, "insert_failed": 0, "early_drop": 0, "error": 1},
		Throttled:  map[string]int64{"capture": 0, "web": 0, "raw": 0, "dns": 0, "store": 0, "nats": 0},
		BacklogMax: 0.11, BacklogN: 120,
	}
}

// TestClassifyGenFailure: o critério da ADR 0046 item 2 (task 256) aceita como do cliente os erros da official-f7
// (só TCP por IPv4, em web e raw) e da official-051 (87% em h3 por IPv6) com o servidor limpo; recusa (falha do
// espelho) quando uma condição do servidor falha, quando falta medida, ou quando os erros ficam num só serviço por
// vários caminhos; sem erro nem pulo, não há falha.
func TestClassifyGenFailure(t *testing.T) {
	cases := []struct {
		name    string
		mod     func(*genFailureIn)
		verdict string
		reason  string
	}{
		{"sem falha", func(*genFailureIn) {}, genNoFailure, "0 erros"},
		{"official-f7", func(in *genFailureIn) {
			in.Errors = map[string]int{"h1": 34, "h1tls": 37, "h2": 38, "raw-echo": 10, "raw-banner": 10, "raw-sink": 6, "h3": 0}
			in.Skipped = 2720
		}, genClientFault, "100% em tcp/ipv4"},
		{"official-051", func(in *genFailureIn) {
			in.Errors = map[string]int{"h3": 58, "h2": 3, "h1tls": 3, "raw-echo": 3}
			in.Skipped = 357
		}, genClientFault, "87% em udp/ipv6"},
		{"só puladas", func(in *genFailureIn) { in.Skipped = 9 }, genClientFault, "backlog do ingest < 1 s"},
		{"espalhados por serviços", func(in *genFailureIn) {
			in.Errors = map[string]int{"h3": 5, "h2": 2, "raw-echo": 5}
		}, genClientFault, "espalhados por raw e web"},
		{"num só serviço", func(in *genFailureIn) {
			in.Errors = map[string]int{"h3": 5, "h2": 4, "h1": 1}
		}, genMirrorFault, "só no serviço web"},
		{"kernel_drops", func(in *genFailureIn) {
			in.Errors = map[string]int{"h1": 3}
			in.KernelDrops = 12
		}, genMirrorFault, "kernel_drops sem crescer: 12"},
		{"degradado", func(in *genFailureIn) { in.Skipped = 4; in.Degraded = 1 }, genMirrorFault, "modo degradado"},
		{"conntrack", func(in *genFailureIn) {
			in.Errors = map[string]int{"h1": 3}
			in.Conntrack["insert_failed"] = 2
		}, genMirrorFault, "0 / 2 / 0"},
		{"throttled", func(in *genFailureIn) { in.Skipped = 1; in.Throttled["web"] = 7 }, genMirrorFault, "web 7"},
		{"backlog", func(in *genFailureIn) { in.Skipped = 1; in.BacklogMax = 1.5 }, genMirrorFault, "máx 1.50 s"},
		{"backlog não medido", func(in *genFailureIn) { in.Skipped = 1; in.BacklogN = 0 }, genMirrorFault, "sem amostras"},
		{"flows não medido", func(in *genFailureIn) { in.Skipped = 1; in.FlowsDropped = -1 }, genMirrorFault, "flows_dropped sem crescer: não medido"},
		{"conntrack não medido", func(in *genFailureIn) { in.Skipped = 1; in.Conntrack = nil }, genMirrorFault, "conntrack -S drop/insert_failed/early_drop sem crescer: não medido"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cleanServer()
			tc.mod(&in)
			got := classifyGenFailure(in)
			if got.Verdict != tc.verdict {
				t.Fatalf("veredito %q (%s), esperava %q", got.Verdict, got.Reason, tc.verdict)
			}
			if !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("motivo %q sem %q", got.Reason, tc.reason)
			}
		})
	}
}

// TestRenderGenFailure: a seção do summary.md traz o veredito, as condições e os erros por caminho e tipo.
func TestRenderGenFailure(t *testing.T) {
	in := cleanServer()
	in.Errors = map[string]int{"h3": 58, "raw-echo": 3}
	var b strings.Builder
	renderGenFailure(&b, classifyGenFailure(in))
	s := b.String()
	for _, want := range []string{
		"61 conexões com erro no cliente", "**falha do cliente aceita**", "| backlog do ingest < 1 s | máx 0.11 s (120 amostras) | sim |",
		"| udp/ipv6 | h3 | web | 58 |", "| tcp/ipv4 | raw-echo | raw | 3 |",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("seção sem %q:\n%s", want, s)
		}
	}
}

// TestBacklogOfAndMax: o backlog vem do /metrics coletado junto do health; coleta com erro (comentário do scrape)
// dá nil, e o máximo só conta as amostras dentro da janela.
func TestBacklogOfAndMax(t *testing.T) {
	v := backlogOf([]byte("# HELP x\nfs_store_ingest_backlog_seconds 0.25\nfs_store_db_bytes 1\n"))
	if v == nil || *v != 0.25 {
		t.Fatalf("backlogOf = %v", v)
	}
	if backlogOf([]byte("# erro: connection refused\n")) != nil {
		t.Fatal("coleta com erro deveria dar nil")
	}
	f := func(x float64) *float64 { return &x }
	hs := []healthSample{{T: 1, Backlog: f(5)}, {T: 10, Backlog: f(0.3)}, {T: 20}, {T: 30, Backlog: f(0.7)}, {T: 99, Backlog: f(9)}}
	m, n := backlogMax(hs, 5, 50)
	if m != 0.7 || n != 2 {
		t.Fatalf("backlogMax = %v, %d; esperava 0.7, 2", m, n)
	}
}
