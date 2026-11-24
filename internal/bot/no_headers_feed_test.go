package bot

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// Task 315 (adendo da ADR 0065 item 2): o resumo de requisição sem cabeçalhos (sem fieldNames, fields nem ja4h)
// nunca vira ua_missing também no feed, no webhook e na consulta que reavalia a conexão (connectionVerdict). Uma
// regressão para httpFromFork direto da última requisição deixa estes testes vermelhos.

// readFeedVerdicts lê n vereditos do SSE (VerdictEvent de kind verdict) ou falha no prazo.
func readFeedVerdicts(t *testing.T, body io.Reader, n int) []Verdict {
	t.Helper()
	out := make(chan Verdict, n)
	go func() {
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var ev VerdictEvent
			if json.Unmarshal([]byte(data), &ev) == nil && ev.Kind == "verdict" && ev.Verdict != nil {
				out <- *ev.Verdict
			}
		}
	}()
	var got []Verdict
	timeout := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case v := <-out:
			got = append(got, v)
		case <-timeout:
			t.Fatalf("feed: %d de %d vereditos", len(got), n)
		}
	}
	return got
}

// pathOf é o path do sujeito do veredito ("" sem ele).
func pathOf(v *Verdict) string {
	return deref(v.Subject.Path)
}

// TestFeedAndWebhookWithoutHeaders: critério 1 — no caso /favicon.ico de TestTraefixRequestWithoutHeaders, o
// veredito publicado no feed (SSE da 9002) e no webhook da chave (todas as classes) não traz ua_missing e mantém a visão HTTP da
// requisição anterior.
func TestFeedAndWebhookWithoutHeaders(t *testing.T) {
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T62"
	recv := make(chan []byte, 8)
	rcv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recv <- b
	}))
	defer rcv.Close()

	f := newFixture(t)
	hc, hookURL := hookReceiver(t, rcv, "/hook")
	f.srv.hooks = webhook.New(webhook.Options{Client: hc, Now: f.clock.Now, Count: f.metrics.Add})
	_, key, _ := f.createWebhookKey(KeyOptions{
		Name: "site", Domains: []string{"www.example.com"}, WebhookURL: hookURL,
		WebhookClasses: []string{ClassHuman, ClassGoodBot, ClassBot, ClassSuspect, ClassUnknown},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); f.srv.hooks.Wait() }()
	f.srv.syncWebhooks(ctx)
	resp := f.openFeed(key, 1)

	if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.62", 50062, chromeConn(nil), chromeRequest())); c != 202 || got["accepted"] != 2 {
		t.Fatalf("ingest com cabeçalhos: %d %v", c, got)
	}
	bare := map[string]any{"path": "/favicon.ico", "status": 404}
	if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.62", 50062, nil, bare)); c != 202 || got["accepted"] != 2 {
		t.Fatalf("ingest sem cabeçalhos: %d %v", c, got)
	}

	check := func(where string, v *Verdict) {
		t.Helper()
		if slices.Contains(signalIDList(v.Signals), "ua_missing") || !v.View.HTTP {
			t.Fatalf("%s: requisição sem cabeçalhos virou ua_missing: %+v", where, v)
		}
	}
	feed := readFeedVerdicts(t, resp.Body, 2)
	var seen bool
	for i := range feed {
		if pathOf(&feed[i]) == "/favicon.ico" {
			check("feed", &feed[i])
			seen = true
		}
	}
	if !seen {
		t.Fatalf("feed sem o veredito de /favicon.ico: %+v", feed)
	}

	seen = false
	timeout := time.After(5 * time.Second)
	for !seen {
		select {
		case b := <-recv:
			var ev VerdictEvent
			if err := json.Unmarshal(b, &ev); err != nil || ev.Verdict == nil {
				t.Fatalf("evento do webhook %s (%v)", b, err)
			}
			if pathOf(ev.Verdict) == "/favicon.ico" {
				check("webhook", ev.Verdict)
				seen = true
			}
		case <-timeout:
			t.Fatal("webhook sem o veredito de /favicon.ico")
		}
	}
}

// TestConnectionVerdictWithoutHeaders: critério 2 — a consulta sem veredito guardado (LastVerdict nil) reavalia a
// conexão por connectionVerdict; com o último resumo sem cabeçalhos, a visão HTTP é a da requisição anterior que os
// tem (sem ua_missing) e, só com resumos sem cabeçalhos, a visão HTTP é desconhecida (também sem ua_missing).
func TestConnectionVerdictWithoutHeaders(t *testing.T) {
	bare := map[string]any{"path": "/favicon.ico", "status": 404}
	for _, tc := range []struct {
		name, id, ip string
		port         int
		first        map[string]any
		wantHTTP     bool
	}{
		{"after a request with headers", "01JC0X3K8V2T7Q9F4M6P1R5T63", "198.51.100.63", 50063, chromeRequest(), true},
		{"only requests without headers", "01JC0X3K8V2T7Q9F4M6P1R5T64", "198.51.100.64", 50064, bare, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.postIngest(traefixBatchJSON(t, tc.id, tc.ip, tc.port, chromeConn(nil), tc.first))
			f.postIngest(traefixBatchJSON(t, tc.id, tc.ip, tc.port, nil, bare))
			// sem o veredito guardado, a consulta passa por connectionVerdict
			f.srv.Index().UpdateFork(tc.id, f.clock.Now(), func(c *ForkConn) { c.LastVerdict, c.LastClass = nil, "" })
			fc, ok := f.srv.Index().Fork(tc.id, f.clock.Now())
			if !ok || fc.LastVerdict != nil || len(fc.Requests) != 2 || forkHeadersKnown(&fc.Requests[1]) {
				t.Fatalf("conexão: %v %+v", ok, fc)
			}
			v := f.verdictOf(tc.id)
			if v.Subject.Kind != "connection" {
				t.Fatalf("consulta não reavaliou a conexão: %+v", v.Subject)
			}
			if slices.Contains(signalIDList(v.Signals), "ua_missing") || v.View.HTTP != tc.wantHTTP {
				t.Fatalf("consulta com o último resumo sem cabeçalhos: %+v", v)
			}
		})
	}
}
