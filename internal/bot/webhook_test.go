package bot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/webhook"
)

// TestWebhookFromHub: um veredito publicado no Hub chega ao webhook da chave (classe e domínio dela) como
// VerdictEvent assinado com o segredo emitido em `key create`; outra classe ou outro site não chegam; com a fila
// cheia por mais de 60 s o health mostra `webhook backlog`.
func TestWebhookFromHub(t *testing.T) {
	type got struct {
		hdr  http.Header
		body []byte
	}
	recv := make(chan got, 4)
	block := make(chan struct{})
	rcv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recv <- got{r.Header.Clone(), b}
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer rcv.Close()
	defer close(block)

	f := newFixture(t)
	hc, hookURL := hookReceiver(t, rcv, "/hook")
	f.srv.hooks = webhook.New(webhook.Options{Client: hc, Now: f.clock.Now, Count: f.metrics.Add})
	k, _, whSecret := f.createWebhookKey(KeyOptions{Name: "site", Domains: []string{"*.example.com"}, WebhookURL: hookURL})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); f.srv.hooks.Wait() }()
	f.srv.syncWebhooks(ctx)

	verdict := func(class, site string) *Verdict {
		return &Verdict{
			Class: class, Signals: []Signal{}, RulesVersion: "v1.2", ListsVersion: "x", Subject: Subject{Kind: "request", Site: &site},
			Ts: "2026-11-16T12:00:00.000000000Z",
		}
	}
	f.srv.hub.Publish(verdict(ClassHuman, "www.example.com"))
	f.srv.hub.Publish(verdict(ClassBot, "other.org"))
	f.srv.hub.Publish(verdict(ClassBot, "www.example.com"))
	r := <-recv
	var ev VerdictEvent
	if err := json.Unmarshal(r.body, &ev); err != nil || ev.Kind != "verdict" || ev.Verdict == nil || ev.Verdict.Class != ClassBot {
		t.Fatalf("evento %s (%v)", r.body, err)
	}
	if !webhook.Verify(whSecret, r.hdr.Get(webhook.HeaderTimestamp), r.hdr.Get(webhook.HeaderSignature), r.body, f.clock.Now(), time.Minute) {
		t.Fatal("assinatura não confere com o segredo da chave")
	}
	if p := r.hdr.Get(webhook.HeaderKeyPrefix); p != keyPrefix+k.Prefix {
		t.Fatalf("prefixo %q", p)
	}

	// o receptor segura o primeiro envio: a fila enche e, 60 s depois, o health degrada
	for range webhook.QueueSize + 1 {
		f.srv.hub.Publish(verdict(ClassSuspect, "a.example.com"))
	}
	if f.metrics.Get("bot_webhook_dropped_total") != 1 {
		t.Fatalf("descartes %v", f.metrics.Get("bot_webhook_dropped_total"))
	}
	if _, reasons := f.srv.Status(); slices.Contains(reasons, "webhook backlog") {
		t.Fatal("backlog cedo demais")
	}
	f.clock.Advance(61 * time.Second)
	if st, reasons := f.srv.Status(); st != "degraded" || !slices.Contains(reasons, "webhook backlog") {
		t.Fatalf("status %s %v", st, reasons)
	}
}

// createWebhookKey emite uma chave com webhook e devolve também o segredo do HMAC.
func (f *fixture) createWebhookKey(o KeyOptions) (Key, string, []byte) {
	f.t.Helper()
	k, secret, wh, err := CreateKey(context.Background(), f.db, o, f.clock.Now())
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.srv.Keys().Reload(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	if got := f.srv.Keys().WebhookKeys(); len(got) != 1 || string(got[0].WebhookSecret()) != string(wh) {
		f.t.Fatal("segredo do webhook não carregado")
	}
	return k, secret, wh
}
