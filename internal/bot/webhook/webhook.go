// Package webhook entrega os vereditos às URLs das chaves de API (spec 020 RF-06, ADR 0051 item 5): fila de 1000
// por chave com descarte contado, filtro por classe e domínio, POST JSON assinado com HMAC-SHA256, prazo de 5 s e
// novas tentativas em 1 s, 5 s e 30 s para 5xx ou erro de rede (4xx não repete).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Parâmetros da entrega (ADR 0051 item 5; spec 018 RF-11).
const (
	QueueSize      = 1000
	RequestTimeout = 5 * time.Second
	// BacklogAfter é quanto a fila precisa ficar cheia para o health ficar degraded (`webhook backlog`).
	BacklogAfter = 60 * time.Second
)

// RetryDelays são as esperas antes de cada nova tentativa.
var RetryDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

// DefaultClasses são as classes entregues quando a chave não escolhe.
var DefaultClasses = []string{"bot", "suspect"}

// Cabeçalhos do envio (openapi do bot, webhooks.verdict).
const (
	HeaderSignature = "X-Fs-Signature"
	HeaderTimestamp = "X-Fs-Timestamp"
	HeaderKeyPrefix = "X-Fs-Key-Prefix"
	signaturePrefix = "sha256="
)

// DroppedMetric conta os eventos descartados pela fila cheia (o serviço a publica zerada desde o início).
const DroppedMetric = "bot_webhook_dropped_total"

// Métricas (spec 018 RF-12). metricURLRejected conta as chaves cuja URL não é https na carga.
const (
	metricSent        = "bot_webhook_sent_total"
	metricDropped     = DroppedMetric
	metricURLRejected = "bot_webhook_url_rejected_total"
)

// Sign devolve o valor de X-Fs-Signature: "sha256=" + hex de HMAC-SHA256(segredo, ts + "." + corpo).
func Sign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return signaturePrefix + hex.EncodeToString(m.Sum(nil))
}

// Verify confere X-Fs-Signature e X-Fs-Timestamp de um envio recebido (o receptor do docs/ faz a mesma conta).
// maxSkew > 0 recusa timestamps mais distantes de now que isso (proteção contra reenvio).
func Verify(secret []byte, timestamp, signature string, body []byte, now time.Time, maxSkew time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if maxSkew > 0 {
		d := now.Sub(time.Unix(ts, 0))
		if d > maxSkew || d < -maxSkew {
			return false
		}
	}
	return hmac.Equal([]byte(Sign(secret, ts, body)), []byte(signature))
}

// ValidURL diz se a URL é aceita para o webhook (só https com host).
func ValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// Target é o webhook de uma chave.
type Target struct {
	KeyID   string
	Prefix  string // prefixo de exibição da chave (X-Fs-Key-Prefix)
	URL     string
	Secret  []byte
	Classes []string // vazio = DefaultClasses
	// Match diz se o site do veredito está nos domínios da chave.
	Match func(site string) bool
}

func (t *Target) accepts(class, site string) bool {
	classes := t.Classes
	if len(classes) == 0 {
		classes = DefaultClasses
	}
	ok := false
	for _, c := range classes {
		if c == class {
			ok = true
			break
		}
	}
	return ok && (t.Match == nil || t.Match(site))
}

// Options são as dependências do despachante (relógio e cliente falsos nos testes).
type Options struct {
	Client *http.Client
	Now    func() time.Time
	// After espera d (time.After por padrão).
	After func(d time.Duration) <-chan time.Time
	// Count soma ao contador name (service.Metrics.Add).
	Count func(name string, delta float64)
}

// Dispatcher mantém um entregador por chave com webhook.
type Dispatcher struct {
	opts     Options
	mu       sync.Mutex
	workers  map[string]*worker
	rejected map[string]string // chave → URL recusada (conta uma vez por URL)
	wg       sync.WaitGroup
}

type worker struct {
	mu        sync.Mutex
	target    Target
	queue     chan []byte
	cancel    context.CancelFunc
	fullSince time.Time // início do período de fila cheia (zero = com espaço)
}

// New cria o despachante.
func New(o Options) *Dispatcher {
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.After == nil {
		o.After = time.After
	}
	if o.Count == nil {
		o.Count = func(string, float64) {}
	}
	return &Dispatcher{opts: o, workers: map[string]*worker{}, rejected: map[string]string{}}
}

// SetTargets ajusta os entregadores às chaves atuais: cria os novos (ligados a ctx), atualiza os existentes e
// para os das chaves que saíram (o que estava na fila delas é descartado e contado). URL que não é https é
// recusada e contada uma vez.
func (d *Dispatcher) SetTargets(ctx context.Context, targets []Target) {
	d.mu.Lock()
	defer d.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range targets {
		if !ValidURL(t.URL) {
			if d.rejected[t.KeyID] != t.URL {
				d.rejected[t.KeyID] = t.URL
				d.opts.Count(metricURLRejected, 1)
			}
			continue
		}
		delete(d.rejected, t.KeyID)
		seen[t.KeyID] = true
		if w, ok := d.workers[t.KeyID]; ok {
			w.mu.Lock()
			w.target = t
			w.mu.Unlock()
			continue
		}
		wctx, cancel := context.WithCancel(ctx)
		w := &worker{target: t, queue: make(chan []byte, QueueSize), cancel: cancel}
		d.workers[t.KeyID] = w
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.run(wctx, w)
		}()
	}
	for id, w := range d.workers {
		if !seen[id] {
			w.cancel()
			delete(d.workers, id)
		}
	}
	for id := range d.rejected {
		if !containsKey(targets, id) {
			delete(d.rejected, id)
		}
	}
}

func containsKey(ts []Target, id string) bool {
	for _, t := range ts {
		if t.KeyID == id {
			return true
		}
	}
	return false
}

// Active diz se há algum webhook ativo (o chamador evita serializar o veredito à toa).
func (d *Dispatcher) Active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.workers) > 0
}

// Publish põe o evento na fila de cada chave cujo filtro aceita; body é chamado no máximo uma vez, só se alguma
// aceitar. Nunca bloqueia: fila cheia descarta e conta.
func (d *Dispatcher) Publish(class, site string, body func() []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var data []byte
	for _, w := range d.workers {
		w.mu.Lock()
		ok := w.target.accepts(class, site)
		w.mu.Unlock()
		if !ok {
			continue
		}
		if data == nil {
			if data = body(); data == nil {
				return
			}
		}
		select {
		case w.queue <- data:
		default:
			d.opts.Count(metricDropped, 1)
			w.mu.Lock()
			if w.fullSince.IsZero() {
				w.fullSince = d.opts.Now()
			}
			w.mu.Unlock()
		}
	}
}

// Backlog diz se a fila de alguma chave está cheia há mais de BacklogAfter (spec 018 RF-11).
func (d *Dispatcher) Backlog(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, w := range d.workers {
		w.mu.Lock()
		since := w.fullSince
		w.mu.Unlock()
		if !since.IsZero() && now.Sub(since) > BacklogAfter {
			return true
		}
	}
	return false
}

// Wait espera os entregadores pararem (depois de cancelar o ctx dado a SetTargets).
func (d *Dispatcher) Wait() { d.wg.Wait() }

// run entrega a fila de uma chave em ordem até ctx acabar.
func (d *Dispatcher) run(ctx context.Context, w *worker) {
	for {
		select {
		case <-ctx.Done():
			if n := len(w.queue); n > 0 {
				d.opts.Count(metricDropped, float64(n))
			}
			return
		case body := <-w.queue:
			// a fila deixa de contar como cheia quando volta a ter metade livre
			if len(w.queue) < QueueSize/2 {
				w.mu.Lock()
				w.fullSince = time.Time{}
				w.mu.Unlock()
			}
			w.mu.Lock()
			t := w.target
			w.mu.Unlock()
			d.deliver(ctx, t, body)
		}
	}
}

// deliver faz o POST com as novas tentativas.
func (d *Dispatcher) deliver(ctx context.Context, t Target, body []byte) {
	for attempt := 0; ; attempt++ {
		retry := d.send(ctx, t, body)
		if !retry || attempt >= len(RetryDelays) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-d.opts.After(RetryDelays[attempt]):
		}
	}
}

// send faz uma tentativa e diz se vale tentar de novo (5xx ou erro de rede).
func (d *Dispatcher) send(ctx context.Context, t Target, body []byte) bool {
	rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		d.opts.Count(sentMetric("error"), 1)
		return false
	}
	ts := d.opts.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(t.Secret, ts, body))
	req.Header.Set(HeaderKeyPrefix, t.Prefix)
	resp, err := d.opts.Client.Do(req)
	if err != nil {
		d.opts.Count(sentMetric("error"), 1)
		return ctx.Err() == nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	d.opts.Count(sentMetric(strconv.Itoa(resp.StatusCode)), 1)
	return resp.StatusCode >= 500
}

// sentMetric monta bot_webhook_sent_total{code="..."} (rótulos no formato da ADR 0056 item 4).
func sentMetric(code string) string {
	return fmt.Sprintf("%s{code=%q}", metricSent, strings.ToLower(code))
}
