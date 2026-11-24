// Package webhook entrega os vereditos às URLs das chaves de API (spec 020 RF-06, ADR 0051 item 5): fila de 1000
// por chave com descarte contado, filtro por classe e domínio, POST JSON assinado com HMAC-SHA256, prazo de 5 s e
// novas tentativas em 1 s, 5 s e 30 s para 5xx ou erro de rede (4xx não repete). Redirecionamento não é seguido
// (3xx é resposta final) e o cliente próprio recusa, depois da resolução, destinos internos (task 372).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// ErrBlockedDestination é o erro do dial para um destino interno (loopback, privado, link-local, CGNAT etc.).
var ErrBlockedDestination = errors.New("webhook: destination address not allowed")

// blockedPrefixes completa os testes de netip.Addr em BlockedAddr com faixas sem método próprio.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "esta rede"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // atribuições do protocolo IETF
	netip.MustParsePrefix("198.18.0.0/15"),   // testes de desempenho
	netip.MustParsePrefix("240.0.0.0/4"),     // reservada, inclui o broadcast
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64 de uso local
	netip.MustParsePrefix("fec0::/10"),       // site-local (obsoleta)
	netip.MustParsePrefix("2001:db8::/32"),   // documentação
	netip.MustParsePrefix("100::/64"),        // descarte
	netip.MustParsePrefix("192.0.2.0/24"),    // documentação
	netip.MustParsePrefix("198.51.100.0/24"), // documentação
	netip.MustParsePrefix("203.0.113.0/24"),  // documentação
}

// BlockedAddr diz se o webhook não pode chamar o endereço: inválido, não especificado, loopback, privado (RFC 1918
// e ULA), link-local, multicast, CGNAT e as faixas reservadas de blockedPrefixes. IPv4 mapeado em IPv6 conta como
// IPv4. Os IPs do próprio host ficam no cliente (localAddrs), porque mudam com a máquina.
func BlockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// blockedOrLocal é a política padrão do cliente: BlockedAddr ou um dos IPs das interfaces do host.
func blockedOrLocal(a netip.Addr) bool {
	if BlockedAddr(a) {
		return true
	}
	a = a.Unmap()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// sem a lista, recusa: melhor perder o envio que chamar o próprio host
		return true
	}
	for _, ia := range addrs {
		if n, ok := ia.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// ClientConfig ajusta o cliente próprio do webhook (resolvedor e política falsos nos testes).
type ClientConfig struct {
	// Lookup resolve o host (net.DefaultResolver.LookupNetIP por padrão).
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Blocked diz se o destino é recusado (BlockedAddr e os IPs do host por padrão).
	Blocked func(netip.Addr) bool
	// TLS é a configuração TLS do cliente (padrão do Go quando nil).
	TLS *tls.Config
}

// NewClient cria o cliente HTTP do webhook: sem proxy, sem seguir redirecionamento e com um dial que resolve o
// nome, recusa os destinos que Blocked aponta e conecta ao IP conferido (o mesmo resolvido, o que também cobre DNS
// rebinding entre a conferência e a conexão).
func NewClient(c ClientConfig) *http.Client {
	if c.Lookup == nil {
		c.Lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if c.Blocked == nil {
		c.Blocked = blockedOrLocal
	}
	d := &net.Dialer{Timeout: RequestTimeout}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip}
		} else if ips, err = c.Lookup(ctx, host); err != nil {
			return nil, err
		}
		lastErr := fmt.Errorf("%w: %s resolves to no address", ErrBlockedDestination, host)
		for _, ip := range ips {
			if c.Blocked(ip) {
				lastErr = fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       c.TLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   RequestTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}
}

// noRedirect faz o 3xx ser a resposta final (contado como resposta sem nova tentativa).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

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
	// Client faz os envios (NewClient(ClientConfig{}) por padrão). Um cliente dado também deixa de seguir
	// redirecionamento: New troca o CheckRedirect de uma cópia dele.
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
	mu     sync.Mutex
	target Target
	// queue é a fila da chave (até QueueSize, em ordem); ready acorda o entregador quando entra um evento. A fila é
	// uma fatia sob mu, e não um canal, para o forget tirar dela os eventos de um prefixo sem perder a ordem.
	queue []*item
	ready chan struct{}
	// current é o evento que o entregador tirou da fila (em envio ou esperando nova tentativa).
	current   *item
	cancel    context.CancelFunc
	fullSince time.Time // início do período de fila cheia (zero = com espaço)
}

// item é um evento na fila: o corpo e o IP de origem do veredito (inválido = sem IP), para o forget.
type item struct {
	body []byte
	src  netip.Addr
	// forgotten é marcado pelo forget no evento que espera nova tentativa: o entregador desiste dele.
	forgotten atomic.Bool
}

// New cria o despachante.
func New(o Options) *Dispatcher {
	if o.Client == nil {
		o.Client = NewClient(ClientConfig{})
	} else {
		c := *o.Client
		c.CheckRedirect = noRedirect
		o.Client = &c
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
		w := &worker{target: t, ready: make(chan struct{}, 1), cancel: cancel}
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
	d.PublishFrom(class, site, netip.Addr{}, body)
}

// PublishFrom é o Publish com o IP de origem do veredito, guardado junto do evento para o Forget.
func (d *Dispatcher) PublishFrom(class, site string, src netip.Addr, body func() []byte) {
	src = src.Unmap()
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
		w.mu.Lock()
		if len(w.queue) >= QueueSize {
			d.opts.Count(metricDropped, 1)
			if w.fullSince.IsZero() {
				w.fullSince = d.opts.Now()
			}
			w.mu.Unlock()
			continue
		}
		w.queue = append(w.queue, &item{body: data, src: src})
		w.mu.Unlock()
		select {
		case w.ready <- struct{}{}:
		default:
		}
	}
}

// Forget tira das filas de todas as chaves os eventos cujo IP de origem está em p, inclusive o que espera nova
// tentativa, e devolve quantos saíram (ADR 0052 item 5, task 299). Um POST já em andamento não é cancelado: ele
// termina, mas não tenta de novo. Eventos sem IP de origem ficam.
func (d *Dispatcher) Forget(p netip.Prefix) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, w := range d.workers {
		w.mu.Lock()
		kept := w.queue[:0]
		for _, it := range w.queue {
			if it.src.IsValid() && p.Contains(it.src) {
				n++
				continue
			}
			kept = append(kept, it)
		}
		clear(w.queue[len(kept):])
		w.queue = kept
		if c := w.current; c != nil && c.src.IsValid() && p.Contains(c.src) && !c.forgotten.Swap(true) {
			n++
		}
		w.mu.Unlock()
	}
	return n
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
		w.mu.Lock()
		if ctx.Err() != nil {
			if n := len(w.queue); n > 0 {
				d.opts.Count(metricDropped, float64(n))
			}
			w.queue, w.current = nil, nil
			w.mu.Unlock()
			return
		}
		if len(w.queue) == 0 {
			w.mu.Unlock()
			select {
			case <-ctx.Done():
			case <-w.ready:
			}
			continue
		}
		it := w.queue[0]
		w.queue[0] = nil
		w.queue = w.queue[1:]
		w.current = it
		// a fila deixa de contar como cheia quando volta a ter metade livre
		if len(w.queue) < QueueSize/2 {
			w.fullSince = time.Time{}
		}
		t := w.target
		w.mu.Unlock()
		d.deliver(ctx, t, it)
		w.mu.Lock()
		w.current = nil
		w.mu.Unlock()
	}
}

// deliver faz o POST com as novas tentativas; um evento esquecido (Forget) não é mais enviado nem repetido.
func (d *Dispatcher) deliver(ctx context.Context, t Target, it *item) {
	for attempt := 0; ; attempt++ {
		if it.forgotten.Load() {
			return
		}
		retry := d.send(ctx, t, it.body)
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

// send faz uma tentativa e diz se vale tentar de novo (5xx, erro de rede ou status fora de 200–599).
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
	class := statusClass(resp.StatusCode)
	d.opts.Count(sentMetric(class), 1)
	return class == "5xx" || class == "error"
}

// statusClass reduz o status da resposta à classe usada no rótulo code (ADR 0073 item 5): o status cru é escolhido
// pelo servidor remoto e daria até ~900 séries e um oráculo no /metrics. 3xx é resposta final (o redirecionamento
// não é seguido); fora de 200–599 conta como error.
func statusClass(code int) string {
	switch {
	case code >= 200 && code <= 299:
		return "2xx"
	case code >= 300 && code <= 399:
		return "3xx"
	case code >= 400 && code <= 499:
		return "4xx"
	case code >= 500 && code <= 599:
		return "5xx"
	default:
		return "error"
	}
}

// sentMetric monta bot_webhook_sent_total{code="..."} (rótulos no formato da ADR 0056 item 4).
func sentMetric(code string) string {
	return fmt.Sprintf("%s{code=%q}", metricSent, strings.ToLower(code))
}
