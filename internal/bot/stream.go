package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Limites do feed SSE (spec 020 RF-05 e RF-04).
const (
	MaxStreamClients = 64
	streamQueue      = 1024
	streamPing       = 15 * time.Second
)

// errStreamFull indica o teto de clientes do feed.
var errStreamFull = errors.New("bot: too many stream clients")

// Hub distribui os vereditos aos clientes do feed: sem replay, fila por cliente com descarte contado e evento
// `stream.dropped` (spec 020 RF-05).
type Hub struct {
	mu      sync.Mutex
	clients map[*streamClient]struct{}
	max     int
	ping    time.Duration
	sink    func(v *Verdict, site string) // saída extra (webhook); não pode bloquear
}

type streamClient struct {
	domains []string // nil = todos (9003 sem chave)
	// keyHash é o hash da chave que abriu o feed (hasKey false na 9003 sem chave): a revogação ou a rotação dela
	// encerra o feed na recarga seguinte das chaves (dropRevoked, task 368). cancel encerra o serve.
	keyHash [32]byte
	hasKey  bool
	cancel  context.CancelFunc
	classes map[string]bool
	site    string
	queue   chan *Verdict
	mu      sync.Mutex
	dropped int
}

// NewHub cria o distribuidor.
func NewHub() *Hub {
	return &Hub{clients: map[*streamClient]struct{}{}, max: MaxStreamClients, ping: streamPing}
}

// SetSink liga uma saída que recebe cada veredito publicado com o site normalizado (o despachante do webhook).
// A saída não pode bloquear: o SSE espera por ela.
func (h *Hub) SetSink(f func(v *Verdict, site string)) {
	h.mu.Lock()
	h.sink = f
	h.mu.Unlock()
}

// Publish entrega o veredito a cada cliente cujo filtro aceita; fila cheia descarta e conta.
func (h *Hub) Publish(v *Verdict) {
	site := ""
	if v.Subject.Site != nil {
		site = NormalizeSite(*v.Subject.Site)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sink != nil {
		h.sink(v, site)
	}
	for c := range h.clients {
		if !c.accepts(v.Class, site) {
			continue
		}
		select {
		case c.queue <- v:
		default:
			c.mu.Lock()
			c.dropped++
			c.mu.Unlock()
		}
	}
}

func (c *streamClient) accepts(class, site string) bool {
	if c.domains != nil && !MatchDomain(c.domains, site) {
		return false
	}
	if c.site != "" && c.site != site {
		return false
	}
	return len(c.classes) == 0 || c.classes[class]
}

func (h *Hub) add(c *streamClient) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= h.max {
		return errStreamFull
	}
	h.clients[c] = struct{}{}
	return nil
}

func (h *Hub) remove(c *streamClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// dropRevoked encerra os clientes abertos com uma chave que não está mais ativa (revogada, ou a antiga de uma
// rotação, que troca o hash): saem do Hub na hora, sem receber mais vereditos, e o serve deles termina; devolve
// quantos saíram. Chamado depois de cada recarga das chaves.
func (h *Hub) dropRevoked(active func(hash [32]byte) bool) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for c := range h.clients {
		if !c.hasKey || active(c.keyHash) {
			continue
		}
		delete(h.clients, c)
		if c.cancel != nil {
			c.cancel()
		}
		n++
	}
	return n
}

// Clients conta os clientes conectados.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// serve atende um cliente SSE até ele sair ou ctx acabar.
func (h *Hub) serve(ctx context.Context, w http.ResponseWriter, c *streamClient) {
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if fl != nil {
		fl.Flush()
	}
	t := time.NewTicker(h.ping)
	defer t.Stop()
	send := func(kind string, ev VerdictEvent) error {
		data, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data); err != nil {
			return err
		}
		if fl != nil {
			fl.Flush()
		}
		return nil
	}
	for {
		c.mu.Lock()
		dropped := c.dropped
		c.dropped = 0
		c.mu.Unlock()
		if dropped > 0 {
			if send("stream.dropped", VerdictEvent{Kind: "stream.dropped", Ts: event.FormatTime(time.Now()), Dropped: dropped}) != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case v := <-c.queue:
			if send("verdict", VerdictEvent{Kind: "verdict", Ts: v.Ts, Verdict: v}) != nil {
				return
			}
		case <-t.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}
