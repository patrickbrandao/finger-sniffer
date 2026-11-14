package web

import (
	"sync/atomic"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Orçamento global de memória de entrada (spec 005 RF-12, ADR 0033).
const (
	// DefaultInputBudget é o padrão de FS_WEB_INPUT_BUDGET (40 MiB).
	DefaultInputBudget = 40 << 20
	// MinInputBudget e MaxInputBudget são os limites aceitos; fora deles o web não sobe.
	MinInputBudget = 8 << 20
	MaxInputBudget = 64 << 20

	// MetricInputBudgetUsed é o gauge dos bytes reservados agora; MetricInputBudgetDenied conta as recusas.
	MetricInputBudgetUsed   = "web_input_budget_used_bytes"
	MetricInputBudgetDenied = "web_input_budget_denied_total"
)

// inputBudget é o contador único do processo: todo caminho que retém bytes recebidos do cliente enquanto
// espera o resto reserva antes de reter e devolve ao soltar. A reserva nunca bloqueia: ou cabe, ou o
// chamador dá a resposta de estouro do seu protocolo (431, 503, H3_EXCESSIVE_LOAD, fields_truncated).
type inputBudget struct {
	limit   int64
	used    atomic.Int64
	metrics *service.Metrics
}

// newInputBudget cria o orçamento; limit <= 0 usa o padrão.
func newInputBudget(limit int64, m *service.Metrics) *inputBudget {
	if limit <= 0 {
		limit = DefaultInputBudget
	}
	b := &inputBudget{limit: limit, metrics: m}
	if m != nil {
		m.Set(MetricInputBudgetUsed, 0)
		m.Add(MetricInputBudgetDenied, 0)
	}
	return b
}

// reserve tenta reservar n bytes; false quando não cabe (conta a recusa).
func (b *inputBudget) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := b.used.Load()
		if cur+n > b.limit {
			if b.metrics != nil {
				b.metrics.Add(MetricInputBudgetDenied, 1)
			}
			return false
		}
		if b.used.CompareAndSwap(cur, cur+n) {
			b.publish(cur + n)
			return true
		}
	}
}

// release devolve n bytes reservados.
func (b *inputBudget) release(n int64) {
	if n <= 0 {
		return
	}
	b.publish(b.used.Add(-n))
}

// inUse devolve os bytes reservados agora.
func (b *inputBudget) inUse() int64 { return b.used.Load() }

func (b *inputBudget) publish(v int64) {
	if b.metrics != nil {
		b.metrics.Set(MetricInputBudgetUsed, float64(v))
	}
}

// budgetHold é a parte do orçamento retida por um dono (requisição, conexão, sessão), com teto local
// opcional (limit > 0). É seguro para uso concorrente (os streams h3 de uma conexão dividem um hold).
type budgetHold struct {
	b     *inputBudget
	limit int64
	held  atomic.Int64
}

// newHold cria um hold com teto local limit (0 = só o global).
func (b *inputBudget) newHold(limit int64) *budgetHold {
	return &budgetHold{b: b, limit: limit}
}

// reserve tenta reservar n bytes no teto local e no global; false sem reservar nada.
func (h *budgetHold) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		cur := h.held.Load()
		if h.limit > 0 && cur+n > h.limit {
			if h.b.metrics != nil {
				h.b.metrics.Add(MetricInputBudgetDenied, 1)
			}
			return false
		}
		if h.held.CompareAndSwap(cur, cur+n) {
			break
		}
	}
	if !h.b.reserve(n) {
		h.held.Add(-n)
		return false
	}
	return true
}

// release devolve n bytes do hold (no máximo o que ele retém).
func (h *budgetHold) release(n int64) {
	for n > 0 {
		cur := h.held.Load()
		d := min(n, cur)
		if d <= 0 {
			return
		}
		if h.held.CompareAndSwap(cur, cur-d) {
			h.b.release(d)
			return
		}
	}
}

// releaseAll devolve tudo o que o hold retém; idempotente.
func (h *budgetHold) releaseAll() {
	if n := h.held.Swap(0); n > 0 {
		h.b.release(n)
	}
}

// inUse devolve os bytes retidos pelo hold.
func (h *budgetHold) inUse() int64 { return h.held.Load() }
