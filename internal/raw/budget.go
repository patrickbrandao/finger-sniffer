package raw

import (
	"sync/atomic"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Orçamento de entrada do raw (spec 006 RF-07b, ADR 0070 item 8).
const (
	// InputBudget é o orçamento interno constante de memória de entrada do raw (sem variável de ambiente).
	InputBudget int64 = 64 << 20
	// MetricInputBudgetUsed é o gauge do que está reservado agora.
	MetricInputBudgetUsed = "raw_input_budget_used_bytes"
	// MetricInputBudgetDenied conta as recusas por falta de orçamento (ClientHello: sessão fechada antes do
	// handshake). Listas cortadas são só de análise e não contam (ADR 0070 item 2).
	MetricInputBudgetDenied = "raw_input_budget_denied_total"
	// MetricPanics conta os pânicos recuperados numa sessão (ADR 0070 item 6).
	MetricPanics = "raw_panics_total"

	// helloReserve é a reserva da captura do ClientHello até o fim do handshake: a mensagem remontada até
	// tlsparse.MaxClientHelloLen mais até 16 KiB de registros crus (ADR 0070 itens 7 e 8).
	helloReserve = int64(tlsparse.MaxClientHelloLen) + 16<<10
	// fixedTimed é quantas entradas de reads_in/writes_out são retenção fixa (16 KiB cada lista); acima
	// disso cada crescimento reserva do orçamento (spec 006 RF-06).
	fixedTimed = 1024
	// timedSize é o tamanho de uma entrada TimedLength ([2]float64).
	timedSize = 16
)

// inputBudget é o orçamento compartilhado pelas sessões.
type inputBudget struct {
	limit   int64
	used    atomic.Int64
	metrics *service.Metrics
}

func newInputBudget(limit int64, m *service.Metrics) *inputBudget {
	b := &inputBudget{limit: limit, metrics: m}
	m.Set(MetricInputBudgetUsed, 0)
	m.Add(MetricInputBudgetDenied, 0)
	return b
}

// reserve tenta reservar n bytes; sem espaço devolve false e, com deny, conta a recusa.
func (b *inputBudget) reserve(n int64, deny bool) bool {
	for {
		cur := b.used.Load()
		if cur+n > b.limit {
			if deny {
				b.metrics.Add(MetricInputBudgetDenied, 1)
			}
			return false
		}
		if b.used.CompareAndSwap(cur, cur+n) {
			b.metrics.Set(MetricInputBudgetUsed, float64(cur+n))
			return true
		}
	}
}

func (b *inputBudget) release(n int64) {
	if n <= 0 {
		return
	}
	b.metrics.Set(MetricInputBudgetUsed, float64(b.used.Add(-n)))
}

func (b *inputBudget) inUse() int64 { return b.used.Load() }

// hold soma as reservas de uma sessão, para devolvê-las todas em defer em qualquer saída.
type hold struct {
	b    *inputBudget
	held int64
}

func (h *hold) reserve(n int64, deny bool) bool {
	if !h.b.reserve(n, deny) {
		return false
	}
	h.held += n
	return true
}

func (h *hold) release(n int64) {
	n = min(n, h.held)
	h.held -= n
	h.b.release(n)
}

func (h *hold) releaseAll() { h.release(h.held) }
