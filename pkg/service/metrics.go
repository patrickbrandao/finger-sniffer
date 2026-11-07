package service

import (
	"maps"
	"sync"
)

// Metrics guarda contadores e medidas do serviço. Elas vão no heartbeat e o store as expõe no /metrics
// agregado (spec 004 RF-10).
type Metrics struct {
	mu   sync.Mutex
	vals map[string]float64
}

// NewMetrics cria um registro vazio.
func NewMetrics() *Metrics { return &Metrics{vals: map[string]float64{}} }

// Add soma delta ao contador name.
func (m *Metrics) Add(name string, delta float64) {
	m.mu.Lock()
	m.vals[name] += delta
	m.mu.Unlock()
}

// Set define o valor da medida name.
func (m *Metrics) Set(name string, v float64) {
	m.mu.Lock()
	m.vals[name] = v
	m.mu.Unlock()
}

// Get devolve o valor atual (0 se ausente).
func (m *Metrics) Get(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vals[name]
}

// Snapshot devolve uma cópia de todos os valores.
func (m *Metrics) Snapshot() map[string]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.vals)
}
