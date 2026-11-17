package bot

import (
	"strconv"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// authBuckets são os limites (s) dos histogramas do forwardAuth (spec 018 RF-12): 1, 2, 5, 10, 20, 50, 100 e
// 200 ms.
var authBuckets = []float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2}

// histogram publica um histograma no heartbeat no formato da ADR 0056 item 4: as séries cumulativas
// `nome_bucket{le="..."}`, `nome_sum` e `nome_count`. Só os limites finitos: o bucket `+Inf` é igual a `_count` e
// não é enviado (ADR 0057 item 3).
type histogram struct {
	m       *service.Metrics
	buckets []string // chaves nome_bucket{le="..."}, na ordem de bounds
	bounds  []float64
	sum     string
	count   string
}

// newHistogram cria o histograma e publica as séries zeradas (aparecem desde o primeiro heartbeat).
func newHistogram(m *service.Metrics, name string, bounds []float64) *histogram {
	h := &histogram{m: m, bounds: bounds, sum: name + "_sum", count: name + "_count"}
	for _, b := range bounds {
		key := name + `_bucket{le="` + strconv.FormatFloat(b, 'g', -1, 64) + `"}`
		h.buckets = append(h.buckets, key)
		m.Add(key, 0)
	}
	m.Add(h.sum, 0)
	m.Add(h.count, 0)
	return h
}

// Observe soma uma medida: cada bucket com limite ≥ d, a soma e a contagem.
func (h *histogram) Observe(d time.Duration) {
	s := d.Seconds()
	for i, b := range h.bounds {
		if s <= b {
			h.m.Add(h.buckets[i], 1)
		}
	}
	h.m.Add(h.sum, s)
	h.m.Add(h.count, 1)
}
