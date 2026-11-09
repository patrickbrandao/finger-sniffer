package loadstat

import (
	"sync"
	"time"
)

// ClockSample é uma medição do deslocamento entre o relógio da vps602 e o local.
type ClockSample struct {
	Local    int64 `json:"local"`     // instante local da medição (ns)
	OffsetNs int64 `json:"offset_ns"` // vps602 − local
	RTTNs    int64 `json:"rtt_ns"`    // ida e volta da medição
	Accepted bool  `json:"accepted"`
}

// ClockTrack acompanha o deslocamento ao longo da carga. O timesyncd da vps602 corrige o relógio por
// rampa (até 500 ppm, ~0,3 s em 10 min), então um deslocamento fixo medido no início distorce o atraso do
// feed. Cada medição nova substitui a anterior se a ida e volta dela não passar de 2× a melhor vista
// (ou da melhor + 10 ms): medições com ida e volta longa têm erro maior que a própria rampa.
type ClockTrack struct {
	mu      sync.Mutex
	offset  time.Duration
	bestRTT time.Duration
	samples []ClockSample
}

// NewClockTrack começa com a medição do início da carga.
func NewClockTrack(local time.Time, offset, rtt time.Duration) *ClockTrack {
	return &ClockTrack{offset: offset, bestRTT: rtt, samples: []ClockSample{{local.UnixNano(), int64(offset), int64(rtt), true}}}
}

// Update registra uma medição e diz se ela passou a valer.
func (c *ClockTrack) Update(local time.Time, offset, rtt time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	lim := max(2*c.bestRTT, c.bestRTT+10*time.Millisecond)
	ok := rtt <= lim
	if ok {
		c.offset = offset
		c.bestRTT = min(c.bestRTT, rtt)
	}
	c.samples = append(c.samples, ClockSample{local.UnixNano(), int64(offset), int64(rtt), ok})
	return ok
}

// Offset devolve o deslocamento vigente.
func (c *ClockTrack) Offset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}

// Samples devolve uma cópia das medições.
func (c *ClockTrack) Samples() []ClockSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ClockSample(nil), c.samples...)
}

// OffsetRange devolve o menor e o maior deslocamento aceito.
func (c *ClockTrack) OffsetRange() (lo, hi time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	first := true
	for _, s := range c.samples {
		if !s.Accepted {
			continue
		}
		o := time.Duration(s.OffsetNs)
		if first || o < lo {
			lo = o
		}
		if first || o > hi {
			hi = o
		}
		first = false
	}
	return lo, hi
}
