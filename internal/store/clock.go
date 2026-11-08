package store

import (
	"math"
	"sort"
	"time"
)

// Agrupamento por relógio de timestamps TCP (spec 013 RF-10): conexões cujo TSval cai na mesma reta
// TSval × tempo vêm do mesmo relógio, ou seja, do mesmo host — inclusive por IPs de origem diferentes.

const (
	clockKeep      = 20 * time.Minute // depois disso um relógio sem conexões novas é esquecido
	clockTolerance = 0.05             // segundos de folga na previsão do TSval (deriva e quantização)
)

// nominalHz são as frequências comuns de TSval; a estimativa é arredondada para a mais próxima (±10%).
var nominalHz = []float64{1, 2, 4, 8, 10, 16, 32, 64, 100, 128, 200, 250, 256, 300, 500, 512, 1000, 1024}

func snapHz(hz float64) float64 {
	for _, n := range nominalHz {
		if math.Abs(hz-n) <= n*0.1 {
			return n
		}
	}
	return hz
}

type clockEntry struct {
	id   string
	hz   float64
	t0   int64  // instante de captura da última amostra (ns)
	v0   uint32 // TSval da última amostra
	last int64
}

type clockRegistry struct {
	entries []*clockEntry
}

// assign devolve o grupo de relógio da conexão. Com register, uma conexão sem grupo conhecido e com
// frequência estimável cria um grupo novo, e o grupo que casou passa a usar a amostra mais recente.
func (r *clockRegistry) assign(c *conn, register bool) *string {
	a := c.ana
	if a.tsCount == 0 {
		return nil
	}
	s := a.tsLast
	hz := a.clockHz()
	if hz > 0 {
		hz = snapHz(hz)
	}
	r.prune(s.t)
	for _, e := range r.entries {
		if hz > 0 && math.Abs(hz-e.hz) > e.hz*0.1 {
			continue
		}
		pred := float64(e.v0) + e.hz*float64(s.t-e.t0)/1e9
		diff := float64(int32(s.v - uint32(int64(pred)))) //nolint:gosec // diferença com wrap de 32 bits
		if math.Abs(diff) <= e.hz*clockTolerance+2 {
			if register && s.t >= e.t0 {
				e.t0, e.v0, e.last = s.t, s.v, s.t
			}
			id := e.id
			return &id
		}
	}
	if hz == 0 || !register {
		return nil
	}
	e := &clockEntry{id: "clk-" + c.id, hz: hz, t0: s.t, v0: s.v, last: s.t}
	r.entries = append(r.entries, e)
	id := e.id
	return &id
}

func (r *clockRegistry) prune(now int64) {
	out := r.entries[:0]
	for _, e := range r.entries {
		if now-e.last <= clockKeep.Nanoseconds() {
			out = append(out, e)
		}
	}
	r.entries = out
}

// cookieSample é uma leitura do contador TcpExt SyncookiesSent.
type cookieSample struct {
	t int64
	v int64
}

// cookieHistory guarda as leituras periódicas do contador (uma por segundo).
type cookieHistory struct {
	samples []cookieSample
}

func (h *cookieHistory) add(t, v int64) {
	h.samples = append(h.samples, cookieSample{t, v})
	cut := t - clockKeep.Nanoseconds()
	i := sort.Search(len(h.samples), func(i int) bool { return h.samples[i].t >= cut })
	h.samples = h.samples[i:]
}

// rose informa se o contador subiu no intervalo de leituras que contém ts.
func (h *cookieHistory) rose(ts int64) bool {
	i := sort.Search(len(h.samples), func(i int) bool { return h.samples[i].t > ts })
	if i == 0 || i == len(h.samples) {
		return false
	}
	return h.samples[i].v > h.samples[i-1].v
}
