package store

import (
	"math"
	"math/rand/v2"
	"testing"
)

// simClock gera n amostras de um relógio de hz Hz enviadas ao longo de dur (s), com atraso de rede no intervalo
// [0, jitter] (s) somado ao instante de captura; devolve a análise alimentada.
func simClock(rng *rand.Rand, hz, dur, jitter float64, n int) *analysis {
	a := newAnalysis()
	v0 := rng.Uint32()
	for i := range n {
		send := dur * float64(i) / float64(n-1)
		arrive := send + 0.020 + jitter*rng.Float64()
		a.addTS(base+int64(arrive*1e9), v0+uint32(math.Floor(hz*send)))
	}
	return a
}

// TestTSClockHzShortJitter: 1000 Hz, jitter de ±15 ms (faixa de 30 ms) e conexão de 150 ms: a estimativa
// publicada fica a até 5% do real, ou sai nula (task 201).
func TestTSClockHzShortJitter(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // teste determinístico
	published := 0
	for range 2000 {
		a := simClock(rng, 1000, 0.150, 0.030, 10)
		hz := a.publishedHz()
		if hz == 0 {
			continue
		}
		published++
		if math.Abs(hz-1000) > 50 {
			t.Fatalf("published %.2f Hz, more than 5%% off", hz)
		}
	}
	t.Logf("published %d of 2000", published)
}

// TestTSClockHzStable: sem jitter relevante, a conexão curta publica a frequência; com 2 s, mesmo o jitter de
// 30 ms dá uma estimativa a até 5%.
func TestTSClockHzStable(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // teste determinístico
	for _, c := range []struct {
		hz, dur, jitter float64
		n               int
	}{
		{1000, 0.150, 0.0005, 10},
		{250, 0.5, 0.001, 10},
		{1000, 2, 0.030, 40},
		{100, 3, 0.010, 30},
	} {
		nulls := 0
		for range 200 {
			a := simClock(rng, c.hz, c.dur, c.jitter, c.n)
			hz := a.publishedHz()
			if hz == 0 {
				nulls++
				continue
			}
			if math.Abs(hz-c.hz) > c.hz*tsMaxRelErr {
				t.Fatalf("%+v: %.2f Hz", c, hz)
			}
			// o agrupamento continua com estimativa (±10%)
			if g := a.clockHz(); math.Abs(g-c.hz) > c.hz*0.1 {
				t.Fatalf("%+v: group estimate %.2f", c, g)
			}
		}
		if nulls > 20 {
			t.Errorf("%+v: %d of 200 null", c, nulls)
		}
	}
}

// TestTSClockHzDelayedFirst: o primeiro segmento atrasado 25 ms numa conexão de 150 ms (o caso do e2e da v0.2.1,
// que dava ~1170 Hz pelas pontas) não publica um valor fora dos 5%.
func TestTSClockHzDelayedFirst(t *testing.T) {
	a := newAnalysis()
	v0 := uint32(123456)
	for i := range 10 {
		send := 0.150 * float64(i) / 9
		arrive := send + 0.020
		if i == 0 {
			arrive += 0.025
		}
		a.addTS(base+int64(arrive*1e9), v0+uint32(1000*send))
	}
	ends := float64(a.tsLast.v-a.tsFirst.v) / (float64(a.tsLast.t-a.tsFirst.t) / 1e9)
	if math.Abs(ends-1000) < 100 {
		t.Fatalf("scenario must break the endpoints estimate: %.2f", ends)
	}
	if hz := a.publishedHz(); hz != 0 && math.Abs(hz-1000) > 50 {
		t.Fatalf("published %.2f Hz", hz)
	}
}

// TestTSHullBounded: amostras numa curva convexa não crescem as envoltórias além do teto, e a estimativa deixa
// de ser publicada.
func TestTSHullBounded(t *testing.T) {
	a := newAnalysis()
	for i := range 1000 {
		x := float64(i) / 1000
		a.addTS(base+int64(x*1e9), uint32(1000*x+500*x*x))
	}
	if len(a.tsHull.upper) > tsHullMax || len(a.tsHull.lower) > tsHullMax {
		t.Fatalf("hull %d/%d", len(a.tsHull.upper), len(a.tsHull.lower))
	}
	if a.publishedHz() != 0 {
		t.Fatal("overflowed hull must not publish")
	}
}
