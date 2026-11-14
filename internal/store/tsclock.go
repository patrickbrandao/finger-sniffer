package store

import "math"

// Estimador da frequência do TSval do cliente (spec 013 RF-10, task 201).
//
// O TSval é carimbado no envio e o instante de captura é o da chegada: chegada = envio + atraso, com atraso ≥ o
// mínimo do caminho. No plano (tempo de captura, TSval) a reta verdadeira fica acima de todos os pontos (o atraso
// só empurra o ponto para a direita, isto é, para baixo da reta). A estimativa é a reta mais baixa que fica acima de
// todos os pontos no instante médio das amostras (programa linear clássico do fingerprinting de relógio): uma aresta
// da envoltória superior. Só a primeira e a última amostra, como antes, viravam 10–20% de erro com alguns ms de
// jitter numa conexão de 150 ms.
//
// Limite do erro: com J = o maior atraso extra de uma amostra em relação à reta estimada e D = a duração das
// amostras, o erro relativo da inclinação é no máximo J / (min(α, 1−α)·D), em que α é a posição do instante médio
// dentro de D. A frequência só é publicada com esse limite ≤ tsMaxRelErr; acima, ts_clock_hz sai nulo.

const (
	// tsMaxRelErr é o erro relativo máximo aceito para publicar ts_clock_hz.
	tsMaxRelErr = 0.05
	// tsHullMax limita os vértices guardados por envoltória (memória por conexão); passou disso, a estimativa
	// continua para o agrupamento, mas não é publicada.
	tsHullMax = 64
)

// tsPoint é uma amostra relativa à primeira: x em ns de captura, y em ticks do TSval.
type tsPoint struct{ x, y float64 }

// tsHulls guarda as envoltórias superior e inferior das amostras do cliente, incrementalmente.
type tsHulls struct {
	upper, lower []tsPoint
	n            int
	sumX         float64
	overflow     bool
}

func cross(o, a, b tsPoint) float64 { return (a.x-o.x)*(b.y-o.y) - (a.y-o.y)*(b.x-o.x) }

// add acrescenta uma amostra (x crescente; fora de ordem é ignorada).
func (h *tsHulls) add(p tsPoint) {
	if len(h.upper) > 0 && p.x < h.upper[len(h.upper)-1].x {
		return
	}
	h.n++
	h.sumX += p.x
	for len(h.upper) >= 2 && cross(h.upper[len(h.upper)-2], h.upper[len(h.upper)-1], p) >= 0 {
		h.upper = h.upper[:len(h.upper)-1]
	}
	h.upper = append(h.upper, p)
	for len(h.lower) >= 2 && cross(h.lower[len(h.lower)-2], h.lower[len(h.lower)-1], p) <= 0 {
		h.lower = h.lower[:len(h.lower)-1]
	}
	h.lower = append(h.lower, p)
	if len(h.upper) > tsHullMax {
		h.upper = append(h.upper[:1], h.upper[2:]...)
		h.overflow = true
	}
	if len(h.lower) > tsHullMax {
		h.lower = append(h.lower[:1], h.lower[2:]...)
		h.overflow = true
	}
}

// estimate devolve a frequência (Hz) e o limite do erro relativo; hz = 0 sem estimativa.
func (h *tsHulls) estimate() (hz, relErr float64) {
	if len(h.upper) < 2 {
		return 0, math.Inf(1)
	}
	first, last := h.upper[0], h.upper[len(h.upper)-1]
	d := last.x - first.x
	if d <= 0 {
		return 0, math.Inf(1)
	}
	mean := h.sumX / float64(h.n)
	// aresta da envoltória superior que contém o instante médio
	i := 0
	for i < len(h.upper)-2 && h.upper[i+1].x < mean {
		i++
	}
	a, b := h.upper[i], h.upper[i+1]
	if b.x <= a.x {
		return 0, math.Inf(1)
	}
	slope := (b.y - a.y) / (b.x - a.x) // ticks por ns
	if slope <= 0 {
		return 0, math.Inf(1)
	}
	// maior atraso extra (em ns) em relação à reta: está num vértice da envoltória inferior
	j := 0.0
	for _, p := range h.lower {
		line := a.y + slope*(p.x-a.x)
		j = max(j, (line-p.y)/slope)
	}
	alpha := (mean - first.x) / d
	relErr = math.Inf(1)
	if m := min(alpha, 1-alpha); m > 0 {
		relErr = j / (m * d)
	}
	if h.overflow {
		relErr = math.Inf(1)
	}
	return slope * 1e9, relErr
}
