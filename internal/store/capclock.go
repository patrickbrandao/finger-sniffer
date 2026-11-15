package store

// captureClock é o relógio de captura do ingest (ADR 0041 item 2): C = min(parede, T + (parede − P)), onde T é o
// maior instante de captura já processado (pacotes e eventos) e P o instante de parede em que ele foi processado.
// Com o ingest em dia, C ≈ parede; atrasado, C anda com o stream; sem tráfego, C anda com a parede. Todo prazo
// do ingest comparado a um instante de captura (lastSeen, closeAt, lingerUntil, ts de evento, validade de
// reserva) usa C, nunca a parede. Usado só pelo laço de ingest (sem trava).
type captureClock struct {
	t, p int64 // T e P, em ns; t == 0 = nada processado ainda (C = parede)
}

// observe registra um instante de captura ts processado no instante de parede wall.
func (c *captureClock) observe(ts, wall int64) {
	if ts > c.t {
		c.t, c.p = ts, wall
	}
}

// at devolve C no instante de parede wall.
func (c *captureClock) at(wall int64) int64 {
	if c.t == 0 {
		return wall
	}
	return min(wall, c.t+(wall-c.p))
}
