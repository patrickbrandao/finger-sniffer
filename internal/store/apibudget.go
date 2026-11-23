package store

import (
	"context"
	"sync/atomic"
)

// Orçamento das respostas JSON finitas da API (ADR 0066 itens 1 e 2): jsonBudgetMax é a soma dos bytes das
// respostas montadas e ainda não escritas de getProbe, listConnections, getConnection, listDNSQueries e
// listStrayPackets; jsonResponseMax é o teto de uma resposta (getProbe marca truncated, as listas devolvem menos
// que limit; getConnection nunca corta).
const (
	jsonBudgetMax   = 256 << 20
	jsonResponseMax = 64 << 20
)

// errJSONBusy é o orçamento esgotado: 503 com Retry-After e {"error":"busy"} (ADR 0066 item 1).
var errJSONBusy = busyError{"busy"}

// jsonBudget conta os bytes reservados pelas respostas em andamento. Nunca bloqueia: quem não cabe desiste.
type jsonBudget struct {
	used atomic.Int64
	max  int64
}

func newJSONBudget(maxBytes int64) *jsonBudget { return &jsonBudget{max: maxBytes} }

// reserve abre a reserva de uma resposta, vazia; release devolve tudo o que ela somou.
func (b *jsonBudget) reserve() *jsonReservation { return &jsonReservation{b: b} }

// jsonReservation é a parte do orçamento de uma resposta. Nil é válido e não conta nada (chamadas de fora da API).
type jsonReservation struct {
	b *jsonBudget
	n int64
}

// add soma n bytes à reserva; se o orçamento passaria do teto, não soma e devolve errJSONBusy.
func (r *jsonReservation) add(n int) error {
	if r == nil || n <= 0 {
		return nil
	}
	if r.b.used.Add(int64(n)) > r.b.max {
		r.b.used.Add(-int64(n))
		return errJSONBusy
	}
	r.n += int64(n)
	return nil
}

// release devolve os bytes da reserva (no defer do handler, depois da escrita, da falha ou do prazo).
func (r *jsonReservation) release() {
	if r == nil || r.n == 0 {
		return
	}
	r.b.used.Add(-r.n)
	r.n = 0
}

type reservationKey struct{}

// withReservation leva a reserva da resposta às consultas pelo contexto da requisição.
func withReservation(ctx context.Context, r *jsonReservation) context.Context {
	return context.WithValue(ctx, reservationKey{}, r)
}

// reservationFrom devolve a reserva do contexto (nil sem reserva: a consulta não conta no orçamento).
func reservationFrom(ctx context.Context) *jsonReservation {
	r, _ := ctx.Value(reservationKey{}).(*jsonReservation)
	return r
}

// respCut acompanha o teto de bytes de uma resposta (jsonResponseMax) e soma cada item à reserva.
type respCut struct {
	res   *jsonReservation
	max   int64
	total int64
}

// take soma n bytes de um item: false se o item passaria do teto da resposta (o item fica de fora e a lista é
// cortada; o primeiro item sempre entra, para a resposta nunca sair vazia por causa de um registro grande);
// erro se o orçamento global não cabe.
func (c *respCut) take(n int) (bool, error) {
	if c.total > 0 && c.total+int64(n) > c.max {
		return false, nil
	}
	if err := c.res.add(n); err != nil {
		return false, err
	}
	c.total += int64(n)
	return true, nil
}
