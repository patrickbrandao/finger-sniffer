package store

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// reservationTTL é quanto vale um conn_id reservado sem conexão (ADR 0017).
const reservationTTL = 30 * time.Second

// reservation é um conn_id prometido a uma 5-tupla antes de o store ver os pacotes dela.
type reservation struct {
	id      string
	expires int64 // ns, no mesmo relógio dos pacotes (tempo real do kernel)
}

// connID responde fs.v1.store.conn_id: o ID da conexão aberta com a 5-tupla ou um ULID reservado por 30 s.
// now é o instante de chegada da requisição; ts é o instante do accept informado pelo produtor.
func (t *flowTable) connID(l4 uint8, client, server netip.AddrPort, ts, now int64) (id string, reserved bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := keyOf(l4, client, server)
	// Conexão já fechando é a anterior com a mesma 5-tupla: a nova (do accept) ainda vai começar.
	if c := t.conns[k]; c != nil && !c.closing() {
		return c.id, false
	}
	if r, ok := t.reserved[k]; ok && now <= r.expires {
		return r.id, true
	}
	if ts <= 0 {
		ts = now
	}
	r := reservation{id: t.newID(ts), expires: now + reservationTTL.Nanoseconds()}
	t.reserved[k] = r
	return r.id, true
}

// takeReserved devolve o ID reservado para a 5-tupla (e consome a reserva) ou gera um novo. Chamado com a trava.
func (t *flowTable) takeReserved(k flowKey, ts int64) string {
	if r, ok := t.reserved[k]; ok {
		delete(t.reserved, k)
		if ts <= r.expires {
			return r.id
		}
	}
	return t.newID(ts)
}

// expireReservations apaga as reservas vencidas. Chamado com a trava.
func (t *flowTable) expireReservations(now int64) {
	for k, r := range t.reserved {
		if now > r.expires {
			delete(t.reserved, k)
		}
	}
}

// reservations devolve quantas reservas estão pendentes.
func (t *flowTable) reservations() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.reserved)
}

// parseConnIDRequest valida a requisição e devolve a 5-tupla e o instante do accept.
func parseConnIDRequest(data []byte) (l4 uint8, client, server netip.AddrPort, ts int64, err error) {
	var req event.ConnIDRequest
	if err = json.Unmarshal(data, &req); err != nil {
		return 0, client, server, 0, fmt.Errorf("conn_id: %w", err)
	}
	switch req.Flow.L4 {
	case "tcp":
		l4 = protoTCP
	case "udp":
		l4 = protoUDP
	default:
		return 0, client, server, 0, fmt.Errorf("conn_id: l4 %q", req.Flow.L4)
	}
	if client, err = addrPort(req.Flow.SrcIP, req.Flow.SrcPort); err != nil {
		return 0, client, server, 0, err
	}
	if server, err = addrPort(req.Flow.DstIP, req.Flow.DstPort); err != nil {
		return 0, client, server, 0, err
	}
	if req.Ts != "" {
		if when, perr := time.Parse(time.RFC3339Nano, req.Ts); perr == nil {
			ts = when.UnixNano()
		}
	}
	return l4, client, server, ts, nil
}

// addrPort converte IP e porta; IPv4 mapeado em IPv6 (socket dual-stack) vira IPv4, como nos pacotes.
func addrPort(ip string, port int) (netip.AddrPort, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("conn_id: ip %q: %w", ip, err)
	}
	if port <= 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("conn_id: port %d", port)
	}
	return netip.AddrPortFrom(a.Unmap().WithZone(""), uint16(port)), nil //nolint:gosec // porta validada acima
}

// handleConnID atende uma mensagem de fs.v1.store.conn_id. Requisição inválida fica sem resposta (o cliente
// segue com conn_id: unknown depois do timeout).
func (s *Store) handleConnID(m *nats.Msg) {
	l4, client, server, ts, err := parseConnIDRequest(m.Data)
	if err != nil {
		s.svc.Log.Warn("invalid conn_id request", "err", err)
		s.svc.Metrics.Add("store_conn_id_invalid_total", 1)
		return
	}
	id, reserved := s.ingest.flows.connID(l4, client, server, ts, time.Now().UnixNano())
	data, _ := json.Marshal(event.ConnIDReply{ConnID: id, Reserved: reserved})
	if err := m.Respond(data); err != nil {
		s.svc.Log.Warn("conn_id reply", "err", err)
		return
	}
	s.svc.Metrics.Add("store_conn_id_requests_total", 1)
}
