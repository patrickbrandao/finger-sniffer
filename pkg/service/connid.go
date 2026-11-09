package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// ConnIDTimeout é a espera máxima pela resposta do store (ADR 0017).
const ConnIDTimeout = 250 * time.Millisecond

// ConnIDUnknown é o valor que o produtor põe no lugar do conn_id quando o store não respondeu a tempo.
const ConnIDUnknown = "unknown"

// ErrConnIDReply indica uma resposta do store sem conn_id válido.
var ErrConnIDReply = errors.New("service: invalid conn_id reply")

// connIDRequester é o pedaço da nats.Conn usado por RequestConnID.
type connIDRequester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// RequestConnID pede ao store o conn_id da 5-tupla (fs.v1.store.conn_id, ADR 0017). ts é o instante do accept.
// Sem prazo no ctx, espera no máximo ConnIDTimeout. Em erro, quem chama usa ConnIDUnknown.
func RequestConnID(ctx context.Context, nc connIDRequester, flow event.Flow, ts time.Time) (event.ConnIDReply, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnIDTimeout)
		defer cancel()
	}
	data, err := json.Marshal(event.ConnIDRequest{Flow: flow, Ts: event.FormatTime(ts)})
	if err != nil {
		return event.ConnIDReply{}, err
	}
	msg, err := nc.RequestWithContext(ctx, event.SubjectStoreConnID, data)
	if err != nil {
		return event.ConnIDReply{}, fmt.Errorf("service: conn_id request: %w", err)
	}
	var rep event.ConnIDReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		return event.ConnIDReply{}, fmt.Errorf("%w: %w", ErrConnIDReply, err)
	}
	if len(rep.ConnID) != 26 {
		return event.ConnIDReply{}, fmt.Errorf("%w: %q", ErrConnIDReply, rep.ConnID)
	}
	return rep, nil
}
