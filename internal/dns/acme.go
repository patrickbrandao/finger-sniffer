package dns

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Subjects do request/reply do DNS-01 (NATS core, fora do stream: ADR 0017).
const (
	SubjectACMESet   = event.SubjectDNSACMESet
	SubjectACMEClear = event.SubjectDNSACMEClear
)

// Erros das operações do TXT ACME (vão no campo error da resposta).
var (
	errNotACMEName = errors.New("name is not _acme-challenge.<name> inside the zone")
	errBadValue    = errors.New("value must have 1 to 255 bytes")
)

// ACMERequest é o pedido de fs.v1.dns.acme.set|clear (asyncapi ACMERequest).
type ACMERequest = event.ACMERequest

// ACMEReply é a resposta (asyncapi ACMEReply). Error é null quando ok.
type ACMEReply = event.ACMEReply

// HandleACME processa um pedido cru do subject dado e devolve a resposta JSON.
func (z *Zone) HandleACME(subject string, data []byte) []byte {
	var req ACMERequest
	var err error
	if e := json.Unmarshal(data, &req); e != nil {
		err = fmt.Errorf("invalid request: %w", e)
	} else {
		switch subject {
		case SubjectACMESet:
			err = z.SetACME(req.Name, req.Value)
		case SubjectACMEClear:
			err = z.ClearACME(req.Name, req.Value)
		default:
			err = fmt.Errorf("unknown subject %q", subject)
		}
	}
	reply := ACMEReply{OK: err == nil}
	if err != nil {
		s := err.Error()
		reply.Error = &s
	}
	out, _ := json.Marshal(reply)
	return out
}

// SubscribeACME assina os dois subjects do DNS-01 na conexão. O log recebe cada operação.
func SubscribeACME(nc *nats.Conn, z *Zone, logf func(msg string, args ...any)) ([]*nats.Subscription, error) {
	var subs []*nats.Subscription
	for _, subj := range []string{SubjectACMESet, SubjectACMEClear} {
		sub, err := nc.Subscribe(subj, func(m *nats.Msg) {
			out := z.HandleACME(m.Subject, m.Data)
			if logf != nil {
				logf("acme request", "subject", m.Subject, "reply", string(out))
			}
			if m.Reply != "" {
				_ = m.Respond(out)
			}
		})
		if err != nil {
			for _, s := range subs {
				_ = s.Unsubscribe()
			}
			return nil, fmt.Errorf("dns: subscribe %s: %w", subj, err)
		}
		subs = append(subs, sub)
	}
	return subs, nil
}
