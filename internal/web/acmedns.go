package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// DefaultACMEDNSTimeout é a espera máxima pela resposta do dns a cada fs.v1.dns.acme.set|clear.
const DefaultACMEDNSTimeout = 5 * time.Second

// natsRequester é o pedaço da nats.Conn usado pelo provedor DNS-01.
type natsRequester interface {
	RequestWithContext(ctx context.Context, subj string, data []byte) (*nats.Msg, error)
}

// natsDNSProvider é o provedor libdns do DNS-01 (spec 015 RF-02): em vez de falar com um provedor externo, pede
// ao nosso dns autoritativo, por request/reply NATS core, que acrescente (set) ou remova (clear) o valor TXT de
// _acme-challenge.<nome>. Só TXT é aceito.
type natsDNSProvider struct {
	nc      natsRequester
	timeout time.Duration
}

// Garantia de interface (certmagic.DNSProvider = RecordAppender + RecordDeleter).
var (
	_ libdns.RecordAppender = (*natsDNSProvider)(nil)
	_ libdns.RecordDeleter  = (*natsDNSProvider)(nil)
)

// AppendRecords faz o set de cada TXT e devolve os registros criados.
func (p *natsDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.apply(ctx, event.SubjectDNSACMESet, zone, recs)
}

// DeleteRecords faz o clear de cada TXT (remover o que não existe não é erro no dns).
func (p *natsDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.apply(ctx, event.SubjectDNSACMEClear, zone, recs)
}

func (p *natsDNSProvider) apply(ctx context.Context, subject, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, "TXT") {
			return out, fmt.Errorf("web: acme dns: only TXT records are supported, got %q", rr.Type)
		}
		name := libdns.AbsoluteName(rr.Name, zone)
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		if err := p.request(ctx, subject, name, rr.Data); err != nil {
			return out, err
		}
		out = append(out, libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data})
	}
	return out, nil
}

// request faz um set ou clear e traduz a resposta em erro claro.
func (p *natsDNSProvider) request(ctx context.Context, subject, name, value string) error {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = DefaultACMEDNSTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	data, err := json.Marshal(event.ACMERequest{Name: name, Value: value})
	if err != nil {
		return err
	}
	msg, err := p.nc.RequestWithContext(ctx, subject, data)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		return fmt.Errorf("web: acme dns: %s %s: no responder (is finger-sniffer-dns running?)", subject, name)
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout):
		return fmt.Errorf("web: acme dns: %s %s: no reply within %s", subject, name, timeout)
	case err != nil:
		return fmt.Errorf("web: acme dns: %s %s: %w", subject, name, err)
	}
	var rep event.ACMEReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		return fmt.Errorf("web: acme dns: %s %s: invalid reply: %w", subject, name, err)
	}
	if !rep.OK {
		reason := "unknown error"
		if rep.Error != nil && *rep.Error != "" {
			reason = *rep.Error
		}
		return fmt.Errorf("web: acme dns: %s %s: refused by dns: %s", subject, name, reason)
	}
	return nil
}
