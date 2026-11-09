package raw

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Publisher é o que o raw usa para publicar (service.Producer em produção).
type Publisher interface {
	Publish(msg *nats.Msg)
}

// TimedLength é o par [t_ms, bytes] do contrato: tempo desde o accept em milissegundos (com fração até o
// nanossegundo) e o tamanho da leitura ou escrita.
type TimedLength [2]float64

// HalfClose é o resultado do teste de meio-fechamento (spec 006 RF-05).
type HalfClose struct {
	ServerSentAfterClientFIN bool `json:"server_sent_after_client_fin"`
	Bytes                    int  `json:"bytes"`
}

// Info é o payload de fs.v1.raw.session (schema RawInfo do openapi).
type Info struct {
	Mode      string        `json:"mode"`
	TLS       bool          `json:"tls"`
	Banner    *string       `json:"banner"`
	ProbeLine *string       `json:"probe_line"`
	ReadsIn   []TimedLength `json:"reads_in"`
	WritesOut []TimedLength `json:"writes_out"`
	HalfClose *HalfClose    `json:"half_close"`
}

// emitter monta os envelopes de uma sessão e publica.
type emitter struct {
	pub  Publisher
	log  *slog.Logger
	flow *event.Flow
}

func (e *emitter) publish(subject string, ts time.Time, probeID string, payload any) {
	env, err := event.New(event.ServiceRaw, version.Version, ts, e.flow, payload)
	if err != nil {
		e.log.Error("raw: event", "subject", subject, "err", err)
		return
	}
	if probeID != "" {
		env.ProbeID = &probeID
	}
	data, err := json.Marshal(env)
	if err != nil {
		e.log.Error("raw: event", "subject", subject, "err", err)
		return
	}
	e.pub.Publish(&nats.Msg{Subject: subject, Data: data})
}

// stream controla o fluxo publicado de um sentido: offset, teto e marca de truncado (ADR 0018).
type stream struct {
	dir       string
	max       int64
	offset    int64
	truncated bool
}

// write publica os bytes em pedaços de até event.StreamChunkBytes; passado o teto, manda um último pedaço vazio com
// truncated=true e para de publicar nesse sentido.
func (s *stream) write(e *emitter, ts time.Time, probeID string, b []byte) {
	for len(b) > 0 && !s.truncated {
		room := s.max - s.offset
		if room <= 0 {
			s.truncated = true
			e.publish(event.SubjectRawRead, ts, probeID, event.StreamBytes{Dir: s.dir, Offset: s.offset, Data: []byte{}, Truncated: true})
			return
		}
		n := min(len(b), event.StreamChunkBytes, int(min(room, int64(event.StreamChunkBytes))))
		e.publish(event.SubjectRawRead, ts, probeID, event.StreamBytes{Dir: s.dir, Offset: s.offset, Data: b[:n]})
		s.offset += int64(n)
		b = b[n:]
	}
}
