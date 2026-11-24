package raw

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
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
	// ReadsInTruncated e WritesOutTruncated marcam que a lista parou em maxTimed itens (spec 006 RF-06);
	// os bytes continuam completos em fs.v1.raw.read.
	ReadsInTruncated   bool       `json:"reads_in_truncated"`
	WritesOutTruncated bool       `json:"writes_out_truncated"`
	HalfClose          *HalfClose `json:"half_close"`
}

// emitter monta os envelopes de uma sessão e publica.
type emitter struct {
	pub     Publisher
	log     *slog.Logger
	flow    *event.Flow
	metrics *service.Metrics
}

func (e *emitter) publish(subject string, ts time.Time, probeID string, payload any) {
	if data := e.encode(subject, ts, probeID, payload); data != nil {
		e.publishData(subject, data)
	}
}

// encode monta o envelope e serializa; nil em erro (registrado no log).
func (e *emitter) encode(subject string, ts time.Time, probeID string, payload any) []byte {
	env, err := event.New(event.ServiceRaw, version.Version, ts, e.flow, payload)
	if err != nil {
		e.log.Error("raw: event", "subject", subject, "err", err)
		return nil
	}
	if probeID != "" {
		env.ProbeID = &probeID
	}
	data, err := json.Marshal(env)
	if err != nil {
		e.log.Error("raw: event", "subject", subject, "err", err)
		return nil
	}
	return data
}

// publishData publica um evento já serializado. Acima de event.MaxEventBytes o evento é descartado com log e
// conta em raw_events_oversize_total: o NATS o recusaria e o teto da ADR 0018 vale para todo evento (ADR 0035).
func (e *emitter) publishData(subject string, data []byte) {
	if len(data) > event.MaxEventBytes {
		if e.metrics != nil {
			e.metrics.Add(MetricEventsOversize, 1)
		}
		e.log.Warn("raw: event over size limit dropped", "subject", subject, "bytes", len(data))
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

	// Pendente (task 345): leituras e escritas pequenas e seguidas são juntadas num só fs.v1.raw.read. O
	// pendente é a vista [pStart, pEnd) do buffer de leitura da sessão, sem cópia e sem memória a mais (a
	// retenção fixa do buf, spec 006 RF-07b); pTS e pProbe são os da primeira leitura juntada.
	pStart, pEnd int
	pTS          time.Time
	pProbe       string
}

// pending informa se há bytes juntados ainda não publicados.
func (s *stream) pending() bool { return s.pEnd > s.pStart }

// add publica b, juntando pedaços pequenos. at >= 0 diz que b é buf[at:at+len(b)]: contíguo ao pendente e com o
// mesmo probe, estende a vista; senão o pendente sai antes e b vira o novo pendente. at < 0 (bytes fora do buf:
// banner, source, linha guardada) publica na hora, depois do pendente. Offsets e bytes são os mesmos de uma
// publicação por chamada; só há menos mensagens.
func (s *stream) add(e *emitter, buf []byte, ts time.Time, probeID string, b []byte, at int) {
	if len(b) == 0 {
		return
	}
	if at >= 0 && s.pending() && s.pEnd == at && s.pProbe == probeID {
		s.pEnd += len(b)
		return
	}
	s.flush(e, buf)
	if at < 0 || s.truncated {
		s.write(e, ts, probeID, b)
		return
	}
	s.pStart, s.pEnd, s.pTS, s.pProbe = at, at+len(b), ts, probeID
}

// flush publica o pendente, se houver.
func (s *stream) flush(e *emitter, buf []byte) {
	if !s.pending() {
		return
	}
	b := buf[s.pStart:s.pEnd]
	s.pStart, s.pEnd = 0, 0
	s.write(e, s.pTS, s.pProbe, b)
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
