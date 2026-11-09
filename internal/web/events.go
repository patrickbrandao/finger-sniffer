package web

import (
	"encoding/json"
	"net"
	"net/netip"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// Métricas do web no heartbeat.
const (
	MetricConnsTotal     = "web_connections_total"
	MetricConnsActive    = "web_connections_active"
	MetricRequestsTotal  = "web_http1_requests_total"
	MetricEventsOversize = "web_events_oversize_total"
	MetricEventsInvalid  = "web_events_marshal_errors_total"
)

// rawSession é o payload de fs.v1.web.raw.session (schema RawInfo do openapi, modo sink).
type rawSession struct {
	Mode      string   `json:"mode"`
	TLS       bool     `json:"tls"`
	Banner    *string  `json:"banner"`
	ProbeLine *string  `json:"probe_line"`
	ReadsIn   [][2]any `json:"reads_in"`
	WritesOut [][2]any `json:"writes_out"`
	// ReadsInTruncated indica que só as primeiras maxRawReads leituras estão em ReadsIn (ADR 0018).
	ReadsInTruncated bool `json:"reads_in_truncated"`
	// WritesOutTruncated fica sempre false no web: o modo sink não escreve.
	WritesOutTruncated bool       `json:"writes_out_truncated"`
	HalfClose          *halfClose `json:"half_close"`
}

// halfClose é o meio-fechamento do RawInfo (o web em modo sink nunca escreve: fica sempre nulo).
type halfClose struct {
	ServerSentAfterClientFIN bool  `json:"server_sent_after_client_fin"`
	Bytes                    int64 `json:"bytes"`
}

// flowOf monta a 5-tupla do ponto de vista do cliente (src = cliente, dst = espelho).
func flowOf(c net.Conn) *event.Flow {
	f := &event.Flow{L4: "tcp"}
	if ap, ok := addrPort(c.RemoteAddr()); ok {
		f.SrcIP, f.SrcPort = ap.Addr().String(), int(ap.Port())
	}
	if ap, ok := addrPort(c.LocalAddr()); ok {
		f.DstIP, f.DstPort = ap.Addr().String(), int(ap.Port())
	}
	return f
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// encode monta o envelope e serializa. Devolve nil se o evento passou do teto (ADR 0018).
func (s *Server) encode(ts time.Time, flow *event.Flow, probeID string, payload any) []byte {
	env, err := event.New(event.ServiceWeb, version.Version, ts, flow, payload)
	if err != nil {
		s.metrics.Add(MetricEventsInvalid, 1)
		s.log.Error("event marshal", "err", err)
		return nil
	}
	if probeID != "" {
		env.ProbeID = &probeID
	}
	data, err := json.Marshal(env)
	if err != nil {
		s.metrics.Add(MetricEventsInvalid, 1)
		s.log.Error("event marshal", "err", err)
		return nil
	}
	return data
}

// publish serializa e publica um evento; nunca manda nada acima de event.MaxEventBytes.
func (s *Server) publish(subject string, ts time.Time, flow *event.Flow, probeID string, payload any) {
	data := s.encode(ts, flow, probeID, payload)
	if data == nil {
		return
	}
	s.publishRaw(subject, data)
}

// publishRaw publica um evento já serializado (e dentro do teto).
func (s *Server) publishRaw(subject string, data []byte) {
	if len(data) > event.MaxEventBytes {
		s.metrics.Add(MetricEventsOversize, 1)
		s.log.Warn("event over size limit dropped", "subject", subject, "bytes", len(data))
		return
	}
	s.deps.Publish(&nats.Msg{Subject: subject, Data: data})
}

// fitHTTP1 serializa o evento da requisição dentro do teto de 900 KiB: corta os bytes crus inline em
// FS_EVENT_INLINE_MAX e, se ainda não couber, reduz as listas analisadas pela metade até caber, marcando
// fields_truncated (ADR 0018).
func (s *Server) fitHTTP1(ts time.Time, flow *event.Flow, probeID string, req *h1.Request) []byte {
	req.LimitInline(s.cfg.EventInlineMax)
	data := s.encode(ts, flow, probeID, req)
	budget := event.MaxEventBytes / 2
	inline := s.cfg.EventInlineMax
	for i := 0; i < 64 && data != nil && len(data) > event.MaxEventBytes; i++ {
		req.LimitFields(budget)
		// Listas longas de itens pequenos também pesam: corta as secundárias junto.
		if len(req.ProxySignals) > 64 {
			req.ProxySignals = req.ProxySignals[:64]
		}
		if len(req.Duplicates) > 256 {
			req.Duplicates = req.Duplicates[:256]
		}
		if req.Body != nil && len(req.Body.Chunks) > 1024 {
			req.Body.Chunks = req.Body.Chunks[:1024]
			req.Body.ChunksTruncated = true
		}
		if req.Body != nil && len(req.Body.Trailers) > 256 {
			req.Body.Trailers = req.Body.Trailers[:256]
			req.FieldsTruncated = true
		}
		if budget < 1024 {
			// Último recurso: as listas secundárias e os bytes inline também encolhem.
			req.ProxySignals = halve(req.ProxySignals)
			req.Duplicates = halve(req.Duplicates)
			if req.Body != nil {
				if len(req.Body.Chunks) > 0 {
					req.Body.ChunksTruncated = true
				}
				req.Body.Chunks = halve(req.Body.Chunks)
				req.Body.Trailers = halve(req.Body.Trailers)
			}
			req.FieldsTruncated = true
			inline = max(inline/2, 1)
			req.LimitInline(inline)
		}
		budget /= 2
		data = s.encode(ts, flow, probeID, req)
	}
	return data
}

func halve[T any](s []T) []T {
	if len(s) == 0 {
		return s
	}
	return s[: len(s)/2 : len(s)/2]
}

// msSince devolve a duração em milissegundos (com fração), para os campos *_ms.
func msSince(from, to time.Time) float64 {
	return float64(to.Sub(from).Nanoseconds()) / 1e6
}

func ptr[T any](v T) *T { return &v }
