package web

import (
	"slices"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/akamai"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// connInfoLocked monta o nível de conexão (fs.v1.web.http2.connection): o que o cliente mandou, os frames
// dos dois sentidos na ordem do tempo e o Akamai; `streams` vai vazio (cada stream sai no seu evento).
// Chamar com h.mu.
func (h *h2Conn) connInfoLocked() *h2passive.HTTP2Info {
	in := h.in.Info()
	info := h2passive.Merge(in, h.out.Info(), h.c.srv.cfg.H2Limits.MaxFrames)
	info.Mode = h.mode
	if in.FirstHeadersStream != 0 || len(in.Settings) > 0 {
		info.Akamai = akamai.FromInfo(in)
	}
	info.Settings = slices.Clone(info.Settings)
	info.Priorities = slices.Clone(info.Priorities)
	info.Streams = []h2passive.HTTP2Stream{}
	return info
}

// publishConn publica o nível de conexão (pode sair mais de uma vez; o store fica com a última).
func (h *h2Conn) publishConn() {
	h.mu.Lock()
	info := h.connInfoLocked()
	h.connEmitted = true
	h.mu.Unlock()
	s := h.c.srv
	h.t.flush()
	data := s.fitH2Conn(h.c, info)
	if data != nil {
		s.publishRaw(event.SubjectWebHTTP2Connection, data)
	}
}

// fitH2Conn serializa o nível de conexão dentro do teto do evento (ADR 0018): corta pela metade as
// listas de frames e de PRIORITY até caber, marcando frames_truncated e priority_frames_capped.
func (s *Server) fitH2Conn(c *conn, info *h2passive.HTTP2Info) []byte {
	ts := s.now()
	data := s.encode(ts, c.flow, c.probe(), info)
	for i := 0; i < 64 && data != nil && len(data) > event.MaxEventBytes; i++ {
		if len(info.Frames) > 0 {
			info.Frames = halve(info.Frames)
			info.FramesTruncated = true
		}
		if len(info.Priorities) > 64 {
			info.Priorities = halve(info.Priorities)
			info.PriorityFramesCapped = true
		}
		if len(info.Frames) == 0 && len(info.Priorities) <= 64 {
			info.Settings = halve(info.Settings)
		}
		data = s.encode(ts, c.flow, c.probe(), info)
	}
	return data
}

// streamRecord devolve o registro do stream visto pelo parser passivo (cópia), ligado a um handler pelo
// :method, :path e :authority: o x/net não expõe o id do stream ao handler. Entre streams iguais vale o
// de menor id ainda livre. ok false se nenhum casou (HPACK parado, por exemplo).
func (h *h2Conn) streamRecordLocked(method, path, authority string) (h2passive.HTTP2Stream, bool) {
	info := h.in.Info()
	best := -1
	bestScore := 0
	for i := range info.Streams {
		st := &info.Streams[i]
		if h.claimed[st.StreamID] {
			continue
		}
		score := 0
		if pseudo(st, ":method") == method && pseudo(st, ":path") == path {
			score = 2
			if pseudo(st, ":authority") == authority {
				score = 3
			}
		} else if len(st.PseudoOrder) == 0 {
			score = 1
		}
		if score > bestScore || (score == bestScore && score > 0 && st.StreamID < info.Streams[best].StreamID) {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return h2passive.HTTP2Stream{}, false
	}
	st := info.Streams[best]
	h.claimed[st.StreamID] = true
	st.PseudoOrder = slices.Clone(st.PseudoOrder)
	st.Fields = slices.Clone(st.Fields)
	return st, true
}

// refreshLocked relê o stream (fim do stream e trailers que chegaram depois do HEADERS).
func (h *h2Conn) refreshLocked(st *h2passive.HTTP2Stream) {
	info := h.in.Info()
	for i := range info.Streams {
		if info.Streams[i].StreamID == st.StreamID {
			st.EndStream = info.Streams[i].EndStream
			st.Fields = slices.Clone(info.Streams[i].Fields)
			if st.Priority == nil {
				st.Priority = info.Streams[i].Priority
			}
			return
		}
	}
}

// h2EndWait é a espera máxima, depois que o handler termina, pelo END_STREAM ou RST_STREAM do servidor no
// fio: o x/net escreve o fim do stream depois que o handler retorna.
const h2EndWait = time.Second

// streamOutLocked devolve o stream id visto pelo parser out (cópia) e se existe. Chamar com h.mu.
func (h *h2Conn) streamOutLocked(id uint32) (h2passive.HTTP2Stream, bool) {
	for _, st := range h.out.Info().Streams {
		if st.StreamID == id {
			return st, true
		}
	}
	return h2passive.HTTP2Stream{}, false
}

// fillInstants preenche os instantes do stream (spec 010 RF-08, ADR 0029): os da requisição pelo parser in
// (HEADERS e END_STREAM do cliente; nulos no stream 1 do Upgrade, que não tem HEADERS) e os da resposta
// pelo parser out (primeiro HEADERS e END_STREAM ou RST_STREAM do servidor). Espera até h2EndWait o fim
// do stream no fio.
func (h *h2Conn) fillInstants(rec *h2passive.HTTP2Stream, upgrade bool) {
	if rec.StreamID == 0 {
		return
	}
	timer := time.NewTimer(h2EndWait)
	defer timer.Stop()
wait:
	for {
		h.mu.Lock()
		out, ok := h.streamOutLocked(rec.StreamID)
		gen := h.outGen
		if gen == nil {
			gen = make(chan struct{})
			h.outGen = gen
		}
		h.mu.Unlock()
		if ok && (!out.EndAt.IsZero() || !out.ResetAt.IsZero()) {
			break
		}
		select {
		case <-gen:
		case <-timer.C:
			break wait
		case <-h.ctx.Done():
			break wait
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !upgrade {
		for _, in := range h.in.Info().Streams {
			if in.StreamID == rec.StreamID {
				rec.RequestStartedAt, rec.RequestEndedAt = instant(in.HeadersAt), instant(in.EndAt)
				break
			}
		}
	}
	if out, ok := h.streamOutLocked(rec.StreamID); ok {
		rec.ResponseStartedAt = instant(out.HeadersAt)
		end := out.EndAt
		if end.IsZero() || (!out.ResetAt.IsZero() && out.ResetAt.Before(end)) {
			end = out.ResetAt
		}
		rec.ResponseEndedAt = instant(end)
	}
}

// pseudo devolve o valor do pseudo-cabeçalho no primeiro bloco do stream.
func pseudo(st *h2passive.HTTP2Stream, name string) string {
	for _, f := range st.Fields[:min(st.HeadFields, len(st.Fields))] {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// ja4hOfStream calcula o JA4H (FoxIO License, ADR 0010) do primeiro bloco do stream.
func ja4hOfStream(st *h2passive.HTTP2Stream) *string {
	if st.HeadFields == 0 {
		return nil
	}
	in := ja4plus.JA4HInput{Method: pseudo(st, ":method"), Version: "HTTP/2"}
	for _, f := range st.Fields[:min(st.HeadFields, len(st.Fields))] {
		in.Fields = append(in.Fields, ja4plus.JA4HField{Name: f.Name, Value: f.Value})
	}
	return ptr(ja4plus.JA4H(in).JA4H)
}

// h2StreamEvent é o payload de fs.v1.web.http2.stream: o registro do parser passivo mais as marcas de corte
// do teto do evento (schema `HTTP2Stream`, contrato 0.2.1), sempre serializadas.
type h2StreamEvent struct {
	*h2passive.HTTP2Stream
	FieldsTruncated bool `json:"fields_truncated"`
	ValuesTruncated bool `json:"values_truncated"`
}

// publishStream publica fs.v1.web.http2.stream dentro do teto (ADR 0018): valores longos são cortados em
// FS_EVENT_INLINE_MAX e, se ainda não couber, a lista de campos cai pela metade. Cada corte marca
// values_truncated ou fields_truncated.
func (h *h2Conn) publishStream(st *h2passive.HTTP2Stream, probeID string) {
	s := h.c.srv
	h.t.flush()
	data := s.fitH2Stream(h.c.flow, probeID, st)
	if data != nil {
		s.publishRaw(event.SubjectWebHTTP2Stream, data)
	}
}

// fitH2Stream serializa o stream dentro do teto do evento, cortando valores e depois campos.
func (s *Server) fitH2Stream(flow *event.Flow, probeID string, st *h2passive.HTTP2Stream) []byte {
	ts := s.now()
	ev := &h2StreamEvent{HTTP2Stream: st}
	data := s.encode(ts, flow, probeID, ev)
	inline := max(s.cfg.EventInlineMax, 64)
	for i := 0; i < 64 && data != nil && len(data) > event.MaxEventBytes; i++ {
		for j := range st.Fields {
			if len(st.Fields[j].Value) > inline {
				st.Fields[j].Value = st.Fields[j].Value[:inline]
				ev.ValuesTruncated = true
			}
		}
		inline = max(inline/2, 64)
		if i > 0 && len(st.Fields) > 0 {
			st.Fields = halve(st.Fields)
			ev.FieldsTruncated = true
		}
		data = s.encode(ts, flow, probeID, ev)
	}
	return data
}
