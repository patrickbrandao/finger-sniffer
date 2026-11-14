package web

import (
	"net/http"
	"slices"
	"strings"
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

// streamRecordLocked devolve o registro do stream visto pelo parser passivo (cópia) que casa com o handler:
// o x/net não expõe o id do stream ao handler (spec 010 RF-02a, ADR 0032). Casa pelos pseudo-cabeçalhos
// (:method, :path, :authority; CONNECT sem :protocol compara com :path vazio, porque o x/net põe a
// autoridade no RequestURI) e, entre candidatos iguais, pelos campos regulares do primeiro bloco contra o
// r.Header (menos divergências vence; depois o menor id). Streams que o servidor já respondeu ou resetou
// (recusados pela biblioteca antes do handler) não são candidatos. ok false se nenhum casou.
func (h *h2Conn) streamRecordLocked(r *http.Request) (h2passive.HTTP2Stream, bool) {
	method, path, authority := r.Method, r.RequestURI, r.Host
	if method == http.MethodConnect && r.Header.Get(":protocol") == "" {
		path = ""
	}
	info := h.in.Info()
	answered := h.answeredLocked()
	best := -1
	bestScore, bestMiss := 0, 0
	for i := range info.Streams {
		st := &info.Streams[i]
		if h.claimed[st.StreamID] || answered[st.StreamID] {
			continue
		}
		score := 0
		if pseudo(st, ":method") == method && pseudo(st, ":path") == path {
			score = 2
			if pseudo(st, ":authority") == authority {
				score = 3
			}
		} else if unreadable(st) {
			// HPACK parado ou campos não guardados (teto/orçamento): o stream pode ser este, sem como conferir.
			score = 1
		}
		if score == 0 {
			continue
		}
		miss := fieldMisses(st, r.Header)
		if score > bestScore || (score == bestScore && (miss < bestMiss ||
			(miss == bestMiss && st.StreamID < info.Streams[best].StreamID))) {
			best, bestScore, bestMiss = i, score, miss
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

// unreadable informa se os pseudo-cabeçalhos do stream não podem ser conferidos: nenhum campo decodificado
// (HPACK parado) ou campos cortados antes de :method e :path. Um stream com campos e sem pseudo-cabeçalhos
// foi recusado pela biblioteca e não casa com handler nenhum.
func unreadable(st *h2passive.HTTP2Stream) bool {
	if len(st.PseudoOrder) == 0 && len(st.Fields) == 0 {
		return true
	}
	return st.FieldsCut && pseudo(st, ":method") == "" && pseudo(st, ":path") == ""
}

// publishUnclaimed publica, no fim da conexão, os streams que o parser passivo viu com HEADERS e que nenhum
// handler atendeu: a biblioteca h2 os recusou antes do handler (RST_STREAM, 400 ou 431, visíveis em frames).
// Saem com status 0 (spec 010 RF-02a, ADR 0032). Chamar depois de h.wg.Wait().
func (h *h2Conn) publishUnclaimed() {
	h.mu.Lock()
	var recs []h2passive.HTTP2Stream
	for _, st := range h.in.Info().Streams {
		if h.claimed[st.StreamID] || st.HeadersAt.IsZero() {
			continue
		}
		h.claimed[st.StreamID] = true
		st.PseudoOrder = slices.Clone(st.PseudoOrder)
		st.Fields = slices.Clone(st.Fields)
		st.Status = 0
		recs = append(recs, st)
	}
	h.mu.Unlock()
	for i := range recs {
		recs[i].JA4H = ja4hOfStream(&recs[i])
		// O contexto já foi cancelado: fillInstants não espera, só copia os instantes vistos no fio.
		h.fillInstants(&recs[i], false)
		h.publishStream(&recs[i], h.c.probe())
	}
}

// answeredLocked devolve os streams em que o servidor já mandou HEADERS ou RST_STREAM. Chamar com h.mu.
func (h *h2Conn) answeredLocked() map[uint32]bool {
	out := map[uint32]bool{}
	for _, st := range h.out.Info().Streams {
		if !st.HeadersAt.IsZero() || !st.ResetAt.IsZero() {
			out[st.StreamID] = true
		}
	}
	return out
}

// fieldMisses conta os campos regulares do primeiro bloco do stream que não aparecem com o mesmo valor em
// hdr (o r.Header do handler).
func fieldMisses(st *h2passive.HTTP2Stream, hdr http.Header) int {
	miss := 0
	for _, f := range st.Fields[:min(st.HeadFields, len(st.Fields))] {
		if strings.HasPrefix(f.Name, ":") {
			continue
		}
		vals := hdr.Values(f.Name)
		if f.Name == "cookie" && len(vals) > 0 {
			// O x/net junta os campos cookie com "; " (RFC 9113 §8.2.3).
			if strings.Contains("; "+strings.Join(vals, "; ")+"; ", "; "+f.Value+"; ") {
				continue
			}
		}
		if !slices.Contains(vals, f.Value) {
			miss++
		}
	}
	return miss
}

// refreshLocked relê o stream (fim do stream e trailers que chegaram depois do HEADERS).
func (h *h2Conn) refreshLocked(st *h2passive.HTTP2Stream) {
	info := h.in.Info()
	for i := range info.Streams {
		if info.Streams[i].StreamID == st.StreamID {
			st.EndStream = info.Streams[i].EndStream
			st.Fields = slices.Clone(info.Streams[i].Fields)
			st.FieldsCut = info.Streams[i].FieldsCut
			if st.Priority == nil {
				st.Priority = info.Streams[i].Priority
			}
			return
		}
	}
}

// h2EndWait é a espera máxima, depois que o handler termina, pelo END_STREAM ou RST_STREAM do servidor no
// fio: o x/net escreve o fim do stream depois que o handler retorna. A espera acaba antes se o cliente
// resetou o stream (o x/net não escreve nada depois do RST_STREAM do cliente) ou se a conexão fechou.
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

// clientResetLocked informa se o parser in viu RST_STREAM do cliente no stream id. Chamar com h.mu.
func (h *h2Conn) clientResetLocked(id uint32) bool {
	for _, st := range h.in.Info().Streams {
		if st.StreamID == id {
			return !st.ResetAt.IsZero()
		}
	}
	return false
}

// fillInstants preenche os instantes do stream (spec 010 RF-08, ADR 0029): os da requisição pelo parser in
// (HEADERS e END_STREAM do cliente; nulos no stream 1 do Upgrade, que não tem HEADERS) e os da resposta
// pelo parser out (primeiro HEADERS e END_STREAM ou RST_STREAM do servidor). Espera até h2EndWait o fim
// do stream no fio; com RST_STREAM do cliente, sai assim que as escritas em andamento chegarem ao parser
// out (task 213), e com a conexão fechada, na hora; response_ended_at fica nulo se o servidor não encerrou o
// stream.
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
		clientReset := h.clientResetLocked(rec.StreamID)
		gen := h.gen
		if gen == nil {
			gen = make(chan struct{})
			h.gen = gen
		}
		h.mu.Unlock()
		if ok && (!out.EndAt.IsZero() || !out.ResetAt.IsZero()) {
			break
		}
		if clientReset {
			// O cliente pode ter resetado ao receber bytes cuja cópia ainda não chegou ao parser out (o tap
			// entrega depois do Write no socket): espera as escritas em andamento antes de ler o out.
			select {
			case <-h.t.writesDone():
			case <-timer.C:
			case <-h.ctx.Done():
			}
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
	// Status sempre serializado (sombra do campo com omitempty do parser): 0 = stream recusado pela
	// biblioteca antes do handler (spec 010 RF-02a, ADR 0032).
	Status int `json:"status"`
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
	ev := &h2StreamEvent{HTTP2Stream: st, FieldsTruncated: st.FieldsCut, Status: st.Status}
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
