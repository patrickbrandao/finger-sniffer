package store

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// wsMaxFrames é o teto de frames WebSocket listados no registro (ADR 0018: o registro precisa caber no teto
// de 900 KiB); além dele só conta frames_truncated.
const wsMaxFrames = 1000

// layers guarda as camadas de aplicação recebidas, na forma do contrato (spec 004, tabela de montagem).
type layers struct {
	clientHello  map[string]any // TLSInfo do ClientHello (substitui)
	handshake    *event.TLSHandshake
	tlsDone      int64
	http1        map[int]json.RawMessage // por index
	http1Version string                  // versão da requisição de menor index
	http1Index   int
	http2        map[string]any // nível de conexão (última versão)
	h2Streams    []json.RawMessage
	h2StreamIdx  map[int]int // stream_id → posição em h2Streams
	ws           *wsJSON
	raw          json.RawMessage
	rawFromWeb   bool // web.raw.session (raw/unknown)
	dns          bool
}

// wsJSON é o schema WebSocketInfo.
type wsJSON struct {
	Over            string                `json:"over"`
	Path            string                `json:"path"`
	Extensions      *string               `json:"extensions"`
	Subprotocol     *string               `json:"subprotocol"`
	Frames          []wsFrameJSON         `json:"frames"`
	FramesTruncated bool                  `json:"frames_truncated"`
	Close           *event.WebSocketClose `json:"close"`
}

type wsFrameJSON struct {
	Dir        string  `json:"dir"`
	TMs        float64 `json:"t_ms"`
	Opcode     int     `json:"opcode"`
	Fin        bool    `json:"fin"`
	RSV        int     `json:"rsv"`
	Masked     bool    `json:"masked"`
	MaskKeyHex *string `json:"mask_key_hex"`
	Length     int64   `json:"length"`
	ts         int64
}

// addLayer incorpora um evento de aplicação às camadas.
func (l *layers) addLayer(ev appEvent) {
	switch ev.subject {
	case event.SubjectWebTLSClientHello:
		var m map[string]any
		if json.Unmarshal(ev.env.Payload, &m) == nil && m != nil {
			l.clientHello = m
		}
	case event.SubjectWebTLSHandshake:
		var h event.TLSHandshake
		if json.Unmarshal(ev.env.Payload, &h) == nil {
			l.handshake = &h
			l.tlsDone = ev.ts
		}
	case event.SubjectWebHTTP1Request:
		var h struct {
			Index       int `json:"index"`
			RequestLine struct {
				Version string `json:"version"`
			} `json:"request_line"`
		}
		if json.Unmarshal(ev.env.Payload, &h) != nil {
			return
		}
		if l.http1 == nil {
			l.http1 = map[int]json.RawMessage{}
		}
		if len(l.http1) == 0 || h.Index < l.http1Index {
			l.http1Index, l.http1Version = h.Index, h.RequestLine.Version
		}
		l.http1[h.Index] = ev.env.Payload
	case event.SubjectWebHTTP2Connection:
		var m map[string]any
		if json.Unmarshal(ev.env.Payload, &m) == nil && m != nil {
			l.http2 = m
		}
	case event.SubjectWebHTTP2Stream:
		var h struct {
			StreamID int `json:"stream_id"`
		}
		if json.Unmarshal(ev.env.Payload, &h) != nil {
			return
		}
		if l.h2StreamIdx == nil {
			l.h2StreamIdx = map[int]int{}
		}
		if i, ok := l.h2StreamIdx[h.StreamID]; ok {
			l.h2Streams[i] = ev.env.Payload
		} else {
			l.h2StreamIdx[h.StreamID] = len(l.h2Streams)
			l.h2Streams = append(l.h2Streams, ev.env.Payload)
		}
	case event.SubjectWebWebSocketFrame:
		var f event.WebSocketFrame
		if json.Unmarshal(ev.env.Payload, &f) != nil {
			return
		}
		if l.ws == nil {
			l.ws = &wsJSON{Frames: []wsFrameJSON{}}
		}
		if f.Upgrade != nil && l.ws.Over == "" {
			l.ws.Over, l.ws.Path, l.ws.Extensions, l.ws.Subprotocol = f.Upgrade.Over, f.Upgrade.Path, f.Upgrade.Extensions, f.Upgrade.Subprotocol
		}
		if f.Close != nil {
			l.ws.Close = f.Close
		}
		if len(l.ws.Frames) >= wsMaxFrames {
			l.ws.FramesTruncated = true
			return
		}
		l.ws.Frames = append(l.ws.Frames, wsFrameJSON{
			Dir: f.Dir, Opcode: f.Opcode, Fin: f.Fin, RSV: f.RSV, Masked: f.Masked, MaskKeyHex: f.MaskKeyHex,
			Length: f.Length, ts: ev.ts,
		})
	case event.SubjectRawSession, event.SubjectWebRawSession:
		l.raw = ev.env.Payload
		l.rawFromWeb = ev.subject == event.SubjectWebRawSession
	case event.SubjectDNSQuery:
		l.dns = true
	}
}

// applyLayers escreve as camadas no registro (aberto ou gravado).
func (l *layers) applyLayers(r *connectionJSON) {
	start := parseTs(r.Started)
	if l.clientHello != nil || l.handshake != nil {
		tls := map[string]any{}
		for k, v := range l.clientHello {
			tls[k] = v
		}
		if l.clientHello != nil {
			if n := clientHelloSegments(l.clientHello, r.TCP); n > 0 {
				tls["client_hello_segments"] = n
			}
		}
		if h := l.handshake; h != nil {
			tls["negotiated"] = h.Negotiated
			tls["handshake_ms"] = h.HandshakeMs
			alerts := make([]map[string]any, 0, len(h.Alerts))
			for _, a := range h.Alerts {
				alerts = append(alerts, map[string]any{"dir": a.Dir, "level": a.Level, "description": a.Description, "name": alertName(a.Description)})
			}
			tls["alerts"] = alerts
			if r.Times != nil {
				r.Times.TLSDone = tsPtr(l.tlsDone)
			}
		}
		r.TLS, _ = json.Marshal(tls)
	}
	requests := 0
	if len(l.http1) > 0 {
		idx := make([]int, 0, len(l.http1))
		for i := range l.http1 {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		r.HTTP = make([]json.RawMessage, 0, len(idx))
		for _, i := range idx {
			r.HTTP = append(r.HTTP, l.http1[i])
		}
		requests += len(idx)
	}
	if l.http2 != nil || len(l.h2Streams) > 0 {
		h2 := map[string]any{}
		for k, v := range l.http2 {
			h2[k] = v
		}
		streams := l.h2Streams
		if streams == nil {
			streams = []json.RawMessage{}
		}
		h2["streams"] = streams
		r.HTTP2, _ = json.Marshal(h2)
		requests += len(l.h2Streams)
	}
	r.Requests = requests
	if l.ws != nil {
		ws := *l.ws
		ws.Frames = make([]wsFrameJSON, len(l.ws.Frames))
		for i, f := range l.ws.Frames {
			if start != 0 {
				f.TMs = float64(f.ts-start) / 1e6
			}
			ws.Frames[i] = f
		}
		r.WebSocket = &ws
	}
	if l.raw != nil {
		r.Raw = l.raw
	}
	r.Proto = l.proto(r.L4)
}

func parseTs(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.UnixNano()
}
