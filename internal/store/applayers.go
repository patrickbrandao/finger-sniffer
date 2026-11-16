package store

import (
	"bytes"
	"encoding/json"
	"sort"
	"sync"
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
	h2StreamIdx  map[int]int    // stream_id → posição em h2Streams
	http3        map[string]any // nível de conexão QUIC/h3 (última versão, sem requests)
	h3Requests   []json.RawMessage
	h3RequestIdx map[int64]int     // stream_id → posição em h3Requests
	h3Close      *event.HTTP3Close // fim da conexão QUIC visto pelo web (ADR 0019)
	h3CloseTs    int64             // ts do http3.connection com close
	h3TLSDone    int64             // ts do primeiro http3.connection com negotiated
	ws           *wsJSON
	raw          json.RawMessage
	rawFromWeb   bool // web.raw.session (raw/unknown)
	dns          bool

	// Cache do JSON das camadas que mudam pouco (task 268: o registro é montado a cada updated publicado para o
	// bot e serializar os mapas era o custo maior). Os eventos (addLayer, sob a trava da tabela de fluxos)
	// invalidam; o registro pode ser montado pela API e pelo ingest ao mesmo tempo, daí a trava própria.
	cacheMu  sync.Mutex
	tlsJSON  json.RawMessage // tls do registro; vale para tlsSeg
	tlsSeg   int             // client_hello_segments usado em tlsJSON
	h3Level  json.RawMessage // nível de conexão h3 serializado, sem requests
	h3Cached bool
	h3TLS    json.RawMessage // tls vindo do client_hello do Initial (QUIC)
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

// decodeObject decodifica um objeto JSON em map com UseNumber: números viram json.Number e voltam idênticos na
// re-serialização (sem UseNumber, inteiros acima de 2^53, como SETTINGS h3 de 62 bits, seriam arredondados por
// float64). nil se o payload não é um objeto válido.
func decodeObject(b []byte) map[string]any {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return nil
	}
	return m
}

// addLayer incorpora um evento de aplicação às camadas.
func (l *layers) addLayer(ev appEvent) {
	switch ev.subject {
	case event.SubjectWebTLSClientHello:
		if m := decodeObject(ev.env.Payload); m != nil {
			l.clientHello = m
			l.invalidate()
		}
	case event.SubjectWebTLSHandshake:
		var h event.TLSHandshake
		if json.Unmarshal(ev.env.Payload, &h) == nil {
			l.handshake = &h
			l.invalidate()
			// tls_done é o fim do handshake (como no QUIC): handshake falho (ClientHello e FIN, alerta) fica null
			if h.Negotiated != nil {
				l.tlsDone = ev.ts
			}
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
		if m := decodeObject(ev.env.Payload); m != nil {
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
		// stream_id 0 é "stream não identificado" (spec 010 RF-02a, ADR 0032): sempre acrescenta.
		if i, ok := l.h2StreamIdx[h.StreamID]; ok && h.StreamID != 0 {
			l.h2Streams[i] = ev.env.Payload
		} else {
			if h.StreamID != 0 {
				l.h2StreamIdx[h.StreamID] = len(l.h2Streams)
			}
			l.h2Streams = append(l.h2Streams, ev.env.Payload)
		}
	case event.SubjectWebHTTP3Connection:
		l.addHTTP3Connection(ev)
	case event.SubjectWebHTTP3Request:
		var h struct {
			StreamID int64 `json:"stream_id"`
		}
		if json.Unmarshal(ev.env.Payload, &h) != nil {
			return
		}
		if l.h3RequestIdx == nil {
			l.h3RequestIdx = map[int64]int{}
		}
		if i, ok := l.h3RequestIdx[h.StreamID]; ok {
			l.h3Requests[i] = ev.env.Payload
		} else {
			l.h3RequestIdx[h.StreamID] = len(l.h3Requests)
			l.h3Requests = append(l.h3Requests, ev.env.Payload)
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
		// Sessão sem frames (ADR 0032): o evento só leva o Upgrade, nenhum frame entra na lista.
		if f.UpgradeOnly {
			return
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

// addHTTP3Connection guarda o nível de conexão h3: a última versão vale (spec 004), sem as requisições, que vêm
// por fs.v1.web.http3.request.
func (l *layers) addHTTP3Connection(ev appEvent) {
	m := decodeObject(ev.env.Payload)
	if m == nil {
		return
	}
	delete(m, "requests")
	l.http3 = m
	l.invalidate()
	var h struct {
		ClientHello *struct {
			Negotiated *event.TLSNegotiated `json:"negotiated"`
		} `json:"client_hello"`
		Close *event.HTTP3Close `json:"close"`
	}
	_ = json.Unmarshal(ev.env.Payload, &h)
	if h.ClientHello != nil && h.ClientHello.Negotiated != nil && l.h3TLSDone == 0 {
		l.h3TLSDone = ev.ts
	}
	if h.Close != nil && l.h3Close == nil {
		l.h3Close, l.h3CloseTs = h.Close, ev.ts
	}
}

// isQUIC informa se a conexão teve evento h3 (Initial analisado ou requisição).
func (l *layers) isQUIC() bool { return l.http3 != nil || len(l.h3Requests) > 0 }

// h3ALPN devolve o ALPN negociado no handshake QUIC ("" se não houve).
func (l *layers) h3ALPN() string {
	ch, _ := l.http3["client_hello"].(map[string]any)
	neg, _ := ch["negotiated"].(map[string]any)
	alpn, _ := neg["alpn"].(string)
	return alpn
}

// invalidate descarta o JSON em cache (camada TLS ou h3 mudou).
func (l *layers) invalidate() {
	l.cacheMu.Lock()
	l.tlsJSON, l.h3Level, l.h3Cached, l.h3TLS = nil, nil, false, nil
	l.cacheMu.Unlock()
}

// applyLayers escreve as camadas no registro (aberto ou gravado).
func (l *layers) applyLayers(r *connectionJSON) {
	start := parseTs(r.Started)
	if l.clientHello != nil || l.handshake != nil {
		r.TLS = l.tlsLayer(r)
		if l.handshake != nil && r.Times != nil {
			r.Times.TLSDone = tsPtr(l.tlsDone)
		}
	}
	l.applyApp(r, start)
}

// tlsLayer devolve o tls do registro, do cache quando client_hello_segments (que depende da análise TCP) não
// mudou.
func (l *layers) tlsLayer(r *connectionJSON) json.RawMessage {
	seg := 0
	if l.clientHello != nil {
		seg = clientHelloSegments(l.clientHello, r.TCP)
	}
	l.cacheMu.Lock()
	defer l.cacheMu.Unlock()
	if l.tlsJSON != nil && l.tlsSeg == seg {
		return l.tlsJSON
	}
	l.tlsJSON, l.tlsSeg = l.buildTLS(seg), seg
	return l.tlsJSON
}

// buildTLS serializa o tls (ClientHello + handshake).
func (l *layers) buildTLS(seg int) json.RawMessage {
	{
		tls := map[string]any{}
		for k, v := range l.clientHello {
			tls[k] = v
		}
		if seg > 0 {
			tls["client_hello_segments"] = seg
		}
		if h := l.handshake; h != nil {
			tls["negotiated"] = h.Negotiated
			tls["handshake_ms"] = h.HandshakeMs
			alerts := make([]map[string]any, 0, len(h.Alerts))
			for _, a := range h.Alerts {
				alerts = append(alerts, map[string]any{"dir": a.Dir, "level": a.Level, "description": a.Description, "name": alertName(a.Description)})
			}
			tls["alerts"] = alerts
		}
		out, _ := json.Marshal(tls)
		return out
	}
}

// applyApp escreve as camadas HTTP, h2, h3, WebSocket e raw.
func (l *layers) applyApp(r *connectionJSON, start int64) {
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
	if l.isQUIC() {
		requests += l.applyHTTP3(r)
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

// applyHTTP3 escreve o http3 do registro (spec 004, ADR 0019): o nível de conexão com as requisições, o tls (=
// client_hello do Initial, quando não houve ClientHello por TCP), times.tls_done e, com a conexão encerrada pelo
// web, o close (quic_close, ou timeout no idle_timeout). Devolve quantas requisições h3 houve.
func (l *layers) applyHTTP3(r *connectionJSON) int {
	r.HTTP3 = l.h3Layer()
	if ch, ok := l.http3["client_hello"].(map[string]any); ok && l.clientHello == nil && l.handshake == nil {
		l.cacheMu.Lock()
		if l.h3TLS == nil {
			l.h3TLS, _ = json.Marshal(ch)
		}
		r.TLS = l.h3TLS
		l.cacheMu.Unlock()
	}
	if l.h3TLSDone != 0 || r.Ended != nil {
		if r.Times == nil {
			r.Times = &timesJSON{End: r.Ended}
		}
		if l.h3TLSDone != 0 {
			r.Times.TLSDone = tsPtr(l.h3TLSDone)
		}
	}
	if c := l.h3Close; c != nil && r.Ended != nil {
		how := "quic_close"
		if c.How == event.QUICCloseIdleTimeout {
			how = "timeout"
		}
		by := c.By
		if by != "client" && by != "server" {
			by = "unknown"
		}
		r.Close = closeJSON{By: by, How: how, IdleBeforeCloseMs: r.Close.IdleBeforeCloseMs}
	}
	return len(l.h3Requests)
}

// h3Layer monta o http3 do registro: o nível de conexão (em cache até o próximo http3.connection) com as
// requisições ao fim.
func (l *layers) h3Layer() json.RawMessage {
	l.cacheMu.Lock()
	if !l.h3Cached {
		h3 := make(map[string]any, len(l.http3))
		for k, v := range l.http3 {
			h3[k] = v
		}
		l.h3Level, _ = json.Marshal(h3)
		l.h3Cached = true
	}
	level := l.h3Level
	l.cacheMu.Unlock()
	n := len(level) + 16
	for _, q := range l.h3Requests {
		n += len(q) + 1
	}
	out := make([]byte, 0, n)
	out = append(out, level[:len(level)-1]...)
	if len(level) > 2 {
		out = append(out, ',')
	}
	out = append(out, `"requests":[`...)
	for i, q := range l.h3Requests {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, q...)
	}
	return append(out, "]}"...)
}

func parseTs(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.UnixNano()
}
