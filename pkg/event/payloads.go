package event

import (
	"encoding/json"
	"fmt"
)

// Limites de tamanho dos eventos (ADR 0018).
const (
	// MaxEventBytes é o teto de qualquer evento JSON publicado.
	MaxEventBytes = 900 << 10
	// DefaultEventInlineMax é o padrão de FS_EVENT_INLINE_MAX: bytes crus por campo inline (*_b64).
	DefaultEventInlineMax = 128 << 10
	// StreamChunkBytes é o tamanho máximo de um pedaço de fs.v1.web.stream.bytes / fs.v1.raw.read.
	StreamChunkBytes = 64 << 10
	// DefaultRawStreamMaxBytes é o padrão de FS_RAW_STREAM_MAX_BYTES: bytes por sentido e por conexão.
	DefaultRawStreamMaxBytes = 16 << 20
)

// Variáveis de ambiente dos limites acima (lidas por pkg/service).
const (
	EnvEventInlineMax    = "FS_EVENT_INLINE_MAX"
	EnvRawStreamMaxBytes = "FS_RAW_STREAM_MAX_BYTES"
)

// Sentidos do fluxo de aplicação: in = do cliente para o espelho, out = do espelho para o cliente.
const (
	DirectionIn  = "in"
	DirectionOut = "out"
)

// StreamBytes é o payload de fs.v1.web.stream.bytes e fs.v1.raw.read: um pedaço de até StreamChunkBytes de um
// sentido. Data é serializado em base64 padrão (chave data_b64).
type StreamBytes struct {
	Dir       string `json:"dir"`
	Offset    int64  `json:"offset"`
	Data      []byte `json:"data_b64"`
	Truncated bool   `json:"truncated,omitempty"`
}

// TLSHandshake é o payload de fs.v1.web.tls.handshake; o store funde no tls do registro.
type TLSHandshake struct {
	Negotiated  *TLSNegotiated `json:"negotiated"`
	HandshakeMs *float64       `json:"handshake_ms"`
	Alerts      []TLSAlert     `json:"alerts,omitempty"`
}

// TLSNegotiated são os parâmetros acordados no handshake.
type TLSNegotiated struct {
	Version string  `json:"version"`
	Cipher  string  `json:"cipher"`
	Group   string  `json:"group"`
	ALPN    *string `json:"alpn"`
	Resumed bool    `json:"resumed"`
}

// TLSAlert é um alerta TLS visto num sentido.
type TLSAlert struct {
	Dir         string `json:"dir"`
	Level       int    `json:"level"`
	Description int    `json:"description"`
}

// WebSocketFrame é o payload de fs.v1.web.websocket.frame.
type WebSocketFrame struct {
	Dir        string            `json:"dir"`
	Opcode     int               `json:"opcode"`
	Fin        bool              `json:"fin"`
	RSV        int               `json:"rsv"`
	Masked     bool              `json:"masked"`
	MaskKeyHex *string           `json:"mask_key_hex"`
	Length     int64             `json:"length"`
	Upgrade    *WebSocketUpgrade `json:"upgrade"`
	Close      *WebSocketClose   `json:"close"`
}

// WebSocketUpgrade traz os dados do Upgrade e as extensões negociadas (só no primeiro frame).
type WebSocketUpgrade struct {
	Over        string  `json:"over"` // http1.1 | h2
	Path        string  `json:"path"`
	Extensions  *string `json:"extensions"`
	Subprotocol *string `json:"subprotocol"`
}

// WebSocketClose descreve o fechamento.
type WebSocketClose struct {
	By     string  `json:"by"` // client | server
	Code   *int    `json:"code"`
	Reason *string `json:"reason"`
}

// ConnIDRequest é a requisição de fs.v1.store.conn_id (ADR 0017). Não usa o envelope.
type ConnIDRequest struct {
	Flow Flow   `json:"flow"`
	Ts   string `json:"ts"`
}

// ConnIDReply é a resposta de fs.v1.store.conn_id.
type ConnIDReply struct {
	ConnID   string `json:"conn_id"`
	Reserved bool   `json:"reserved,omitempty"`
}

// ACMERequest é a requisição de fs.v1.dns.acme.set e fs.v1.dns.acme.clear. Não usa o envelope.
type ACMERequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ACMEReply é a resposta do dns às requisições ACME.
type ACMEReply struct {
	OK    bool    `json:"ok"`
	Error *string `json:"error"`
}

// HTTP3Info é o payload de fs.v1.web.http3.connection (schema HTTP3Info do openapi, ADR 0019): o Initial QUIC
// analisado, o SETTINGS do h3 e o fim da conexão. Publicado até três vezes por conexão (handshake, SETTINGS do
// cliente, fim com Close); Requests vai vazio no evento, porque cada requisição vai em fs.v1.web.http3.request.
type HTTP3Info struct {
	Version                string           `json:"version"`
	DCIDHex                string           `json:"dcid_hex"`
	SCIDHex                string           `json:"scid_hex"`
	TokenLen               int              `json:"token_len"`
	TokenHex               string           `json:"token_hex"`
	InitialLength          int              `json:"initial_length"`
	InitialPacketNumber    int64            `json:"initial_packet_number"`
	InitialDatagramSize    int              `json:"initial_datagram_size"`
	PaddedTo1200           bool             `json:"padded_to_1200"`
	CoalescedPackets       int              `json:"coalesced_packets"`
	ClientHelloDatagrams   int              `json:"client_hello_datagrams"`
	InitialFrames          []string         `json:"initial_frames"`
	InitialFramesTruncated bool             `json:"initial_frames_truncated"`
	TransportParams        []TransportParam `json:"transport_params"`
	// ClientHello segue o schema TLSInfo (pkg/tlsparse); fica cru aqui para pkg/event não depender do parser.
	ClientHello json.RawMessage `json:"client_hello,omitempty"`
	H3Settings  [][2]uint64     `json:"h3_settings"`
	// H3ControlStreamSeen: o cliente abriu o stream de controle h3 e o SETTINGS foi lido (contrato 0.3.2).
	H3ControlStreamSeen bool           `json:"h3_control_stream_seen"`
	Close               *HTTP3Close    `json:"close"`
	Requests            []HTTP3Request `json:"requests"`
}

// HTTP3Close é o fim da conexão QUIC visto pelo web.
type HTTP3Close struct {
	By        string  `json:"by"`  // client | server | unknown
	How       string  `json:"how"` // connection_close | application_close | idle_timeout | stateless_reset | handshake_failed
	ErrorCode *uint64 `json:"error_code"`
	Reason    *string `json:"reason"`
}

// Valores de HTTP3Close.How.
const (
	QUICCloseConnection  = "connection_close"
	QUICCloseApplication = "application_close"
	QUICCloseIdleTimeout = "idle_timeout"
	QUICCloseStateless   = "stateless_reset"
	QUICCloseHandshake   = "handshake_failed"
)

// TransportParam é um transport parameter QUIC, serializado como `[id, nome, valor_hex]`.
type TransportParam struct {
	ID       uint64
	Name     string
	ValueHex string
}

// MarshalJSON serializa como array de três posições.
func (p TransportParam) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{p.ID, p.Name, p.ValueHex})
}

// UnmarshalJSON lê o array de três posições.
func (p *TransportParam) UnmarshalJSON(b []byte) error {
	var a []json.RawMessage
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	if len(a) != 3 {
		return fmt.Errorf("event: transport param: %d items", len(a))
	}
	if err := json.Unmarshal(a[0], &p.ID); err != nil {
		return err
	}
	if err := json.Unmarshal(a[1], &p.Name); err != nil {
		return err
	}
	return json.Unmarshal(a[2], &p.ValueHex)
}

// HTTP3Request é o payload de fs.v1.web.http3.request: uma requisição h3 (spec 011 RF-03), publicada quando a
// resposta termina.
type HTTP3Request struct {
	StreamID        int64        `json:"stream_id"`
	PseudoOrder     []string     `json:"pseudo_order"`
	Fields          []QPACKField `json:"fields"`
	FieldsTruncated bool         `json:"fields_truncated"`
	ValuesTruncated bool         `json:"values_truncated"`
	JA4H            *string      `json:"ja4h"`
	BodyLen         int64        `json:"body_len"`
	Status          int          `json:"status"`
	// Controls segue o schema Controls do openapi (os controles de resposta do web).
	Controls json.RawMessage `json:"controls,omitempty"`
	// Instantes da requisição e da resposta (FormatTime, relógio do web; nulos quando não houve), contrato
	// 0.4.0, ADR 0029.
	RequestStartedAt  *string `json:"request_started_at"`
	RequestEndedAt    *string `json:"request_ended_at"`
	ResponseStartedAt *string `json:"response_started_at"`
	ResponseEndedAt   *string `json:"response_ended_at"`
}

// QPACKField é uma linha de campo QPACK como chegou (RFC 9204 4.5).
type QPACKField struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	Repr         string `json:"repr"` // indexed | indexed-post-base | literal-name-ref | literal-post-base-name-ref | literal
	Static       *bool  `json:"static"`
	Index        *int   `json:"index"`
	NeverIndexed *bool  `json:"never_indexed"`
	HuffmanName  *bool  `json:"huffman_name"`
	HuffmanValue *bool  `json:"huffman_value"`
}
