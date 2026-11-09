package event

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
