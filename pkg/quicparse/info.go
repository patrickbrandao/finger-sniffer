package quicparse

import "github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"

// MaxInitialFrames é o teto de `initial_frames` (spec 011, ADR 0018).
const MaxInitialFrames = 256

// Info é o campo `http3` do registro (schema HTTP3Info do openapi 0.3.0). O Assembler preenche a parte do
// Initial; h3_settings, close e requests vêm do serviço web.
type Info struct {
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
	ClientHello            *tlsparse.Info   `json:"client_hello"`
	H3Settings             [][2]uint64      `json:"h3_settings"`
	// H3ControlStreamSeen: o cliente abriu o stream de controle h3 (tipo 0x00) e o SETTINGS foi lido.
	H3ControlStreamSeen bool           `json:"h3_control_stream_seen"`
	Close               *Close         `json:"close"`
	Requests            []HTTP3Request `json:"requests"`
}

// Close é o fim da conexão QUIC visto pelo web (HTTP3Info.close).
type Close struct {
	// By: client, server ou unknown.
	By string `json:"by"`
	// How: connection_close, application_close, idle_timeout, stateless_reset ou handshake_failed.
	How       string  `json:"how"`
	ErrorCode *uint64 `json:"error_code"`
	Reason    *string `json:"reason"`
}

// Valores de Close.How.
const (
	CloseConnection      = "connection_close"
	CloseApplication     = "application_close"
	CloseIdleTimeout     = "idle_timeout"
	CloseStatelessReset  = "stateless_reset"
	CloseHandshakeFailed = "handshake_failed"
)

// HTTP3Request é uma requisição h3 (schema HTTP3Request). JA4H, Status e Controls são preenchidos pelo
// serviço web.
type HTTP3Request struct {
	StreamID        uint64       `json:"stream_id"`
	PseudoOrder     []string     `json:"pseudo_order"`
	Fields          []QPACKField `json:"fields"`
	FieldsTruncated bool         `json:"fields_truncated"`
	ValuesTruncated bool         `json:"values_truncated"`
	JA4H            *string      `json:"ja4h"`
	BodyLen         int64        `json:"body_len"`
	Status          int          `json:"status,omitempty"`
	Controls        any          `json:"controls,omitempty"`

	// HeadFields é quantos itens de Fields vieram do primeiro HEADERS (o resto são trailers).
	HeadFields int `json:"-"`
	// UnknownFrames conta os frames de tipo desconhecido ou reservado (GREASE incluído) no stream;
	// GREASEFrames conta só os GREASE.
	UnknownFrames int `json:"-"`
	GREASEFrames  int `json:"-"`
	// Frames são os tipos de frame na ordem (até MaxStreamFrames).
	Frames []uint64 `json:"-"`
}

// QPACKField é uma linha de campo com a sua representação QPACK (schema QPACKField). Static e Index são
// nulos no literal com nome literal; HuffmanName é nulo quando o nome veio de tabela, HuffmanValue é nulo
// no campo indexado. Numa referência à tabela dinâmica (static false) o que vem da tabela fica vazio.
type QPACKField struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	Repr         string `json:"repr"`
	Static       *bool  `json:"static"`
	Index        *int   `json:"index"`
	NeverIndexed *bool  `json:"never_indexed"`
	HuffmanName  *bool  `json:"huffman_name"`
	HuffmanValue *bool  `json:"huffman_value"`
}
