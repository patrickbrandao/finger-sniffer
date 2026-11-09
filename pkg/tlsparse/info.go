package tlsparse

import (
	"encoding/hex"

	"github.com/patrickbrandao/finger-sniffer/pkg/iana"
)

// DefaultInlineMax é o padrão de FS_EVENT_INLINE_MAX: bytes crus inline por campo (ADR 0018).
const DefaultInlineMax = 128 << 10

// Info é o campo `tls` do registro da conexão (schema TLSInfo do openapi, spec 008).
//
// Os campos ja3*/ja4* são preenchidos por pkg/fingerprint; negotiated, handshake_ms e alerts pelo serviço
// que fez o handshake; client_hello_segments pelo store (vem dos pacotes).
type Info struct {
	ClientHelloB64       []byte          `json:"client_hello_b64"`
	ClientHelloTruncated bool            `json:"client_hello_truncated,omitempty"`
	ClientHelloRecords   int             `json:"client_hello_records"`
	ClientHelloSegments  int             `json:"client_hello_segments,omitempty"`
	RecordVersion        int             `json:"record_version"`
	HandshakeVersion     int             `json:"handshake_version"`
	RandomHex            string          `json:"random_hex"`
	SessionIDLen         int             `json:"session_id_len"`
	CipherSuites         []CodeName      `json:"cipher_suites"`
	CompressionMethods   []int           `json:"compression_methods"`
	Extensions           []ExtensionInfo `json:"extensions"`
	SNI                  *string         `json:"sni"`
	ALPN                 []string        `json:"alpn"`
	SupportedGroups      []CodeName      `json:"supported_groups"`
	ECPointFormats       []int           `json:"ec_point_formats"`
	SignatureAlgorithms  []CodeName      `json:"signature_algorithms"`
	SupportedVersions    []CodeName      `json:"supported_versions"`
	KeyShare             []KeyShareInfo  `json:"key_share"`
	PSKKeyExchangeModes  []int           `json:"psk_key_exchange_modes"`
	PreSharedKey         bool            `json:"pre_shared_key"`
	EarlyData            bool            `json:"early_data"`
	PaddingLen           *int            `json:"padding_len"`
	CompressCertificate  []int           `json:"compress_certificate"`
	RecordSizeLimit      *int            `json:"record_size_limit"`
	ALPS                 []string        `json:"alps"`
	EncryptedClientHello bool            `json:"encrypted_client_hello"`
	SessionTicket        bool            `json:"session_ticket"`
	StatusRequest        bool            `json:"status_request"`
	DelegatedCredentials []CodeName      `json:"delegated_credentials"`
	JA3                  string          `json:"ja3,omitempty"`
	JA3MD5               string          `json:"ja3_md5,omitempty"`
	JA3N                 string          `json:"ja3n,omitempty"`
	JA3NMD5              string          `json:"ja3n_md5,omitempty"`
	JA4                  string          `json:"ja4,omitempty"`
	JA4R                 string          `json:"ja4_r,omitempty"`
	JA4O                 string          `json:"ja4_o,omitempty"`
	JA4Stable            string          `json:"ja4_stable,omitempty"`
	Negotiated           *Negotiated     `json:"negotiated"`
	HandshakeMs          *float64        `json:"handshake_ms"`
	Alerts               []Alert         `json:"alerts"`
}

// CodeName é um código com o nome IANA legível (schema CodeName).
type CodeName struct {
	Code   int    `json:"code"`
	Name   string `json:"name,omitempty"`
	GREASE bool   `json:"grease,omitempty"`
}

// ExtensionInfo é uma extensão na ordem recebida (schema TLSExtension).
type ExtensionInfo struct {
	Type    int    `json:"type"`
	Name    string `json:"name,omitempty"`
	GREASE  bool   `json:"grease,omitempty"`
	DataHex string `json:"data_hex"`
}

// KeyShareInfo é uma entrada do key_share: grupo e tamanho da chave.
type KeyShareInfo struct {
	Group  CodeName `json:"group"`
	Length int      `json:"length"`
}

// Negotiated é o resultado do handshake (spec 008 RF-04).
type Negotiated struct {
	Version string  `json:"version"`
	Cipher  string  `json:"cipher"`
	Group   string  `json:"group"`
	ALPN    *string `json:"alpn"`
	Resumed bool    `json:"resumed"`
}

// Alert é um alerta TLS recebido (in) ou enviado (out).
type Alert struct {
	Dir         string `json:"dir"`
	Level       int    `json:"level"`
	Description int    `json:"description"`
	Name        string `json:"name,omitempty"`
}

// NewAlert monta um Alert com o nome IANA da descrição.
func NewAlert(dir string, level, description uint8) Alert {
	return Alert{Dir: dir, Level: int(level), Description: int(description), Name: iana.Alert(description)}
}

func codeName(v uint16, name func(uint16) string) CodeName {
	return CodeName{Code: int(v), Name: name(v), GREASE: iana.IsGREASE(v)}
}

func codeNames(vs []uint16, name func(uint16) string) []CodeName {
	out := make([]CodeName, 0, len(vs))
	for _, v := range vs {
		out = append(out, codeName(v, name))
	}
	return out
}

func ints[T uint8 | uint16](vs []T) []int {
	out := make([]int, 0, len(vs))
	for _, v := range vs {
		out = append(out, int(v))
	}
	return out
}

// NewInfo monta o Info a partir do ClientHello analisado e dos bytes crus do(s) registro(s). records vai
// inline em client_hello_b64 até inlineMax bytes (FS_EVENT_INLINE_MAX; <= 0 usa DefaultInlineMax); acima
// disso o campo é cortado e client_hello_truncated fica true (ADR 0018). As listas saem sempre não nulas.
func NewInfo(ch *ClientHello, records []byte, inlineMax int) *Info {
	if inlineMax <= 0 {
		inlineMax = DefaultInlineMax
	}
	in := &Info{
		ClientHelloB64:       records,
		ClientHelloRecords:   ch.Records,
		RecordVersion:        int(ch.RecordVersion),
		HandshakeVersion:     int(ch.HandshakeVersion),
		RandomHex:            hex.EncodeToString(ch.Random),
		SessionIDLen:         len(ch.SessionID),
		CipherSuites:         codeNames(ch.CipherSuites, iana.CipherSuite),
		CompressionMethods:   ints(ch.CompressionMethods),
		Extensions:           make([]ExtensionInfo, 0, len(ch.Extensions)),
		ALPN:                 nonNil(ch.ALPN),
		SupportedGroups:      codeNames(ch.SupportedGroups, iana.Group),
		ECPointFormats:       ints(ch.ECPointFormats),
		SignatureAlgorithms:  codeNames(ch.SignatureAlgorithms, iana.SignatureScheme),
		SupportedVersions:    codeNames(ch.SupportedVersions, iana.Version),
		KeyShare:             make([]KeyShareInfo, 0, len(ch.KeyShares)),
		PSKKeyExchangeModes:  ints(ch.PSKModes),
		PreSharedKey:         ch.PreSharedKey,
		EarlyData:            ch.EarlyData,
		CompressCertificate:  ints(ch.CompressCertificate),
		ALPS:                 nonNil(ch.ALPS),
		EncryptedClientHello: ch.EncryptedClientHello,
		SessionTicket:        ch.SessionTicket,
		StatusRequest:        ch.StatusRequest,
		DelegatedCredentials: codeNames(ch.DelegatedCredentials, iana.SignatureScheme),
		Alerts:               []Alert{},
	}
	if in.ClientHelloB64 == nil {
		in.ClientHelloB64 = []byte{}
	}
	if len(records) > inlineMax {
		in.ClientHelloB64 = records[:inlineMax]
		in.ClientHelloTruncated = true
	}
	for _, e := range ch.Extensions {
		in.Extensions = append(in.Extensions, ExtensionInfo{
			Type:    int(e.Type),
			Name:    iana.Extension(e.Type),
			GREASE:  iana.IsGREASE(e.Type),
			DataHex: hex.EncodeToString(e.Data),
		})
	}
	for _, k := range ch.KeyShares {
		in.KeyShare = append(in.KeyShare, KeyShareInfo{Group: codeName(k.Group, iana.Group), Length: k.Length})
	}
	if ch.HasSNI {
		s := ch.SNI
		in.SNI = &s
	}
	if ch.PaddingLen >= 0 {
		v := ch.PaddingLen
		in.PaddingLen = &v
	}
	if ch.RecordSizeLimit >= 0 {
		v := ch.RecordSizeLimit
		in.RecordSizeLimit = &v
	}
	return in
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
