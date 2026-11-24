package tlsparse

import (
	"encoding/hex"
	"errors"

	"github.com/patrickbrandao/finger-sniffer/pkg/iana"
)

// DefaultInlineMax é o padrão de FS_EVENT_INLINE_MAX: bytes crus inline por campo (ADR 0018).
const DefaultInlineMax = 128 << 10

// Info é o campo `tls` do registro da conexão (schema TLSInfo do openapi, spec 008).
//
// Os campos ja3*/ja4* são preenchidos por pkg/fingerprint; negotiated, handshake_ms e alerts pelo serviço
// que fez o handshake; client_hello_segments pelo store (vem dos pacotes).
type Info struct {
	ClientHelloB64       []byte `json:"client_hello_b64"`
	ClientHelloTruncated bool   `json:"client_hello_truncated,omitempty"`
	// ListsTruncated marca que as listas analisadas e as strings longas dos fingerprints foram cortadas para
	// o evento caber no teto (ADR 0032); os fingerprints foram calculados antes do corte.
	ListsTruncated bool `json:"lists_truncated,omitempty"`
	// ExtensionErrors e FieldErrors são os erros de análise que não impediram o parse (extensão repetida ou
	// malformada, campo de tamanho ímpar; spec 008 RF-02), até MaxParseIssues cada (acima, lists_truncated).
	ExtensionErrors      []ParseIssue    `json:"extension_errors,omitempty"`
	FieldErrors          []ParseIssue    `json:"field_errors,omitempty"`
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

// MaxParseIssues é o teto de itens de extension_errors e field_errors (schema TLSInfo, maxItems).
const MaxParseIssues = 64

// Códigos estáveis de ParseIssue.Error (schema TLSParseIssue); nunca o texto do erro Go.
const (
	IssueDuplicate = "duplicate"
	IssueMalformed = "malformed"
	IssueOddLength = "odd_length"
)

// ParseIssue é um erro de análise do ClientHello que não impediu o parse (schema TLSParseIssue).
type ParseIssue struct {
	// Field é o ParseError.Field: "extension 0x%04x" ou o nome do campo (ex.: cipher_suites).
	Field string `json:"field"`
	// Offset é a posição do item contada do início da mensagem de handshake.
	Offset int `json:"offset"`
	// Error é o código: duplicate, malformed ou odd_length.
	Error string `json:"error"`
}

// parseIssues converte os erros do parser em ParseIssue com código estável, até MaxParseIssues itens; *cut
// liga quando sobrou erro. Erro sem ParseError (não acontece hoje) entra com campo e posição vazios.
func parseIssues(errs []error, cut *bool) []ParseIssue {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) > MaxParseIssues {
		errs = errs[:MaxParseIssues]
		*cut = true
	}
	out := make([]ParseIssue, 0, len(errs))
	for _, err := range errs {
		var it ParseIssue
		var pe *ParseError
		if errors.As(err, &pe) {
			it.Field, it.Offset = pe.Field, max(pe.Offset, 0)
		}
		switch {
		case errors.Is(err, ErrDuplicateExtension):
			it.Error = IssueDuplicate
		case errors.Is(err, ErrOddLength):
			it.Error = IssueOddLength
		default:
			it.Error = IssueMalformed
		}
		out = append(out, it)
	}
	return out
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
	cut := false
	in.ExtensionErrors = parseIssues(ch.ExtensionErrors, &cut)
	in.FieldErrors = parseIssues(ch.FieldErrors, &cut)
	in.ListsTruncated = cut
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

// Pisos do corte de Fit: abaixo deles as strings dos fingerprints e o inline não encolhem mais.
const (
	minFingerprintText = 256
	fitMaxRounds       = 64
)

// Fit serializa o Info com encode e, enquanto o resultado passar de limit bytes, reduz as listas analisadas
// pela metade e corta as strings longas ja3, ja3n, ja4_r e ja4_o, marcando lists_truncated; quando as listas
// já estão curtas, corta também o inline client_hello_b64 (client_hello_truncated). Os hashes (ja3_md5, ja4
// etc.) não mudam: vêm do ClientHello completo, calculados antes (ADR 0032, spec 008 RF-02). Devolve o
// último resultado de encode (nil se encode falhou); acima de limit só se nem o mínimo couber.
func (in *Info) Fit(encode func(*Info) []byte, limit int) []byte {
	data := encode(in)
	n := in.longestList() / 2
	text := 64 << 10
	for i := 0; i < fitMaxRounds && data != nil && len(data) > limit; i++ {
		in.limitLists(n)
		in.limitText(text)
		if n < 64 && len(in.ClientHelloB64) > 0 {
			// Listas já curtas e ainda acima do teto: o inline também encolhe.
			in.ClientHelloB64 = in.ClientHelloB64[:len(in.ClientHelloB64)/2]
			in.ClientHelloTruncated = true
		}
		n /= 2
		text = max(text/2, minFingerprintText)
		data = encode(in)
	}
	return data
}

func (in *Info) longestList() int {
	return max(len(in.CipherSuites), len(in.CompressionMethods), len(in.Extensions), len(in.ALPN),
		len(in.SupportedGroups), len(in.ECPointFormats), len(in.SignatureAlgorithms), len(in.SupportedVersions),
		len(in.KeyShare), len(in.PSKKeyExchangeModes), len(in.CompressCertificate), len(in.ALPS),
		len(in.DelegatedCredentials), len(in.ExtensionErrors), len(in.FieldErrors))
}

// limitLists corta cada lista analisada em no máximo n itens; as listas continuam não nulas.
func (in *Info) limitLists(n int) {
	n = max(n, 0)
	cut := false
	in.CipherSuites = limitList(in.CipherSuites, n, &cut)
	in.CompressionMethods = limitList(in.CompressionMethods, n, &cut)
	in.Extensions = limitList(in.Extensions, n, &cut)
	in.ALPN = limitList(in.ALPN, n, &cut)
	in.SupportedGroups = limitList(in.SupportedGroups, n, &cut)
	in.ECPointFormats = limitList(in.ECPointFormats, n, &cut)
	in.SignatureAlgorithms = limitList(in.SignatureAlgorithms, n, &cut)
	in.SupportedVersions = limitList(in.SupportedVersions, n, &cut)
	in.KeyShare = limitList(in.KeyShare, n, &cut)
	in.PSKKeyExchangeModes = limitList(in.PSKKeyExchangeModes, n, &cut)
	in.CompressCertificate = limitList(in.CompressCertificate, n, &cut)
	in.ALPS = limitList(in.ALPS, n, &cut)
	in.DelegatedCredentials = limitList(in.DelegatedCredentials, n, &cut)
	in.ExtensionErrors = limitList(in.ExtensionErrors, n, &cut)
	in.FieldErrors = limitList(in.FieldErrors, n, &cut)
	if cut {
		in.ListsTruncated = true
	}
}

// limitText corta as strings longas dos fingerprints (texto ASCII) em no máximo n bytes.
func (in *Info) limitText(n int) {
	for _, p := range []*string{&in.JA3, &in.JA3N, &in.JA4R, &in.JA4O} {
		if len(*p) > n {
			*p = (*p)[:n]
			in.ListsTruncated = true
		}
	}
}

// limitList devolve s com no máximo n itens (capacidade junto, para não reaproveitar o resto) e liga *cut
// quando cortou.
func limitList[T any](s []T, n int, cut *bool) []T {
	if len(s) <= n {
		return s
	}
	*cut = true
	return s[:n:n]
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
