// Package tlsparse remonta e analisa o ClientHello TLS sem normalizar nada (spec 008 RF-01/RF-02).
//
// A ordem das cipher suites e das extensões, os valores GREASE e os dados crus de cada extensão são
// preservados como chegaram; a decodificação das extensões conhecidas vem ao lado dos bytes crus, nunca
// no lugar deles. O parser não depende de crypto/tls nem de utls e serve ao web, ao raw e ao ClientHello
// do QUIC Initial (spec 011).
package tlsparse

import (
	"errors"
	"fmt"
)

// ClientHello é o ClientHello analisado.
type ClientHello struct {
	// Raw é a mensagem de handshake completa (tipo, tamanho de 3 bytes e corpo), como foi remontada.
	Raw []byte
	// RecordVersion é a versão do primeiro registro TLS (0 quando a mensagem não veio em registros, ex.: QUIC).
	RecordVersion uint16
	// Records é quantos registros TLS carregaram a mensagem (0 fora de registros).
	Records int

	// HandshakeVersion é o legacy_version do ClientHello.
	HandshakeVersion uint16
	Random           []byte
	SessionID        []byte
	// CipherSuites na ordem recebida, GREASE incluído.
	CipherSuites       []uint16
	CompressionMethods []uint8
	// Extensions na ordem recebida, com os dados crus.
	Extensions []Extension

	// Decodificação das extensões conhecidas (ver extensions.go).

	// SNI é o primeiro host_name do server_name; HasSNI informa se a extensão está presente.
	SNI    string
	HasSNI bool
	ALPN   []string
	// SupportedGroups, ECPointFormats, SignatureAlgorithms e SupportedVersions na ordem recebida.
	SupportedGroups     []uint16
	ECPointFormats      []uint8
	SignatureAlgorithms []uint16
	// SignatureAlgorithmsCert: extensão signature_algorithms_cert (50).
	SignatureAlgorithmsCert []uint16
	SupportedVersions       []uint16
	KeyShares               []KeyShare
	PSKModes                []uint8
	// PreSharedKey: extensão pre_shared_key presente (retomada); PSKIdentities é o número de identidades.
	PreSharedKey  bool
	PSKIdentities int
	// EarlyData: extensão early_data presente (0-RTT).
	EarlyData bool
	// PaddingLen é o tamanho dos dados da extensão padding (-1 sem a extensão).
	PaddingLen          int
	CompressCertificate []uint16
	// RecordSizeLimit é o valor da extensão record_size_limit (-1 sem a extensão).
	RecordSizeLimit int
	// ALPS: protocolos das extensões application_settings (17513 e 17613), na ordem.
	ALPS []string
	// ALPSCodepoints: quais codepoints de ALPS vieram (17513 antigo, 17613 novo).
	ALPSCodepoints []uint16
	// EncryptedClientHello: extensão encrypted_client_hello (0xfe0d) presente.
	EncryptedClientHello bool
	// SessionTicket: extensão session_ticket presente; SessionTicketLen é o tamanho do ticket (> 0 = retomada).
	SessionTicket    bool
	SessionTicketLen int
	// StatusRequest: extensão status_request (OCSP) presente.
	StatusRequest bool
	// DelegatedCredentials: algoritmos da extensão delegated_credential (34).
	DelegatedCredentials []uint16
	// HasDelegatedCredentials informa se a extensão está presente.
	HasDelegatedCredentials bool

	// ExtensionErrors lista as extensões conhecidas cujos dados não puderam ser decodificados; os dados
	// crus continuam em Extensions.
	ExtensionErrors []error
}

// Extension é uma extensão do ClientHello como chegou.
type Extension struct {
	Type uint16
	Data []byte
}

// KeyShare é uma entrada do key_share: grupo e tamanho da chave.
type KeyShare struct {
	Group  uint16
	Length int
}

// ParseError descreve onde o ClientHello ficou ilegível.
type ParseError struct {
	// Field é o campo que estava sendo lido.
	Field string
	// Offset é a posição do campo dentro da mensagem de handshake.
	Offset int
	Err    error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("tlsparse: %s at offset %d: %v", e.Field, e.Offset, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// errShort indica que o campo acaba depois do fim dos dados.
var errShort = errors.New("truncated")

// Parse remonta o ClientHello a partir dos bytes do(s) registro(s) TLS e o analisa.
//
// Nunca devolve ClientHello nil: em caso de erro vem o que já foi analisado. Se a remontagem só não
// terminou por falta de bytes (ErrIncomplete), a parte recebida é analisada mesmo assim.
func Parse(records []byte) (*ClientHello, error) {
	r, rerr := Reassemble(records)
	ch, perr := ParseMessage(r.Message)
	ch.RecordVersion = r.RecordVersion
	ch.Records = r.Records
	if rerr != nil {
		return ch, rerr
	}
	return ch, perr
}

// ParseMessage analisa a mensagem de handshake ClientHello (tipo, tamanho de 3 bytes e corpo), já
// remontada; é a entrada usada pelo QUIC, cujo ClientHello vem em frames CRYPTO e não em registros.
func ParseMessage(msg []byte) (*ClientHello, error) {
	ch := &ClientHello{Raw: msg, PaddingLen: -1, RecordSizeLimit: -1}
	err := ch.parse(msg)
	return ch, err
}

func (ch *ClientHello) parse(msg []byte) error {
	if len(msg) < handshakeHeaderLen {
		return &ParseError{Field: "handshake header", Err: errShort}
	}
	if msg[0] != HandshakeTypeClientHello {
		return ErrNotClientHello
	}
	n := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[handshakeHeaderLen:]
	var truncated bool
	if len(body) > n {
		body = body[:n]
	} else if len(body) < n {
		truncated = true
	}
	s := reader{buf: body, base: handshakeHeaderLen}

	var ok bool
	if ch.HandshakeVersion, ok = s.u16(); !ok {
		return s.fail("legacy_version")
	}
	if ch.Random, ok = s.bytes(32); !ok {
		return s.fail("random")
	}
	if ch.SessionID, ok = s.vec8(); !ok {
		return s.fail("legacy_session_id")
	}
	cs, ok := s.vec16()
	if !ok {
		return s.fail("cipher_suites")
	}
	ch.CipherSuites = u16list(cs)
	cm, ok := s.vec8()
	if !ok {
		return s.fail("legacy_compression_methods")
	}
	ch.CompressionMethods = append([]uint8{}, cm...)
	if s.empty() {
		// ClientHello sem extensões (SSL 3.0, TLS 1.0 antigos)
		if truncated {
			return &ParseError{Field: "handshake body", Offset: s.pos(), Err: errShort}
		}
		return nil
	}
	exts, ok := s.vec16()
	if !ok {
		// lista de extensões cortada: aproveita as extensões inteiras que vieram
		start := s.pos()
		rest := s.rest()
		if len(rest) >= 2 {
			_ = ch.parseExtensions(reader{buf: rest[2:], base: start + 2}) // o erro de corte é o de baixo
		}
		return &ParseError{Field: "extensions", Offset: start, Err: errShort}
	}
	extStart := s.pos() - len(exts)
	if err := ch.parseExtensions(reader{buf: exts, base: extStart}); err != nil {
		return err
	}
	if truncated {
		return &ParseError{Field: "handshake body", Offset: s.pos(), Err: errShort}
	}
	return nil
}

// parseExtensions lê as extensões na ordem; uma extensão cortada encerra a lista.
func (ch *ClientHello) parseExtensions(s reader) error {
	for !s.empty() {
		start := s.pos()
		typ, ok := s.u16()
		if !ok {
			return &ParseError{Field: "extension type", Offset: start, Err: errShort}
		}
		data, ok := s.vec16()
		if !ok {
			return &ParseError{Field: fmt.Sprintf("extension 0x%04x", typ), Offset: start, Err: errShort}
		}
		ch.Extensions = append(ch.Extensions, Extension{Type: typ, Data: data})
		if err := ch.decodeExtension(typ, data); err != nil {
			ch.ExtensionErrors = append(ch.ExtensionErrors,
				&ParseError{Field: fmt.Sprintf("extension 0x%04x", typ), Offset: start, Err: err})
		}
	}
	return nil
}

// HasExtension informa se a extensão typ está presente.
func (ch *ClientHello) HasExtension(typ uint16) bool {
	for _, e := range ch.Extensions {
		if e.Type == typ {
			return true
		}
	}
	return false
}

// reader lê campos do TLS (RFC 8446 §3) sem pânico; base é a posição de buf dentro da mensagem.
type reader struct {
	buf  []byte
	off  int
	base int
}

func (r *reader) empty() bool    { return r.off >= len(r.buf) }
func (r *reader) pos() int       { return r.base + r.off }
func (r *reader) rest() []byte   { return r.buf[r.off:] }
func (r *reader) remaining() int { return len(r.buf) - r.off }

func (r *reader) fail(field string) error {
	return &ParseError{Field: field, Offset: r.pos(), Err: errShort}
}

func (r *reader) u8() (uint8, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	v := r.buf[r.off]
	r.off++
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := uint16(r.buf[r.off])<<8 | uint16(r.buf[r.off+1])
	r.off += 2
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.remaining() < 4 {
		return 0, false
	}
	b := r.buf[r.off:]
	r.off += 4
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	v := r.buf[r.off : r.off+n : r.off+n]
	r.off += n
	return v, true
}

// vec8 lê um vetor com tamanho de 1 byte; em falha não avança.
func (r *reader) vec8() ([]byte, bool) {
	save := r.off
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	v, ok := r.bytes(int(n))
	if !ok {
		r.off = save
	}
	return v, ok
}

// vec16 lê um vetor com tamanho de 2 bytes; em falha não avança.
func (r *reader) vec16() ([]byte, bool) {
	save := r.off
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	v, ok := r.bytes(int(n))
	if !ok {
		r.off = save
	}
	return v, ok
}

// u16list converte pares de bytes em uint16; um byte sobrando é ignorado.
func u16list(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}
