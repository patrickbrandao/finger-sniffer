package quicparse

import (
	"errors"
	"fmt"
	"strings"
)

// Tipos de stream unidirecional do HTTP/3 (RFC 9114 seção 6.2, RFC 9204 seção 4.2).
const (
	StreamTypeControl      = 0x00
	StreamTypePush         = 0x01
	StreamTypeQPACKEncoder = 0x02
	StreamTypeQPACKDecoder = 0x03
)

// Tipos de frame do HTTP/3 (RFC 9114 seção 7.2).
const (
	H3FrameData        = 0x00
	H3FrameHeaders     = 0x01
	H3FrameCancelPush  = 0x03
	H3FrameSettings    = 0x04
	H3FramePushPromise = 0x05
	H3FrameGoaway      = 0x07
	H3FrameMaxPushID   = 0x0d
)

// Identificadores de SETTINGS do HTTP/3 (RFC 9114 seção 7.2.4.1, RFC 9204, RFC 9220, RFC 9297).
const (
	SettingQPACKMaxTableCapacity = 0x01
	SettingMaxFieldSectionSize   = 0x06
	SettingQPACKBlockedStreams   = 0x07
	SettingEnableConnectProtocol = 0x08
	SettingH3Datagram            = 0x33
)

// Limites padrão dos leitores de stream h3.
const (
	// DefaultMaxFrameBuffer limita o payload de HEADERS/SETTINGS guardado para decodificar.
	DefaultMaxFrameBuffer = 1 << 20
	// DefaultMaxSettings limita os pares do SETTINGS registrados.
	DefaultMaxSettings = 256
	// MaxStreamFrames limita a lista de tipos de frame guardada por stream.
	MaxStreamFrames = 256
)

// Erros dos leitores h3.
var (
	ErrH3FrameTooLarge = errors.New("quicparse: frame h3 acima do teto")
	ErrH3Settings      = errors.New("quicparse: SETTINGS h3 inválido")
)

// IsGREASEH3 informa se o tipo (de frame, stream ou setting) é reservado para GREASE: 0x1f * N + 0x21
// (RFC 9114 seções 6.2.3, 7.2.8 e 7.2.4.1).
func IsGREASEH3(t uint64) bool { return t >= 0x21 && (t-0x21)%0x1f == 0 }

// H3FrameName devolve o nome do tipo de frame h3.
func H3FrameName(t uint64) string {
	switch t {
	case H3FrameData:
		return "DATA"
	case H3FrameHeaders:
		return "HEADERS"
	case H3FrameCancelPush:
		return "CANCEL_PUSH"
	case H3FrameSettings:
		return "SETTINGS"
	case H3FramePushPromise:
		return "PUSH_PROMISE"
	case H3FrameGoaway:
		return "GOAWAY"
	case H3FrameMaxPushID:
		return "MAX_PUSH_ID"
	}
	if IsGREASEH3(t) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%x", t)
}

// frameReader separa frames h3 (tipo, tamanho, payload) de bytes que chegam em pedaços quaisquer. O
// payload só é guardado para os tipos que buffered aceita; os demais são contados e pulados.
type frameReader struct {
	hdr       []byte // bytes do cabeçalho ainda incompleto
	inFrame   bool
	typ       uint64
	length    uint64
	remaining uint64
	buf       []byte
	keep      bool
	maxBuf    int
	buffered  func(t uint64) bool
	onFrame   func(t, length uint64, payload []byte)
	onData    func(t uint64, n int)
	err       error
}

func (r *frameReader) feed(b []byte) {
	for len(b) > 0 && r.err == nil {
		if !r.inFrame {
			// cabeçalho: dois varints; junta com o que sobrou do pedaço anterior
			need := append(r.hdr, b[:min(len(b), 16)]...)
			t, n1, ok1 := ReadVarint(need)
			var l uint64
			var n2 int
			ok2 := false
			if ok1 {
				l, n2, ok2 = ReadVarint(need[n1:])
			}
			if !ok2 {
				r.hdr = append(r.hdr, b...)
				if len(r.hdr) > 16 {
					r.err = errShort // impossível: dois varints cabem em 16 bytes
				}
				return
			}
			used := n1 + n2 - len(r.hdr)
			b = b[used:]
			r.hdr = r.hdr[:0]
			r.inFrame, r.typ, r.length, r.remaining = true, t, l, l
			r.keep = r.buffered != nil && r.buffered(t)
			r.buf = r.buf[:0]
			if r.keep && l > uint64(r.maxBuf) { //nolint:gosec // maxBuf > 0
				r.err = fmt.Errorf("%w: %s com %d bytes", ErrH3FrameTooLarge, H3FrameName(t), l)
				return
			}
		}
		n := int(min(uint64(len(b)), r.remaining)) //nolint:gosec // limitado por len(b)
		if r.keep {
			r.buf = append(r.buf, b[:n]...)
		} else if n > 0 && r.onData != nil {
			r.onData(r.typ, n)
		}
		b = b[n:]
		r.remaining -= uint64(n)
		if r.remaining == 0 {
			r.inFrame = false
			var p []byte
			if r.keep {
				p = r.buf
			}
			if r.onFrame != nil {
				r.onFrame(r.typ, r.length, p)
			}
		}
	}
}

// UniStream lê um stream unidirecional do cliente: o tipo do stream e, no stream de controle, os frames
// (o primeiro deve ser SETTINGS). Os demais tipos (QPACK encoder/decoder, push, GREASE) só têm os bytes
// contados.
type UniStream struct {
	// StreamType é o tipo do stream; Typed informa se o varint do tipo já chegou.
	StreamType uint64
	Typed      bool
	// Settings são os pares [id, valor] do SETTINGS na ordem (GREASE incluído); SettingsSeen informa se o
	// frame SETTINGS chegou inteiro.
	Settings     [][2]uint64
	SettingsSeen bool
	// SettingsTruncated: mais de DefaultMaxSettings pares.
	SettingsTruncated bool
	// Frames são os tipos de frame do stream de controle na ordem (até MaxStreamFrames).
	Frames []uint64
	// Goaway é o id do último GOAWAY do cliente (nil sem GOAWAY).
	Goaway *uint64
	// Bytes é o total de bytes recebidos no stream (o tipo incluído).
	Bytes int64

	head []byte
	fr   frameReader
	err  error
}

// NewUniStream cria o leitor de um stream unidirecional.
func NewUniStream() *UniStream {
	u := &UniStream{Settings: [][2]uint64{}}
	u.fr = frameReader{
		maxBuf: DefaultMaxFrameBuffer,
		buffered: func(t uint64) bool {
			return t == H3FrameSettings || t == H3FrameGoaway
		},
		onFrame: u.onFrame,
	}
	return u
}

// Feed entrega mais bytes do stream.
func (u *UniStream) Feed(b []byte) {
	u.Bytes += int64(len(b))
	if !u.Typed {
		u.head = append(u.head, b[:min(len(b), 8)]...)
		v, n, ok := ReadVarint(u.head)
		if !ok {
			return
		}
		u.StreamType, u.Typed = v, true
		b = b[n-(len(u.head)-min(len(b), 8)):]
		u.head = nil
	}
	if u.StreamType != StreamTypeControl || len(b) == 0 {
		return
	}
	u.fr.feed(b)
}

func (u *UniStream) onFrame(t, _ uint64, p []byte) {
	if len(u.Frames) < MaxStreamFrames {
		u.Frames = append(u.Frames, t)
	}
	switch t {
	case H3FrameSettings:
		if u.SettingsSeen {
			return
		}
		u.SettingsSeen = true
		r := reader{buf: p}
		for !r.empty() {
			id := r.varint()
			v := r.varint()
			if r.bad {
				u.err = ErrH3Settings
				return
			}
			if len(u.Settings) >= DefaultMaxSettings {
				u.SettingsTruncated = true
				continue
			}
			u.Settings = append(u.Settings, [2]uint64{id, v})
		}
	case H3FrameGoaway:
		if v, _, ok := ReadVarint(p); ok {
			u.Goaway = &v
		}
	}
}

// Err devolve o primeiro erro de leitura (frame grande demais, SETTINGS ilegível).
func (u *UniStream) Err() error {
	if u.err != nil {
		return u.err
	}
	return u.fr.err
}

// RequestStream lê um stream bidirecional de requisição do cliente: o primeiro HEADERS dá os campos e a
// ordem dos pseudo-cabeçalhos, HEADERS seguintes são trailers (acrescentados a Fields), DATA é contado em
// BodyLen e frames desconhecidos ou GREASE são contados.
type RequestStream struct {
	// Request é a requisição montada até agora.
	Request HTTP3Request
	// Prefix é o prefixo QPACK do primeiro HEADERS.
	Prefix FieldSectionPrefix
	// HeadersSeen informa se o primeiro HEADERS chegou inteiro.
	HeadersSeen bool

	maxFields int
	fr        frameReader
	err       error
}

// NewRequestStream cria o leitor do stream id. maxFields <= 0 usa DefaultMaxFieldsPerSection.
func NewRequestStream(id uint64, maxFields int) *RequestStream {
	if maxFields <= 0 {
		maxFields = DefaultMaxFieldsPerSection
	}
	s := &RequestStream{
		Request:   HTTP3Request{StreamID: id, PseudoOrder: []string{}, Fields: []QPACKField{}},
		maxFields: maxFields,
	}
	s.fr = frameReader{
		maxBuf:   DefaultMaxFrameBuffer,
		buffered: func(t uint64) bool { return t == H3FrameHeaders },
		onFrame:  s.onFrame,
		onData: func(t uint64, n int) {
			if t == H3FrameData {
				s.Request.BodyLen += int64(n)
			}
		},
	}
	return s
}

// Feed entrega mais bytes do stream.
func (s *RequestStream) Feed(b []byte) { s.fr.feed(b) }

func (s *RequestStream) onFrame(t, _ uint64, p []byte) {
	r := &s.Request
	if len(r.Frames) < MaxStreamFrames {
		r.Frames = append(r.Frames, t)
	}
	switch t {
	case H3FrameData:
	case H3FrameHeaders:
		left := s.maxFields - len(r.Fields)
		if left <= 0 {
			r.FieldsTruncated = true
			return
		}
		prefix, fields, err := DecodeFieldSection(p, left)
		if errors.Is(err, ErrQPACKFieldsLimit) {
			r.FieldsTruncated = true
		} else if err != nil && s.err == nil {
			s.err = err
		}
		r.Fields = append(r.Fields, fields...)
		if !s.HeadersSeen {
			s.HeadersSeen = true
			s.Prefix = prefix
			r.HeadFields = len(r.Fields)
			for _, f := range fields {
				if strings.HasPrefix(f.Name, ":") {
					r.PseudoOrder = append(r.PseudoOrder, f.Name)
				}
			}
		}
	default:
		r.UnknownFrames++
		if IsGREASEH3(t) {
			r.GREASEFrames++
		}
	}
}

// Err devolve o primeiro erro de leitura (frame grande demais, QPACK ilegível).
func (s *RequestStream) Err() error {
	if s.err != nil {
		return s.err
	}
	return s.fr.err
}
