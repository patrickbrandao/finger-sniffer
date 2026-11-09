// Package h2passive lê passivamente uma cópia dos bytes de um sentido de uma conexão HTTP/2 (spec 010) e
// extrai o que o servidor `x/net/http2` esconde: SETTINGS na ordem recebida (com ids repetidos), o
// WINDOW_UPDATE inicial, frames PRIORITY e a prioridade dos HEADERS, a ordem dos pseudo-cabeçalhos e dos
// campos, a representação HPACK de cada campo e a lista de frames com tamanho e tempo.
//
// O parser nunca devolve erro ao consumidor dos bytes: entrada malformada vira um registro parcial e
// [Parser.Err] diz por que a leitura parou. Os frames são lidos aqui mesmo (cabeçalho de 9 bytes, RFC 9113
// seção 4.1) em vez do `http2.Framer`, porque o Framer rejeita frames que violam o protocolo e o espelho
// precisa registrar justamente esses; do x/net vem só a decodificação Huffman do HPACK.
package h2passive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Preface é o prefácio da conexão enviado pelo cliente (RFC 9113 seção 3.4).
const Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Sentidos dos bytes, como em `H2Frame.dir`.
const (
	DirIn  = "in"
	DirOut = "out"
)

// Modos de chegada ao h2, como em `HTTP2Info.mode`.
const (
	ModeALPN           = "alpn"
	ModePriorKnowledge = "prior-knowledge"
	ModeUpgrade        = "upgrade"
)

// Tipos de frame (RFC 9113 seção 6 e registro IANA).
const (
	FrameData         = 0x0
	FrameHeaders      = 0x1
	FramePriority     = 0x2
	FrameRSTStream    = 0x3
	FrameSettings     = 0x4
	FramePushPromise  = 0x5
	FramePing         = 0x6
	FrameGoAway       = 0x7
	FrameWindowUpdate = 0x8
	FrameContinuation = 0x9
)

// Flags usadas aqui.
const (
	FlagEndStream  = 0x1
	FlagAck        = 0x1
	FlagEndHeaders = 0x4
	FlagPadded     = 0x8
	FlagPriority   = 0x20
)

const frameHeaderLen = 9

// Erros que encerram a leitura (ver [Parser.Err]).
var (
	ErrBadPreface        = errors.New("h2passive: prefácio HTTP/2 ausente ou inválido")
	ErrHeaderBlockLimit  = errors.New("h2passive: bloco de cabeçalho acima do limite")
	ErrContinuationOrder = errors.New("h2passive: frame intercalado num bloco de cabeçalho")
	ErrMalformedHeaders  = errors.New("h2passive: frame HEADERS malformado")
)

var frameNames = map[uint8]string{
	FrameData:         "DATA",
	FrameHeaders:      "HEADERS",
	FramePriority:     "PRIORITY",
	FrameRSTStream:    "RST_STREAM",
	FrameSettings:     "SETTINGS",
	FramePushPromise:  "PUSH_PROMISE",
	FramePing:         "PING",
	FrameGoAway:       "GOAWAY",
	FrameWindowUpdate: "WINDOW_UPDATE",
	FrameContinuation: "CONTINUATION",
	0xa:               "ALTSVC",
	0xc:               "ORIGIN",
	0x10:              "PRIORITY_UPDATE",
}

// FrameTypeName devolve o nome do tipo de frame; tipos desconhecidos viram `UNKNOWN_0xNN`.
func FrameTypeName(t uint8) string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN_0x%02x", t)
}

// HPACKField é um campo de cabeçalho com a sua representação HPACK (schema `HPACKField`). Index é o índice
// da entrada (campo indexado) ou do nome (literal com nome indexado), nulo para nome literal; HuffmanName é
// nulo quando o nome veio da tabela e HuffmanValue é nulo no campo indexado.
type HPACKField struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	Repr         string `json:"repr"`
	Index        *int   `json:"index"`
	HuffmanName  *bool  `json:"huffman_name"`
	HuffmanValue *bool  `json:"huffman_value"`
}

// H2Frame é um frame visto (schema `H2Frame`). TMs é o tempo do pedaço em que chegou o primeiro byte do
// frame; Length é o tamanho do payload declarado no cabeçalho.
type H2Frame struct {
	Dir      string  `json:"dir"`
	TMs      float64 `json:"t_ms"`
	Type     string  `json:"type"`
	Flags    uint8   `json:"flags"`
	StreamID uint32  `json:"stream_id"`
	Length   uint32  `json:"length"`
}

// StreamPriority é a prioridade de um HEADERS com a flag PRIORITY. Weight é o peso real (1..256), isto é,
// o valor do fio + 1 (RFC 7540 seção 6.3), como no fingerprint Akamai.
type StreamPriority struct {
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    int    `json:"weight"`
}

// Priority é um frame PRIORITY (item de `HTTP2Info.priorities`). Weight segue a regra de [StreamPriority].
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    int    `json:"weight"`
}

// HTTP2Stream é o que se viu de um stream (schema `HTTP2Stream`). JA4H, Status e Controls são preenchidos
// por quem monta o registro (serviço web); o parser preenche Status no sentido `out` a partir de `:status`.
type HTTP2Stream struct {
	StreamID    uint32          `json:"stream_id"`
	PseudoOrder []string        `json:"pseudo_order"`
	Fields      []HPACKField    `json:"fields"`
	Priority    *StreamPriority `json:"priority"`
	EndStream   bool            `json:"end_stream"`
	JA4H        *string         `json:"ja4h"`
	Status      int             `json:"status,omitempty"`
	Controls    any             `json:"controls,omitempty"`
	// Instantes da requisição e da resposta (RFC 3339 UTC com ns, relógio do web; nulos quando não houve),
	// preenchidos por quem monta o registro a partir de HeadersAt/EndAt/ResetAt dos dois sentidos (spec 010
	// RF-08, ADR 0029).
	RequestStartedAt  *string `json:"request_started_at"`
	RequestEndedAt    *string `json:"request_ended_at"`
	ResponseStartedAt *string `json:"response_started_at"`
	ResponseEndedAt   *string `json:"response_ended_at"`

	// HeadFields é quantos itens de Fields vieram do primeiro bloco (o resto são trailers).
	HeadFields int `json:"-"`
	// HeadersAt, EndAt e ResetAt são os instantes (de FeedAt) em que terminaram, neste sentido, o primeiro
	// frame HEADERS do stream, o frame com END_STREAM e o RST_STREAM; zero quando não houve (ou com Feed).
	HeadersAt time.Time `json:"-"`
	EndAt     time.Time `json:"-"`
	ResetAt   time.Time `json:"-"`
}

// HTTP2Info é o resultado da análise de uma conexão (schema `HTTP2Info`). Akamai é preenchido por
// `pkg/fingerprint/akamai`.
type HTTP2Info struct {
	Mode                 string        `json:"mode,omitempty"`
	PrefaceOK            bool          `json:"preface_ok"`
	Settings             [][2]uint32   `json:"settings"`
	WindowUpdate         *uint32       `json:"window_update"`
	Priorities           []Priority    `json:"priorities"`
	PriorityFramesCapped bool          `json:"priority_frames_capped"`
	Akamai               string        `json:"akamai"`
	Streams              []HTTP2Stream `json:"streams"`
	Frames               []H2Frame     `json:"frames"`
	FramesTruncated      bool          `json:"frames_truncated"`

	// PrioritiesBeforeHeaders é quantos itens de Priorities chegaram antes do primeiro HEADERS (os que entram
	// no Akamai).
	PrioritiesBeforeHeaders int `json:"-"`
	// FirstHeadersStream é o stream do primeiro HEADERS (0 se nenhum).
	FirstHeadersStream uint32 `json:"-"`
	// PriorityFrames é o total de frames PRIORITY vistos, inclusive os não registrados.
	PriorityFrames int `json:"-"`
	// FrameCount é o total de frames vistos, inclusive os cortados da lista.
	FrameCount int `json:"-"`
}

// Options configura o parser.
type Options struct {
	// Dir é o sentido dos bytes: DirIn (cliente → servidor, começa pelo prefácio) ou DirOut.
	Dir string
	// Mode vai para HTTP2Info.Mode.
	Mode string
	// SkipPreface diz que os bytes de entrada já não têm o prefácio.
	SkipPreface bool
	// HeaderTableSize é o SETTINGS_HEADER_TABLE_SIZE anunciado pelo receptor destes bytes (0 = 4096).
	HeaderTableSize uint32
	// Limits são os tetos; o valor zero usa DefaultLimits().
	Limits Limits
}

// Parser consome os bytes de um sentido em pedaços (Feed) e acumula o HTTP2Info.
type Parser struct {
	opts Options
	lim  Limits
	info HTTP2Info
	dec  *hpackDecoder
	err  error

	preface []byte // bytes do prefácio ainda em verificação
	inPref  bool

	hdr     [frameHeaderLen]byte
	hdrN    int
	hdrT    float64
	at      time.Time // instante do pedaço em consumo (FeedAt)
	need    int       // bytes do payload ainda por vir
	keep    bool      // se o payload atual é guardado
	payload []byte    // payload guardado do frame atual
	cur     frameHeader

	// bloco de cabeçalho em montagem (HEADERS sem END_HEADERS + CONTINUATION)
	blockStream uint32
	block       []byte
	blockOpen   bool
	hpackDead   bool

	streams     map[uint32]int
	settingsSet bool
	seenHeaders bool
}

type frameHeader struct {
	length   uint32
	typ      uint8
	flags    uint8
	streamID uint32
}

// NewParser cria um parser.
func NewParser(opts Options) *Parser {
	if opts.Dir == "" {
		opts.Dir = DirIn
	}
	lim := opts.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	lim = lim.normalize()
	ts := opts.HeaderTableSize
	if ts == 0 {
		ts = DefaultHeaderTableSize
	}
	p := &Parser{
		opts:    opts,
		lim:     lim,
		dec:     newHPACKDecoder(ts, lim.MaxFieldsPerBlock),
		streams: map[uint32]int{},
		inPref:  opts.Dir == DirIn && !opts.SkipPreface,
	}
	p.info.Mode = opts.Mode
	p.info.PrefaceOK = !p.inPref
	return p
}

// Parse analisa um sentido inteiro de uma vez, com tempo zero em todos os frames.
func Parse(b []byte, opts Options) *HTTP2Info {
	p := NewParser(opts)
	p.Feed(0, b)
	return p.Info()
}

// Err devolve o motivo pelo qual a leitura (ou a decodificação HPACK) parou, ou nil.
func (p *Parser) Err() error { return p.err }

// Info devolve o resultado acumulado até aqui. As listas nunca são nulas (viram `[]` no JSON).
func (p *Parser) Info() *HTTP2Info {
	out := p.info
	if out.Settings == nil {
		out.Settings = [][2]uint32{}
	}
	if out.Priorities == nil {
		out.Priorities = []Priority{}
	}
	if out.Streams == nil {
		out.Streams = []HTTP2Stream{}
	}
	if out.Frames == nil {
		out.Frames = []H2Frame{}
	}
	for i := range out.Streams {
		if out.Streams[i].PseudoOrder == nil {
			out.Streams[i].PseudoOrder = []string{}
		}
		if out.Streams[i].Fields == nil {
			out.Streams[i].Fields = []HPACKField{}
		}
	}
	return &out
}

// Feed consome mais um pedaço de bytes que chegou no instante tMs (milissegundos desde a referência do
// chamador).
func (p *Parser) Feed(tMs float64, b []byte) {
	p.FeedAt(time.Time{}, tMs, b)
}

// FeedAt é o Feed com o instante absoluto do pedaço, que vai para HeadersAt, EndAt e ResetAt dos streams.
func (p *Parser) FeedAt(at time.Time, tMs float64, b []byte) {
	p.at = at
	if p.inPref {
		b = p.feedPreface(b)
		if p.inPref || p.err != nil {
			return
		}
	}
	if errors.Is(p.err, ErrBadPreface) {
		return
	}
	for len(b) > 0 {
		if p.need == 0 && p.hdrN < frameHeaderLen {
			if p.hdrN == 0 {
				p.hdrT = tMs
			}
			n := copy(p.hdr[p.hdrN:], b)
			p.hdrN += n
			b = b[n:]
			if p.hdrN < frameHeaderLen {
				return
			}
			p.startFrame()
			if p.need == 0 {
				p.endFrame()
			}
			continue
		}
		n := min(p.need, len(b))
		if p.keep {
			p.payload = append(p.payload, b[:n]...)
		}
		p.need -= n
		b = b[n:]
		if p.need == 0 {
			p.endFrame()
		}
	}
}

// feedPreface confere o prefácio e devolve o que sobrou depois dele.
func (p *Parser) feedPreface(b []byte) []byte {
	n := min(len(Preface)-len(p.preface), len(b))
	p.preface = append(p.preface, b[:n]...)
	if string(p.preface) != Preface[:len(p.preface)] {
		p.inPref = false
		p.err = ErrBadPreface
		return nil
	}
	if len(p.preface) < len(Preface) {
		return nil
	}
	p.inPref = false
	p.info.PrefaceOK = true
	return b[n:]
}

// startFrame registra o frame cujo cabeçalho acabou de chegar e decide se o payload é guardado.
func (p *Parser) startFrame() {
	h := frameHeader{
		length:   uint32(p.hdr[0])<<16 | uint32(p.hdr[1])<<8 | uint32(p.hdr[2]),
		typ:      p.hdr[3],
		flags:    p.hdr[4],
		streamID: binary.BigEndian.Uint32(p.hdr[5:9]) & 0x7fffffff,
	}
	p.cur = h
	p.need = int(h.length)
	p.payload = p.payload[:0]
	p.info.FrameCount++
	if len(p.info.Frames) < p.lim.MaxFrames {
		p.info.Frames = append(p.info.Frames, H2Frame{
			Dir: p.opts.Dir, TMs: p.hdrT, Type: FrameTypeName(h.typ), Flags: h.flags,
			StreamID: h.streamID, Length: h.length,
		})
	} else {
		p.info.FramesTruncated = true
	}
	switch h.typ {
	case FrameSettings:
		p.keep = !p.settingsSet && h.flags&FlagAck == 0 && int(h.length) <= p.lim.MaxSettings*6
	case FrameWindowUpdate, FramePriority:
		p.keep = h.length <= 16
	case FrameHeaders:
		// guardado mesmo com o HPACK parado, para ler a prioridade
		p.keep = int(h.length) <= p.lim.MaxHeaderBlock
		if !p.keep && !p.hpackDead {
			p.killHPACK(ErrHeaderBlockLimit)
		}
	case FrameContinuation:
		p.keep = p.blockOpen && len(p.block)+int(h.length) <= p.lim.MaxHeaderBlock
		if p.blockOpen && !p.keep {
			p.killHPACK(ErrHeaderBlockLimit)
		}
	default:
		p.keep = false
	}
}

// endFrame processa o frame completo.
func (p *Parser) endFrame() {
	h := p.cur
	pl := p.payload
	p.hdrN = 0
	if p.blockOpen && (h.typ != FrameContinuation || h.streamID != p.blockStream) {
		// RFC 9113 seção 6.10: só CONTINUATION do mesmo stream pode seguir um bloco aberto
		p.killHPACK(ErrContinuationOrder)
	}
	switch h.typ {
	case FrameSettings:
		if p.keep && len(pl)%6 == 0 {
			p.settingsSet = true
			p.info.Settings = make([][2]uint32, 0, len(pl)/6)
			for i := 0; i+6 <= len(pl); i += 6 {
				p.info.Settings = append(p.info.Settings, [2]uint32{
					uint32(binary.BigEndian.Uint16(pl[i:])), binary.BigEndian.Uint32(pl[i+2:]),
				})
			}
		}
	case FrameWindowUpdate:
		if h.streamID == 0 && !p.seenHeaders && p.info.WindowUpdate == nil && len(pl) == 4 {
			v := binary.BigEndian.Uint32(pl) & 0x7fffffff
			p.info.WindowUpdate = &v
		}
	case FramePriority:
		p.info.PriorityFrames++
		if len(pl) != 5 {
			break
		}
		if len(p.info.Priorities) >= p.lim.MaxPriorityFrames {
			p.info.PriorityFramesCapped = true
			break
		}
		sp := parsePriority(pl)
		p.info.Priorities = append(p.info.Priorities, Priority{
			StreamID: h.streamID, Exclusive: sp.Exclusive, DependsOn: sp.DependsOn, Weight: sp.Weight,
		})
		if !p.seenHeaders {
			p.info.PrioritiesBeforeHeaders = len(p.info.Priorities)
		}
	case FrameData:
		if i, ok := p.streams[h.streamID]; ok && h.flags&FlagEndStream != 0 {
			p.info.Streams[i].EndStream = true
			stamp(&p.info.Streams[i].EndAt, p.at)
		}
	case FrameRSTStream:
		// No sentido out o stream é criado se preciso (reset antes de qualquer HEADERS do servidor); no in só
		// streams já vistos, para não inventar requisições.
		if i, ok := p.streams[h.streamID]; ok {
			stamp(&p.info.Streams[i].ResetAt, p.at)
		} else if p.opts.Dir == DirOut && h.streamID != 0 {
			if st := p.stream(h.streamID); st != nil {
				stamp(&st.ResetAt, p.at)
			}
		}
	case FrameHeaders:
		p.onHeaders(h, pl)
	case FrameContinuation:
		if p.blockOpen && p.keep {
			p.block = append(p.block, pl...)
			if h.flags&FlagEndHeaders != 0 {
				p.finishBlock()
			}
		}
	}
	p.keep = false
}

// onHeaders trata um frame HEADERS: prioridade, padding e início do bloco.
func (p *Parser) onHeaders(h frameHeader, pl []byte) {
	if !p.seenHeaders {
		p.seenHeaders = true
		p.info.FirstHeadersStream = h.streamID
	}
	st := p.stream(h.streamID)
	frag := pl
	var prio *StreamPriority
	ok := p.keep
	if ok && h.flags&FlagPadded != 0 {
		if len(frag) < 1 {
			ok = false
		} else {
			pad := int(frag[0])
			frag = frag[1:]
			if pad > len(frag) {
				ok = false
			} else {
				frag = frag[:len(frag)-pad]
			}
		}
	}
	if ok && h.flags&FlagPriority != 0 {
		if len(frag) < 5 {
			ok = false
		} else {
			sp := parsePriority(frag[:5])
			prio = &sp
			frag = frag[5:]
		}
	}
	if st != nil {
		if prio != nil && st.Priority == nil {
			st.Priority = prio
		}
		stamp(&st.HeadersAt, p.at)
		if h.flags&FlagEndStream != 0 {
			st.EndStream = true
			stamp(&st.EndAt, p.at)
		}
	}
	if !p.keep || p.hpackDead {
		return
	}
	if !ok {
		p.killHPACK(ErrMalformedHeaders)
		return
	}
	p.blockStream = h.streamID
	p.block = append(p.block[:0], frag...)
	p.blockOpen = true
	if h.flags&FlagEndHeaders != 0 {
		p.finishBlock()
	}
}

// finishBlock decodifica o bloco montado e anexa os campos ao stream.
func (p *Parser) finishBlock() {
	p.blockOpen = false
	fields, err := p.dec.decode(p.block)
	p.block = p.block[:0]
	st := p.stream(p.blockStream)
	if st != nil {
		first := st.HeadFields == 0 && len(st.Fields) == 0
		for _, f := range fields {
			if first && len(f.Name) > 0 && f.Name[0] == ':' {
				st.PseudoOrder = append(st.PseudoOrder, f.Name)
				if f.Name == ":status" && p.opts.Dir == DirOut {
					if s, e := strconv.Atoi(f.Value); e == nil {
						st.Status = s
					}
				}
			}
		}
		st.Fields = append(st.Fields, fields...)
		if first {
			st.HeadFields = len(st.Fields)
		}
	}
	if err != nil {
		p.killHPACK(err)
	}
}

// killHPACK para a decodificação HPACK da conexão: sem o bloco perdido a tabela dinâmica não é mais
// confiável. Os frames continuam sendo registrados.
func (p *Parser) killHPACK(err error) {
	p.hpackDead = true
	p.blockOpen = false
	p.block = nil
	if p.err == nil {
		p.err = err
	}
}

// stream devolve o stream registrado (criando-o) ou nil quando o teto de streams foi atingido.
func (p *Parser) stream(id uint32) *HTTP2Stream {
	if i, ok := p.streams[id]; ok {
		return &p.info.Streams[i]
	}
	if len(p.info.Streams) >= p.lim.MaxStreams {
		return nil
	}
	p.streams[id] = len(p.info.Streams)
	p.info.Streams = append(p.info.Streams, HTTP2Stream{StreamID: id})
	return &p.info.Streams[len(p.info.Streams)-1]
}

// stamp guarda at em dst só na primeira vez.
func stamp(dst *time.Time, at time.Time) {
	if dst.IsZero() {
		*dst = at
	}
}

// parsePriority lê os 5 bytes de prioridade (E + dependência de 31 bits + peso).
func parsePriority(b []byte) StreamPriority {
	v := binary.BigEndian.Uint32(b)
	return StreamPriority{Exclusive: v&0x80000000 != 0, DependsOn: v & 0x7fffffff, Weight: int(b[4]) + 1}
}

// Merge junta a análise dos dois sentidos de uma conexão: o resultado tem o que o cliente mandou (in) e a
// lista de frames dos dois sentidos ordenada pelo tempo, com `status` de cada stream tirado das respostas.
// O teto de frames de in vale para a lista unida.
func Merge(in, out *HTTP2Info, maxFrames int) *HTTP2Info {
	if maxFrames <= 0 {
		maxFrames = DefaultMaxFrames
	}
	res := *in
	if out == nil {
		return &res
	}
	status := map[uint32]int{}
	for _, s := range out.Streams {
		if s.Status != 0 {
			status[s.StreamID] = s.Status
		}
	}
	res.Streams = make([]HTTP2Stream, len(in.Streams))
	copy(res.Streams, in.Streams)
	for i := range res.Streams {
		if s, ok := status[res.Streams[i].StreamID]; ok && res.Streams[i].Status == 0 {
			res.Streams[i].Status = s
		}
	}
	frames := make([]H2Frame, 0, min(len(in.Frames)+len(out.Frames), maxFrames))
	i, j := 0, 0
	for len(frames) < maxFrames && (i < len(in.Frames) || j < len(out.Frames)) {
		if j >= len(out.Frames) || (i < len(in.Frames) && in.Frames[i].TMs <= out.Frames[j].TMs) {
			frames = append(frames, in.Frames[i])
			i++
		} else {
			frames = append(frames, out.Frames[j])
			j++
		}
	}
	res.Frames = frames
	res.FramesTruncated = in.FramesTruncated || out.FramesTruncated || i < len(in.Frames) || j < len(out.Frames)
	res.FrameCount = in.FrameCount + out.FrameCount
	return &res
}
