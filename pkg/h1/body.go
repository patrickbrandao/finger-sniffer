package h1

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strconv"
	"strings"
	"unsafe"
)

// Enquadramentos do corpo (schema HTTP1Request.body.framing).
const (
	FramingNone          = "none"
	FramingContentLength = "content-length"
	FramingChunked       = "chunked"
	FramingClose         = "close"
)

// Padrões do leitor de corpo.
const (
	// DefaultRawBodyMax é o padrão de FS_RAW_BODY_MAX_BYTES (ADR 0018).
	DefaultRawBodyMax = 128 << 10
	// DefaultMaxChunks é quantos pedaços chunked são registrados um a um; os seguintes só entram no total.
	DefaultMaxChunks = 4096
	// maxChunkExtTotal é o teto agregado de bytes de extensão dos pedaços registrados por requisição (RF-03,
	// ADR 0033): acima dele a lista para no prefixo e chunks_truncated fica true.
	maxChunkExtTotal = 256 << 10
	// maxChunkLine é o teto de uma linha de tamanho de pedaço (com extensões).
	maxChunkLine = 64 << 10
	// maxChunkSize evita estouro: 15 dígitos hexadecimais.
	maxChunkHexDigits = 15
)

// Erros do leitor de corpo.
var (
	// ErrBadContentLength: Content-Length inválido ou repetido com valores diferentes.
	ErrBadContentLength = errors.New("h1: invalid content-length")
	// ErrBadTransferEncoding: Transfer-Encoding cuja última codificação não é chunked.
	ErrBadTransferEncoding = errors.New("h1: unsupported transfer-encoding")
	// ErrBadChunk: linha de tamanho de pedaço inválida ou pedaço sem terminador.
	ErrBadChunk = errors.New("h1: malformed chunk")
)

// Chunk é um pedaço chunked como chegou: tamanho, dígitos literais e o resto da linha (extensões, com o
// ";" inicial e os espaços literais; nil sem extensão).
type Chunk struct {
	Size        int64   `json:"size"`
	SizeLiteral string  `json:"size_literal"`
	Ext         *string `json:"ext"`
}

// Body é o corpo da requisição. Size e SHA256 são sempre do conteúdo inteiro decodificado (sem o
// enquadramento chunked); Raw são os bytes do corpo como chegaram no fio (com o enquadramento chunked), até
// o teto pedido pelo chamador (RF-03, ADR 0018).
type Body struct {
	Framing      string  `json:"framing"`
	Size         int64   `json:"size"`
	SHA256       *string `json:"sha256"`
	Raw          []byte  `json:"raw_b64"`
	RawTruncated bool    `json:"raw_truncated"`
	Chunks       []Chunk `json:"chunks,omitempty"`
	// ChunksTruncated indica que só os primeiros pedaços foram registrados (MaxChunks pedaços ou 256 KiB de
	// extensões somadas), ou que a lista foi cortada para caber no teto do evento; tamanho e SHA-256 seguem do
	// corpo inteiro.
	ChunksTruncated bool    `json:"chunks_truncated"`
	Trailers        []Field `json:"trailers,omitempty"`

	// WireSize é o tamanho do corpo no fio (com o enquadramento chunked).
	WireSize int64 `json:"-"`
}

// BodyOptions controla a leitura do corpo.
type BodyOptions struct {
	// RawMax é quantos bytes crus guardar (FS_RAW_BODY_MAX_BYTES); 0 usa DefaultRawBodyMax, < 0 não guarda.
	RawMax int
	// MaxChunks é quantos pedaços registrar um a um; 0 usa DefaultMaxChunks.
	MaxChunks int
	// MaxTrailerBytes é o teto dos trailers; 0 usa o teto do cabeçalho do Reader.
	MaxTrailerBytes int
}

// Framing decide o enquadramento do corpo da requisição (RFC 9112 §6.3): Transfer-Encoding vence
// Content-Length; sem nenhum dos dois, a requisição não tem corpo. Devolve também o tamanho declarado.
func (r *Request) Framing() (framing string, length int64, err error) {
	te := r.Values("Transfer-Encoding")
	if len(te) > 0 {
		codings := strings.Split(strings.Join(te, ","), ",")
		last := strings.Trim(codings[len(codings)-1], " \t")
		if !strings.EqualFold(last, "chunked") {
			return "", 0, ErrBadTransferEncoding
		}
		return FramingChunked, -1, nil
	}
	cl := r.Values("Content-Length")
	if len(cl) == 0 {
		return FramingNone, 0, nil
	}
	length = -1
	for _, v := range cl {
		// Lista "N, N" é aceita pela RFC 9110 §8.6 quando os valores são iguais.
		for _, p := range strings.Split(v, ",") {
			n, err := parseDecimal(strings.Trim(p, " \t"))
			if err != nil || (length >= 0 && n != length) {
				return "", 0, ErrBadContentLength
			}
			length = n
		}
	}
	return FramingContentLength, length, nil
}

func parseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 18 {
		return 0, ErrBadContentLength
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrBadContentLength
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// chunkSize é o tamanho de um Chunk na fatia; chunkOverhead estima o que cada pedaço guardado aloca além
// da fatia (o literal do tamanho, a string da extensão e o ponteiro para ela).
const (
	chunkSize     = int(unsafe.Sizeof(Chunk{}))
	chunkOverhead = 48
	// minRawBuf é a menor capacidade alocada para Body.Raw.
	minRawBuf = 4 << 10
)

// bodySink acumula tamanho, hash do conteúdo e os bytes crus do fio até o teto. Com reserve, o crescimento da
// capacidade de Raw e da lista de pedaços é reservado antes de alocar; sem orçamento, para de guardar
// (ADR 0070 item 7).
type bodySink struct {
	body    *Body
	hash    hash.Hash
	rawMax  int
	reserve func(n int) bool
	// rawDenied: o orçamento recusou o crescimento de Raw; nada mais é guardado.
	rawDenied bool
}

func newBodySink(b *Body, rawMax int, reserve func(n int) bool) *bodySink {
	return &bodySink{body: b, hash: sha256.New(), rawMax: rawMax, reserve: reserve}
}

func (s *bodySink) ok(n int) bool { return n <= 0 || s.reserve == nil || s.reserve(n) }

// growRaw garante capacidade para mais n bytes em Raw (dobra até rawMax, reservando o crescimento).
func (s *bodySink) growRaw(n int) bool {
	raw := s.body.Raw
	need := len(raw) + n
	if need <= cap(raw) {
		return true
	}
	newCap := min(max(2*cap(raw), need, minRawBuf), max(s.rawMax, need))
	if !s.ok(newCap - cap(raw)) {
		s.rawDenied = true
		return false
	}
	grown := make([]byte, len(raw), newCap)
	copy(grown, raw)
	s.body.Raw = grown
	return true
}

// wire registra bytes do fio (enquadramento e conteúdo).
func (s *bodySink) wire(p []byte) {
	s.body.WireSize += int64(len(p))
	if s.rawMax <= 0 || len(p) == 0 {
		return
	}
	room := s.rawMax - len(s.body.Raw)
	if room <= 0 || s.rawDenied {
		s.body.RawTruncated = true
		return
	}
	keep := p
	if len(p) > room {
		keep = p[:room]
	}
	if !s.growRaw(len(keep)) {
		s.body.RawTruncated = true
		return
	}
	s.body.Raw = append(s.body.Raw, keep...)
	if len(keep) < len(p) {
		s.body.RawTruncated = true
	}
}

// addChunk guarda um pedaço na lista, reservando o crescimento da fatia e o que o pedaço aloca; false sem
// orçamento (sem guardar).
func (s *bodySink) addChunk(ch Chunk) bool {
	b := s.body
	cost := chunkOverhead
	if ch.Ext != nil {
		cost += len(*ch.Ext)
	}
	if len(b.Chunks) == cap(b.Chunks) {
		newCap := max(2*cap(b.Chunks), 8)
		cost += (newCap - cap(b.Chunks)) * chunkSize
		if !s.ok(cost) {
			return false
		}
		grown := make([]Chunk, len(b.Chunks), newCap)
		copy(grown, b.Chunks)
		b.Chunks = grown
	} else if !s.ok(cost) {
		return false
	}
	b.Chunks = append(b.Chunks, ch)
	return true
}

// content registra bytes de conteúdo (que também estão no fio).
func (s *bodySink) content(p []byte) {
	s.hash.Write(p)
	s.body.Size += int64(len(p))
	s.wire(p)
}

func (s *bodySink) finish() {
	sum := hex.EncodeToString(s.hash.Sum(nil))
	s.body.SHA256 = &sum
}

// ReadBody lê o corpo da requisição conforme o enquadramento dela e preenche req.Body e
// req.BufferedAfter. Em erro, req.Body traz o que foi lido.
func (r *Reader) ReadBody(req *Request, opts BodyOptions) error {
	framing, length, err := req.Framing()
	if err != nil {
		req.Body = &Body{Framing: FramingNone}
		req.BufferedAfter = r.br.Buffered()
		return err
	}
	err = r.ReadBodyFraming(req, framing, length, opts)
	req.BufferedAfter = r.br.Buffered()
	return err
}

// ReadBodyFraming lê o corpo com um enquadramento explícito (inclusive FramingClose, até o EOF).
func (r *Reader) ReadBodyFraming(req *Request, framing string, length int64, opts BodyOptions) error {
	b := &Body{Framing: framing}
	req.Body = b
	rawMax := opts.RawMax
	if rawMax == 0 {
		rawMax = DefaultRawBodyMax
	}
	sink := newBodySink(b, rawMax, r.ReserveBody)
	var err error
	switch framing {
	case FramingNone:
		return nil
	case FramingContentLength:
		err = r.copyContent(sink, length)
	case FramingClose:
		err = r.copyContent(sink, -1)
	case FramingChunked:
		err = r.readChunked(req, sink, opts)
	default:
		return ErrBadTransferEncoding
	}
	sink.finish()
	return err
}

// copyContent copia n bytes (ou até o EOF, com n < 0) do leitor para o sink.
func (r *Reader) copyContent(sink *bodySink, n int64) error {
	if r.copyBuf == nil {
		r.copyBuf = make([]byte, 32<<10)
	}
	buf := r.copyBuf
	for n != 0 {
		want := len(buf)
		if n > 0 && int64(want) > n {
			want = int(n)
		}
		got, err := r.br.Read(buf[:want])
		if got > 0 {
			sink.content(buf[:got])
			r.consumed += int64(got)
			if n > 0 {
				n -= int64(got)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if n < 0 {
					return nil
				}
				if n > 0 {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			return err
		}
	}
	return nil
}

// readChunked lê pedaços até o de tamanho 0 e os trailers (RFC 9112 §7.1), registrando cada pedaço.
func (r *Reader) readChunked(req *Request, sink *bodySink, opts BodyOptions) error {
	b := sink.body
	maxChunks := opts.MaxChunks
	if maxChunks == 0 {
		maxChunks = DefaultMaxChunks
	}
	extTotal := 0
	for {
		ch, err := r.readChunkLine(sink)
		if err != nil {
			return err
		}
		if !b.ChunksTruncated {
			ext := 0
			if ch.Ext != nil {
				ext = len(*ch.Ext)
			}
			if len(b.Chunks) < maxChunks && extTotal+ext <= maxChunkExtTotal && sink.addChunk(ch) {
				extTotal += ext
			} else {
				// A lista fica no prefixo: nenhum pedaço posterior entra depois do corte.
				b.ChunksTruncated = true
			}
		}
		if ch.Size == 0 {
			break
		}
		if err := r.copyContent(sink, ch.Size); err != nil {
			return err
		}
		// Cada pedaço termina em CRLF (ou LF puro, tolerado e refletido nos bytes crus).
		if err := r.readChunkEnd(sink); err != nil {
			return err
		}
	}
	return r.readTrailers(b, sink, opts)
}

// readChunkEnd consome o CRLF (ou LF) que fecha os dados de um pedaço, sem engolir bytes além dele.
func (r *Reader) readChunkEnd(sink *bodySink) error {
	p, err := r.br.Peek(1)
	if err != nil {
		return io.ErrUnexpectedEOF
	}
	n := 1
	switch p[0] {
	case '\n':
	case '\r':
		p, err = r.br.Peek(2)
		if err != nil {
			return io.ErrUnexpectedEOF
		}
		if p[1] != '\n' {
			return ErrBadChunk
		}
		n = 2
	default:
		return ErrBadChunk
	}
	sink.wire(p[:n])
	_, _ = r.br.Discard(n)
	r.consumed += int64(n)
	return nil
}

// readChunkLine lê e interpreta a linha do tamanho de um pedaço. A linha que cabe no bufio é lida sem
// cópia (ADR 0070 item 5: no máximo ~3 alocações pequenas por pedaço); só a linha mais longa que o buffer
// passa por readLine.
func (r *Reader) readChunkLine(sink *bodySink) (Chunk, error) {
	line, err := r.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// Linha maior que o buffer: junta o resto com readLine (cópia nova), no teto de maxChunkLine.
		head := append([]byte(nil), line...)
		r.consumed += int64(len(head))
		var rest []byte
		if len(head) < maxChunkLine {
			rest, err = r.readLine(maxChunkLine-len(head), false)
		} else {
			err = ErrHeadTooLarge
		}
		line = append(head, rest...)
	} else {
		r.consumed += int64(len(line))
	}
	sink.wire(line)
	if err != nil {
		if errors.Is(err, ErrHeadTooLarge) {
			return Chunk{}, ErrBadChunk
		}
		if errors.Is(err, io.EOF) {
			return Chunk{}, io.ErrUnexpectedEOF
		}
		return Chunk{}, err
	}
	return parseChunkLine(line)
}

// parseChunkLine separa os dígitos hexadecimais literais do resto da linha.
func parseChunkLine(line []byte) (Chunk, error) {
	content, _ := splitTerm(line)
	i := 0
	for i < len(content) && isHex(content[i]) {
		i++
	}
	if i == 0 || i > maxChunkHexDigits {
		return Chunk{}, ErrBadChunk
	}
	// O literal e a extensão viram strings próprias: a lista não segura a linha inteira.
	lit := string(content[:i])
	size, err := strconv.ParseInt(lit, 16, 64)
	if err != nil {
		return Chunk{}, ErrBadChunk
	}
	ch := Chunk{Size: size, SizeLiteral: lit}
	if rest := content[i:]; len(rest) > 0 {
		// Só espaços (BWS) e extensões iniciadas por ";" são válidos depois do tamanho.
		if t := bytes.TrimLeft(rest, " \t"); len(t) > 0 && t[0] != ';' {
			return Chunk{}, ErrBadChunk
		}
		ext := string(rest)
		ch.Ext = &ext
	}
	return ch, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// readTrailers lê os campos depois do último pedaço até a linha vazia.
func (r *Reader) readTrailers(b *Body, sink *bodySink, opts BodyOptions) error {
	limit := opts.MaxTrailerBytes
	if limit == 0 {
		limit = r.maxHead()
	}
	used := 0
	fold := folder{reserve: r.Reserve}
	flushFold := func() {
		if len(b.Trailers) > 0 {
			fold.flush(&b.Trailers[len(b.Trailers)-1])
		}
	}
	// O valor dobrado parcial fica gravado no último trailer em qualquer saída.
	defer flushFold()
	for {
		line, err := r.readLine(limit-used, true)
		used += len(line)
		sink.wire(line)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		content, term := splitTerm(line)
		if len(content) == 0 {
			return nil
		}
		if content[0] == ' ' || content[0] == '\t' {
			if len(b.Trailers) == 0 {
				return ErrObsFoldFirst
			}
			if !fold.add(&b.Trailers[len(b.Trailers)-1], content, term) {
				return ErrHeadTooLarge
			}
			continue
		}
		flushFold()
		f, err := parseField(content, term)
		if err != nil {
			return err
		}
		// Teto de campos dos trailers (RF-10): acima dele, 400 (o servidor trata ErrHeadTooLarge no corpo).
		if len(b.Trailers) >= r.maxFields() {
			return ErrHeadTooLarge
		}
		if !r.appendField(&b.Trailers, f, len(content)) {
			return ErrHeadTooLarge
		}
	}
}
