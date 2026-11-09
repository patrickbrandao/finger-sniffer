package h1

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// HeaderField é um campo de resposta: nome e valor escritos exatamente assim, na ordem dada.
type HeaderField struct {
	Name  string
	Value string
}

// Interim é uma resposta 1xx enviada antes da final (100 Continue, 103 Early Hints).
type Interim struct {
	Status int
	// Reason vazio usa o texto padrão do código.
	Reason string
	Fields []HeaderField
}

// Response descreve a resposta final (spec 005 RF-07 / spec 009 RF-08).
type Response struct {
	// Version é "HTTP/1.1" (padrão) ou "HTTP/1.0".
	Version string
	Status  int
	// Reason vazio usa o texto padrão do código.
	Reason string
	// Fields vai na ordem e na caixa exatas. O escritor só acrescenta Content-Length ou
	// Transfer-Encoding quando o enquadramento pede e o campo não está na lista.
	Fields []HeaderField
	// Framing é FramingContentLength, FramingChunked, FramingClose ou FramingNone (sem corpo).
	Framing string
	// BodyLen é o tamanho do corpo em FramingContentLength (e o máximo lido nos outros, quando > 0).
	BodyLen int64
	// ChunkSize é o tamanho de cada pedaço em FramingChunked (0 usa DefaultChunkSize).
	ChunkSize int
	// Trailers vão depois do último pedaço em FramingChunked.
	Trailers []HeaderField
	// HeadSize > 0 completa o cabeçalho (linha de status até a linha vazia) até esse tamanho exato com
	// um campo PadFieldName (controle hsize).
	HeadSize int
}

// Constantes do escritor.
const (
	DefaultChunkSize = 16 << 10
	// PadFieldName é o campo usado para inflar o cabeçalho (hsize).
	PadFieldName = "X-Fs-Pad"
	// padOverhead é o tamanho fixo de "X-Fs-Pad: " + CRLF.
	padOverhead = len(PadFieldName) + 4
)

// ErrShortBody indica que o corpo acabou antes de BodyLen em FramingContentLength.
var ErrShortBody = errors.New("h1: body shorter than content-length")

// Sent são os bytes enviados de uma resposta (1xx incluídas): os primeiros até o teto de captura, o
// tamanho total e se a captura foi cortada (response_sent_b64, response_sent_truncated, response_sent_size).
type Sent struct {
	Bytes     []byte
	Truncated bool
	Size      int64
}

// ResponseWriter escreve respostas byte a byte e guarda o que saiu.
type ResponseWriter struct {
	dst        io.Writer
	captureMax int
	sent       Sent
}

// NewResponseWriter cria um escritor sobre dst que guarda até captureMax bytes por resposta
// (FS_EVENT_INLINE_MAX); captureMax <= 0 não guarda bytes, só conta.
func NewResponseWriter(dst io.Writer, captureMax int) *ResponseWriter {
	return &ResponseWriter{dst: dst, captureMax: captureMax}
}

// Sent devolve os bytes enviados desde o último Reset.
func (w *ResponseWriter) Sent() Sent { return w.sent }

// Reset começa a captura de uma nova resposta.
func (w *ResponseWriter) Reset() { w.sent = Sent{} }

// write envia p e registra o que foi efetivamente escrito.
func (w *ResponseWriter) write(p []byte) error {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.sent.Size += int64(n)
		room := w.captureMax - len(w.sent.Bytes)
		switch {
		case room >= n:
			w.sent.Bytes = append(w.sent.Bytes, p[:n]...)
		case room > 0:
			w.sent.Bytes = append(w.sent.Bytes, p[:room]...)
			w.sent.Truncated = true
		case w.captureMax > 0:
			w.sent.Truncated = true
		}
	}
	return err
}

func statusLine(version string, status int, reason string) string {
	if version == "" {
		version = "HTTP/1.1"
	}
	if reason == "" {
		reason = http.StatusText(status)
	}
	return version + " " + strconv.Itoa(status) + " " + reason + "\r\n"
}

func appendFields(b *strings.Builder, fields []HeaderField) {
	for _, f := range fields {
		b.WriteString(f.Name)
		b.WriteString(": ")
		b.WriteString(f.Value)
		b.WriteString("\r\n")
	}
}

// WriteInterim escreve uma resposta 1xx.
func (w *ResponseWriter) WriteInterim(version string, i Interim) error {
	var b strings.Builder
	b.WriteString(statusLine(version, i.Status, i.Reason))
	appendFields(&b, i.Fields)
	b.WriteString("\r\n")
	return w.write([]byte(b.String()))
}

func hasField(fields []HeaderField, name string) bool {
	for _, f := range fields {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// Head monta o cabeçalho da resposta (linha de status até a linha vazia) sem escrever.
func (r *Response) Head() []byte {
	var b strings.Builder
	b.WriteString(statusLine(r.Version, r.Status, r.Reason))
	appendFields(&b, r.Fields)
	switch r.Framing {
	case FramingContentLength:
		if !hasField(r.Fields, "Content-Length") {
			appendFields(&b, []HeaderField{{"Content-Length", strconv.FormatInt(r.BodyLen, 10)}})
		}
	case FramingChunked:
		if !hasField(r.Fields, "Transfer-Encoding") {
			appendFields(&b, []HeaderField{{"Transfer-Encoding", "chunked"}})
		}
	}
	// hsize: o campo de enchimento entra por último para atingir o tamanho exato (com a linha vazia).
	if missing := r.HeadSize - (b.Len() + 2); missing >= padOverhead {
		appendFields(&b, []HeaderField{{PadFieldName, strings.Repeat("a", missing-padOverhead)}})
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// WriteHead escreve o cabeçalho da resposta.
func (w *ResponseWriter) WriteHead(r *Response) error {
	return w.write(r.Head())
}

// WriteBody escreve o corpo lido de body conforme o enquadramento. Em FramingContentLength escreve
// exatamente BodyLen bytes; nos outros, até o EOF de body (limitado a BodyLen quando BodyLen > 0).
func (w *ResponseWriter) WriteBody(r *Response, body io.Reader) error {
	switch r.Framing {
	case FramingNone, "":
		return nil
	case FramingContentLength:
		n, err := w.copyBody(io.LimitReader(body, r.BodyLen))
		if err != nil {
			return err
		}
		if n < r.BodyLen {
			return ErrShortBody
		}
		return nil
	case FramingClose:
		if r.BodyLen > 0 {
			body = io.LimitReader(body, r.BodyLen)
		}
		_, err := w.copyBody(body)
		return err
	case FramingChunked:
		if r.BodyLen > 0 {
			body = io.LimitReader(body, r.BodyLen)
		}
		return w.writeChunked(r, body)
	default:
		return ErrBadTransferEncoding
	}
}

func (w *ResponseWriter) copyBody(body io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if werr := w.write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (w *ResponseWriter) writeChunked(r *Response, body io.Reader) error {
	size := r.ChunkSize
	if size <= 0 {
		size = DefaultChunkSize
	}
	buf := make([]byte, size)
	for {
		n, err := io.ReadFull(body, buf)
		if n > 0 {
			chunk := make([]byte, 0, n+20)
			chunk = strconv.AppendInt(chunk, int64(n), 16)
			chunk = append(chunk, '\r', '\n')
			chunk = append(chunk, buf[:n]...)
			chunk = append(chunk, '\r', '\n')
			if werr := w.write(chunk); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	var b strings.Builder
	b.WriteString("0\r\n")
	appendFields(&b, r.Trailers)
	b.WriteString("\r\n")
	return w.write([]byte(b.String()))
}

// WriteResponse escreve as 1xx, o cabeçalho e o corpo de uma vez.
func (w *ResponseWriter) WriteResponse(interim []Interim, r *Response, body io.Reader) error {
	for _, i := range interim {
		if err := w.WriteInterim(r.Version, i); err != nil {
			return err
		}
	}
	if err := w.WriteHead(r); err != nil {
		return err
	}
	return w.WriteBody(r, body)
}
