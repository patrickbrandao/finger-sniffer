package quicparse

import (
	"errors"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// Representações QPACK de uma linha de campo (RFC 9204 seção 4.5), nos valores do enum `repr` do openapi.
const (
	ReprIndexed                = "indexed"
	ReprIndexedPostBase        = "indexed-post-base"
	ReprLiteralNameRef         = "literal-name-ref"
	ReprLiteralPostBaseNameRef = "literal-post-base-name-ref"
	ReprLiteral                = "literal"
)

// DefaultMaxFieldsPerSection limita os campos decodificados por bloco.
const DefaultMaxFieldsPerSection = 1024

const (
	maxQPACKInt                 = 1 << 62
	qpackStaticTableLen         = 99
	errQPACKStaticIndexTemplate = "%w: índice estático %d"
)

// Erros do decodificador QPACK. Depois de qualquer um deles o resto do bloco é descartado.
var (
	ErrQPACKTruncated   = errors.New("quicparse: bloco QPACK truncado")
	ErrQPACKInteger     = errors.New("quicparse: inteiro QPACK grande demais")
	ErrQPACKIndex       = errors.New("quicparse: índice QPACK inválido")
	ErrQPACKHuffman     = errors.New("quicparse: Huffman QPACK inválido")
	ErrQPACKFieldsLimit = errors.New("quicparse: campos demais no bloco QPACK")
)

// qpackStatic é a tabela estática da RFC 9204, apêndice A (índices 0..98).
var qpackStatic = [qpackStaticTableLen][2]string{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

// QPACKStatic devolve a entrada i da tabela estática.
func QPACKStatic(i int) (name, value string, ok bool) {
	if i < 0 || i >= qpackStaticTableLen {
		return "", "", false
	}
	return qpackStatic[i][0], qpackStatic[i][1], true
}

// FieldSectionPrefix é o prefixo do bloco de campos (RFC 9204 seção 4.5.1), como chegou: o Required Insert
// Count codificado e o Delta Base com o sinal. Com QPACK_MAX_TABLE_CAPACITY = 0 os dois valem 0.
type FieldSectionPrefix struct {
	EncodedRequiredInsertCount uint64
	BaseSign                   bool
	DeltaBase                  uint64
}

// DecodeFieldSection decodifica um bloco de campos QPACK (payload de um frame HEADERS) só com a tabela
// estática; referências à tabela dinâmica viram campos com `static: false` e sem o que viria da tabela.
// maxFields <= 0 usa DefaultMaxFieldsPerSection. Em erro devolve os campos já lidos.
func DecodeFieldSection(b []byte, maxFields int) (FieldSectionPrefix, []QPACKField, error) {
	if maxFields <= 0 {
		maxFields = DefaultMaxFieldsPerSection
	}
	d := qpackReader{buf: b}
	var p FieldSectionPrefix
	var err error
	if p.EncodedRequiredInsertCount, err = d.integer(8); err != nil {
		return p, nil, err
	}
	if d.empty() {
		return p, nil, ErrQPACKTruncated
	}
	p.BaseSign = d.peek()&0x80 != 0
	if p.DeltaBase, err = d.integer(7); err != nil {
		return p, nil, err
	}
	fields := []QPACKField{}
	for !d.empty() {
		if len(fields) >= maxFields {
			return p, fields, ErrQPACKFieldsLimit
		}
		f, err := d.field()
		if err != nil {
			return p, fields, err
		}
		fields = append(fields, f)
	}
	return p, fields, nil
}

type qpackReader struct {
	buf []byte
	off int
}

func (d *qpackReader) empty() bool { return d.off >= len(d.buf) }
func (d *qpackReader) peek() byte  { return d.buf[d.off] }

// integer lê um inteiro com prefixo de n bits (RFC 9204 seção 4.1.1, igual ao HPACK).
func (d *qpackReader) integer(n uint) (uint64, error) {
	if d.empty() {
		return 0, ErrQPACKTruncated
	}
	mask := byte(1<<n - 1)
	v := uint64(d.buf[d.off] & mask)
	d.off++
	if v < uint64(mask) {
		return v, nil
	}
	var shift uint
	for {
		if d.empty() {
			return 0, ErrQPACKTruncated
		}
		c := d.buf[d.off]
		d.off++
		if shift > 56 {
			return 0, ErrQPACKInteger
		}
		v += uint64(c&0x7f) << shift
		if v >= maxQPACKInt {
			return 0, ErrQPACKInteger
		}
		if c&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}

// str lê uma string com o bit H na posição do prefixo de n bits (n+1 é o bit H).
func (d *qpackReader) str(n uint) (string, bool, error) {
	if d.empty() {
		return "", false, ErrQPACKTruncated
	}
	huff := d.peek()&(1<<n) != 0
	l, err := d.integer(n)
	if err != nil {
		return "", false, err
	}
	if l > uint64(len(d.buf)-d.off) { //nolint:gosec // off <= len(buf)
		return "", huff, ErrQPACKTruncated
	}
	raw := d.buf[d.off : d.off+int(l)] //nolint:gosec // l <= len(buf)-off
	d.off += int(l)                    //nolint:gosec // idem
	if !huff {
		return string(raw), false, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", true, fmt.Errorf("%w: %w", ErrQPACKHuffman, err)
	}
	return s, true, nil
}

func ptr[T any](v T) *T { return &v }

func (d *qpackReader) field() (QPACKField, error) {
	c := d.peek()
	switch {
	case c&0x80 != 0: // 1Txxxxxx: campo indexado
		static := c&0x40 != 0
		i, err := d.integer(6)
		if err != nil {
			return QPACKField{}, err
		}
		f := QPACKField{Repr: ReprIndexed, Static: ptr(static), Index: ptr(int(min(i, 1<<31))), HuffmanName: nil}
		if static {
			n, v, ok := QPACKStatic(int(min(i, 1<<31)))
			if !ok {
				return f, fmt.Errorf(errQPACKStaticIndexTemplate, ErrQPACKIndex, i)
			}
			f.Name, f.Value = n, v
		}
		return f, nil
	case c&0x40 != 0: // 01NTxxxx: literal com referência de nome
		never := c&0x20 != 0
		static := c&0x10 != 0
		i, err := d.integer(4)
		if err != nil {
			return QPACKField{}, err
		}
		f := QPACKField{
			Repr: ReprLiteralNameRef, Static: ptr(static), Index: ptr(int(min(i, 1<<31))),
			NeverIndexed: ptr(never),
		}
		if static {
			n, _, ok := QPACKStatic(int(min(i, 1<<31)))
			if !ok {
				return f, fmt.Errorf(errQPACKStaticIndexTemplate, ErrQPACKIndex, i)
			}
			f.Name = n
		}
		v, h, err := d.str(7)
		f.Value, f.HuffmanValue = v, ptr(h)
		return f, err
	case c&0x20 != 0: // 001NHxxx: literal com nome literal
		never := c&0x10 != 0
		f := QPACKField{Repr: ReprLiteral, NeverIndexed: ptr(never)}
		n, hn, err := d.str(3)
		f.Name, f.HuffmanName = n, ptr(hn)
		if err != nil {
			return f, err
		}
		v, hv, err := d.str(7)
		f.Value, f.HuffmanValue = v, ptr(hv)
		return f, err
	case c&0x10 != 0: // 0001xxxx: indexado pós-base (tabela dinâmica)
		i, err := d.integer(4)
		if err != nil {
			return QPACKField{}, err
		}
		return QPACKField{Repr: ReprIndexedPostBase, Static: ptr(false), Index: ptr(int(min(i, 1<<31)))}, nil
	default: // 0000Nxxx: literal com referência de nome pós-base (tabela dinâmica)
		never := c&0x08 != 0
		i, err := d.integer(3)
		if err != nil {
			return QPACKField{}, err
		}
		f := QPACKField{
			Repr: ReprLiteralPostBaseNameRef, Static: ptr(false), Index: ptr(int(min(i, 1<<31))),
			NeverIndexed: ptr(never),
		}
		v, h, err := d.str(7)
		f.Value, f.HuffmanValue = v, ptr(h)
		return f, err
	}
}
