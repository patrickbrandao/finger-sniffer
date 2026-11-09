package h2passive

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

// Representações HPACK de um campo (RFC 7541 seção 6), nos valores do enum `repr` do openapi.
const (
	ReprIndexed             = "indexed"
	ReprLiteralIndexed      = "literal-indexed"
	ReprLiteralNotIndexed   = "literal-not-indexed"
	ReprLiteralNeverIndexed = "literal-never-indexed"
)

// Erros do decodificador HPACK. Depois de qualquer um deles a tabela dinâmica deixa de ser confiável e o
// parser para de decodificar blocos da conexão.
var (
	ErrHPACKTruncated   = errors.New("h2passive: bloco HPACK truncado")
	ErrHPACKInteger     = errors.New("h2passive: inteiro HPACK grande demais")
	ErrHPACKIndex       = errors.New("h2passive: índice HPACK inválido")
	ErrHPACKHuffman     = errors.New("h2passive: Huffman HPACK inválido")
	ErrHPACKTableSize   = errors.New("h2passive: atualização de tamanho da tabela acima do limite")
	ErrHPACKFieldsLimit = errors.New("h2passive: campos demais no bloco")
)

// hpackEntry é uma entrada da tabela (estática ou dinâmica).
type hpackEntry struct {
	name, value string
}

// size é o tamanho da entrada pela RFC 7541 seção 4.1.
func (e hpackEntry) size() uint32 {
	// nome e valor cabem no bloco, que é limitado por MaxHeaderBlock
	return uint32(len(e.name)) + uint32(len(e.value)) + 32 //nolint:gosec // limitado pelo bloco
}

// staticTable é a tabela estática da RFC 7541, apêndice A (índices 1..61).
var staticTable = [...]hpackEntry{
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

// hpackDecoder decodifica blocos de cabeçalho mantendo a tabela dinâmica em paralelo à do servidor. O
// `hpack.Decoder` do x/net não expõe a representação de cada campo, por isso os prefixos são lidos aqui; do
// x/net só se usa a decodificação Huffman.
type hpackDecoder struct {
	dyn       []hpackEntry // mais nova primeiro (índice 62 = dyn[0])
	size      uint32       // soma dos tamanhos das entradas
	maxSize   uint32       // tamanho máximo atual (última atualização de tamanho)
	limit     uint32       // teto anunciado pelo receptor (SETTINGS_HEADER_TABLE_SIZE)
	maxFields int          // teto de campos por bloco
}

func newHPACKDecoder(limit uint32, maxFields int) *hpackDecoder {
	return &hpackDecoder{maxSize: limit, limit: limit, maxFields: maxFields}
}

// lookup devolve a entrada do índice (1..61 estática, 62.. dinâmica).
func (d *hpackDecoder) lookup(idx uint64) (hpackEntry, bool) {
	if idx == 0 {
		return hpackEntry{}, false
	}
	if idx <= uint64(len(staticTable)) {
		return staticTable[idx-1], true
	}
	i := idx - uint64(len(staticTable)) - 1
	if i >= uint64(len(d.dyn)) {
		return hpackEntry{}, false
	}
	return d.dyn[i], true
}

// add insere uma entrada na tabela dinâmica, despejando as mais antigas (RFC 7541 seção 4.4).
func (d *hpackDecoder) add(e hpackEntry) {
	es := e.size()
	if es > d.maxSize {
		d.dyn = d.dyn[:0]
		d.size = 0
		return
	}
	d.evict(d.maxSize - es)
	d.dyn = append(d.dyn, hpackEntry{})
	copy(d.dyn[1:], d.dyn)
	d.dyn[0] = e
	d.size += es
}

// evict remove as entradas mais antigas até o tamanho caber em max.
func (d *hpackDecoder) evict(max uint32) {
	for d.size > max && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.dyn = d.dyn[:len(d.dyn)-1]
		d.size -= last.size()
	}
}

// decode decodifica um bloco completo (HEADERS + CONTINUATION). Em caso de erro devolve os campos lidos até
// ali e o erro.
func (d *hpackDecoder) decode(block []byte) ([]HPACKField, error) {
	var fields []HPACKField
	for len(block) > 0 {
		if len(fields) >= d.maxFields {
			return fields, ErrHPACKFieldsLimit
		}
		b := block[0]
		switch {
		case b&0x80 != 0: // 1xxxxxxx: campo indexado
			idx, rest, err := readInt(block, 7)
			if err != nil {
				return fields, err
			}
			block = rest
			e, ok := d.lookup(idx)
			if !ok {
				return fields, ErrHPACKIndex
			}
			fields = append(fields, HPACKField{
				Name: e.name, Value: e.value, Repr: ReprIndexed, Index: intPtr(idx),
			})
		case b&0xc0 == 0x40: // 01xxxxxx: literal com indexação incremental
			f, rest, err := d.literal(block, 6, ReprLiteralIndexed)
			if err != nil {
				return fields, err
			}
			block = rest
			d.add(hpackEntry{f.Name, f.Value})
			fields = append(fields, f)
		case b&0xe0 == 0x20: // 001xxxxx: atualização de tamanho da tabela dinâmica
			n, rest, err := readInt(block, 5)
			if err != nil {
				return fields, err
			}
			block = rest
			if n > uint64(d.limit) {
				return fields, ErrHPACKTableSize
			}
			d.maxSize = uint32(n) //nolint:gosec // n <= d.limit, conferido acima
			d.evict(d.maxSize)
		case b&0xf0 == 0x10: // 0001xxxx: literal nunca indexado
			f, rest, err := d.literal(block, 4, ReprLiteralNeverIndexed)
			if err != nil {
				return fields, err
			}
			block = rest
			fields = append(fields, f)
		default: // 0000xxxx: literal sem indexação
			f, rest, err := d.literal(block, 4, ReprLiteralNotIndexed)
			if err != nil {
				return fields, err
			}
			block = rest
			fields = append(fields, f)
		}
	}
	return fields, nil
}

// literal lê um campo literal cujo índice do nome usa um prefixo de n bits.
func (d *hpackDecoder) literal(block []byte, n uint8, repr string) (HPACKField, []byte, error) {
	idx, rest, err := readInt(block, n)
	if err != nil {
		return HPACKField{}, nil, err
	}
	f := HPACKField{Repr: repr}
	if idx == 0 {
		name, h, r, err := readString(rest)
		if err != nil {
			return HPACKField{}, nil, err
		}
		f.Name, f.HuffmanName, rest = name, boolPtr(h), r
	} else {
		e, ok := d.lookup(idx)
		if !ok {
			return HPACKField{}, nil, ErrHPACKIndex
		}
		f.Name, f.Index = e.name, intPtr(idx)
	}
	value, h, rest, err := readString(rest)
	if err != nil {
		return HPACKField{}, nil, err
	}
	f.Value, f.HuffmanValue = value, boolPtr(h)
	return f, rest, nil
}

// readInt lê um inteiro HPACK com prefixo de n bits (RFC 7541 seção 5.1). Valores acima de 2^32 são
// rejeitados: nenhum campo legítimo chega perto disso.
func readInt(b []byte, n uint8) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, ErrHPACKTruncated
	}
	mask := uint64(1)<<n - 1
	v := uint64(b[0]) & mask
	b = b[1:]
	if v < mask {
		return v, b, nil
	}
	var shift uint
	for {
		if len(b) == 0 {
			return 0, nil, ErrHPACKTruncated
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << shift
		if v > 1<<32 {
			return 0, nil, ErrHPACKInteger
		}
		if c&0x80 == 0 {
			return v, b, nil
		}
		shift += 7
	}
}

// readString lê uma cadeia HPACK (RFC 7541 seção 5.2) e diz se estava em Huffman.
func readString(b []byte) (string, bool, []byte, error) {
	if len(b) == 0 {
		return "", false, nil, ErrHPACKTruncated
	}
	huff := b[0]&0x80 != 0
	n, rest, err := readInt(b, 7)
	if err != nil {
		return "", false, nil, err
	}
	if n > uint64(len(rest)) {
		return "", false, nil, ErrHPACKTruncated
	}
	raw := rest[:n]
	rest = rest[n:]
	if !huff {
		return string(raw), false, rest, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", true, nil, ErrHPACKHuffman
	}
	return s, true, rest, nil
}

// intPtr recebe índices de readInt, que nunca passam de 2^32.
func intPtr(v uint64) *int { i := int(v); return &i } //nolint:gosec // v <= 2^32 (readInt)

func boolPtr(v bool) *bool { return &v }
