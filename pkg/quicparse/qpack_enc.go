package quicparse

// Escrita de frames h3 e de blocos QPACK sem tabela dinâmica, para o servidor h3 do web. A saída é
// determinística: o mesmo conjunto de campos gera sempre os mesmos bytes, o que deixa o registro da
// resposta reproduzível.

// staticExact e staticName indexam a tabela estática por nome+valor e por nome (primeira ocorrência).
var (
	staticExact = map[[2]string]int{}
	staticName  = map[string]int{}
)

func init() {
	for i, e := range qpackStatic {
		if _, ok := staticExact[e]; !ok {
			staticExact[e] = i
		}
		if _, ok := staticName[e[0]]; !ok {
			staticName[e[0]] = i
		}
	}
}

// AppendH3Frame acrescenta um frame h3 (tipo, tamanho e payload).
func AppendH3Frame(b []byte, typ uint64, payload []byte) []byte {
	b = AppendVarint(b, typ)
	b = AppendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

// AppendH3FrameHeader acrescenta só o cabeçalho de um frame h3 de tamanho n (o payload vem depois).
func AppendH3FrameHeader(b []byte, typ uint64, n uint64) []byte {
	return AppendVarint(AppendVarint(b, typ), n)
}

// appendQPACKInt escreve um inteiro com prefixo de n bits; first traz os bits acima do prefixo.
//
//nolint:gosec // cada byte é uma fatia do valor, o corte é intencional
func appendQPACKInt(b []byte, first byte, n uint, v uint64) []byte {
	limit := uint64(1)<<n - 1
	if v < limit {
		return append(b, first|byte(v))
	}
	b = append(b, first|byte(limit))
	v -= limit
	for v >= 0x80 {
		b = append(b, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// AppendFieldSection acrescenta um bloco de campos QPACK com Required Insert Count 0 e Base 0: campo
// indexado quando nome e valor estão na tabela estática, literal com referência de nome estático quando só
// o nome está, e literal com nome literal no resto; nenhum Huffman. Os nomes vão como vieram (o chamador
// garante minúsculas, RFC 9114 seção 4.2).
//
//nolint:gosec // índices da tabela estática (< 99) e tamanhos de string não estouram
func AppendFieldSection(b []byte, fields [][2]string) []byte {
	b = append(b, 0, 0)
	for _, f := range fields {
		if i, ok := staticExact[f]; ok {
			b = appendQPACKInt(b, 0xc0, 6, uint64(i))
			continue
		}
		if i, ok := staticName[f[0]]; ok {
			b = appendQPACKInt(b, 0x50, 4, uint64(i))
		} else {
			b = appendQPACKInt(b, 0x20, 3, uint64(len(f[0])))
			b = append(b, f[0]...)
		}
		b = appendQPACKInt(b, 0x00, 7, uint64(len(f[1])))
		b = append(b, f[1]...)
	}
	return b
}
