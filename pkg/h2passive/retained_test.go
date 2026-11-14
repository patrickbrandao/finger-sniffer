package h2passive

import (
	"bytes"
	"strconv"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// hpackBlocks codifica blocos com um único codificador (a tabela dinâmica segue de um bloco para o outro).
type hpackBlocks struct {
	buf bytes.Buffer
	enc *hpack.Encoder
}

func newHPACKBlocks() *hpackBlocks {
	b := &hpackBlocks{}
	b.enc = hpack.NewEncoder(&b.buf)
	return b
}

func (b *hpackBlocks) block(fields ...[2]string) []byte {
	b.buf.Reset()
	for _, f := range fields {
		_ = b.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return bytes.Clone(b.buf.Bytes())
}

// manyFields devolve os pseudo-cabeçalhos de um GET seguidos de n campos regulares iguais em todo stream
// (indexados depois do primeiro).
func manyFields(n int) [][2]string {
	out := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.b"}, {":path", "/"}}
	for i := range n {
		out = append(out, [2]string{"x-" + strconv.Itoa(i), "v"})
	}
	return out
}

// task 135: com muitos streams de muitos campos, o custo guardado nunca passa do teto; os cortados saem
// com FieldsCut; soltar os campos de um stream publicado libera espaço para os seguintes; e o HPACK segue em
// sincronia depois do corte.
func TestRetainedFieldsCap(t *testing.T) {
	enc := newHPACKBlocks()
	p := NewParser(Options{})
	p.Feed(0, []byte(Preface))
	const streams = 200
	maxSeen := 0
	for i := range streams {
		fields := manyFields(1019) // com os 4 pseudo e o x-new, até 1024 campos por bloco
		if i == streams-1 {
			// literal com indexação no último bloco (cortado): entra na tabela dinâmica mesmo assim
			fields = append(fields, [2]string{"x-new", "hello"})
		}
		p.Feed(0, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, uint32(2*i+1), enc.block(fields...)))
		maxSeen = max(maxSeen, p.RetainedFieldBytes())
	}
	if p.Err() != nil || maxSeen > DefaultMaxRetainedFieldBytes {
		t.Fatalf("err %v retained max %d", p.Err(), maxSeen)
	}
	info := p.Info()
	if len(info.Streams) != streams || info.Streams[0].FieldsCut || len(info.Streams[0].Fields) != 1023 ||
		!info.Streams[streams-1].FieldsCut {
		t.Fatalf("first cut %v (%d fields), last cut %v", info.Streams[0].FieldsCut, len(info.Streams[0].Fields),
			info.Streams[streams-1].FieldsCut)
	}
	// Publicados: os campos saem do parser e o custo volta a zero.
	for i := range streams {
		p.ReleaseFields(uint32(2*i + 1))
	}
	if p.RetainedFieldBytes() != 0 || len(p.Info().Streams[0].Fields) != 0 {
		t.Fatalf("retained %d after release", p.RetainedFieldBytes())
	}
	// O campo indexado no bloco cortado é resolvido no bloco seguinte.
	id := uint32(2*streams + 1)
	p.Feed(0, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, id, enc.block(
		[2]string{":method", "GET"}, [2]string{":path", "/"}, [2]string{"x-new", "hello"})))
	last := p.Info().Streams[streams]
	if p.Err() != nil || last.FieldsCut || len(last.Fields) != 3 || last.Fields[2].Value != "hello" ||
		last.Fields[2].Repr != ReprIndexed {
		t.Fatalf("after cut: %v %+v", p.Err(), last.Fields)
	}
}

// task 135: conexão longa com milhares de requisições pequenas, cada uma solta depois de publicada, nunca
// corta campos (até o teto de streams registrados).
func TestRetainedFieldsLongConnection(t *testing.T) {
	enc := newHPACKBlocks()
	p := NewParser(Options{})
	p.Feed(0, []byte(Preface))
	for i := range DefaultMaxStreams {
		id := uint32(2*i + 1)
		p.Feed(0, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, id, enc.block(manyFields(20)...)))
		st := p.Info().Streams[i]
		if st.FieldsCut || len(st.Fields) != 24 {
			t.Fatalf("stream %d cut %v fields %d", id, st.FieldsCut, len(st.Fields))
		}
		p.ReleaseFields(id)
	}
}

// task 135: Reserve recusando corta os campos sem parar a decodificação; Release devolve exatamente o que
// foi reservado.
func TestRetainedFieldsReserve(t *testing.T) {
	enc := newHPACKBlocks()
	used := 0
	p := NewParser(Options{
		Reserve: func(n int) bool {
			if used+n > 1000 {
				return false
			}
			used += n
			return true
		},
		Release: func(n int) { used -= n },
	})
	p.Feed(0, []byte(Preface))
	p.Feed(0, frame(FrameHeaders, FlagEndHeaders, 1, enc.block(manyFields(30)...)))
	st := p.Info().Streams[0]
	if !st.FieldsCut || len(st.Fields) == 0 || len(st.Fields) >= 34 || used != p.RetainedFieldBytes() {
		t.Fatalf("cut %v fields %d used %d retained %d", st.FieldsCut, len(st.Fields), used, p.RetainedFieldBytes())
	}
	// Trailers depois do corte continuam sendo trailers (não viram o primeiro bloco).
	p.Feed(0, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, enc.block([2]string{"x-t", "1"})))
	if got := p.Info().Streams[0]; len(got.PseudoOrder) != 4 || got.HeadFields != len(st.Fields) {
		t.Fatalf("pseudo %v head %d", got.PseudoOrder, got.HeadFields)
	}
	p.ReleaseFields(1)
	if used != 0 {
		t.Fatalf("used %d after release", used)
	}
}
