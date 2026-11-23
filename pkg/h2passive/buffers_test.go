package h2passive

import (
	"bytes"
	"errors"
	"testing"
)

// task 328: depois de um HEADERS de ~1 MiB e de um bloco de CONTINUATION de ~1 MiB, o parser não segura os
// buffers (soltos acima de 32 KiB); o bloco em montagem reserva do orçamento e devolve tudo.
func TestBuffersReleasedAfterBigBlocks(t *testing.T) {
	enc := newHPACKBlocks()
	big := string(bytes.Repeat([]byte("a"), 1000<<10))
	inUse, peak := 0, 0
	p := NewParser(Options{
		Reserve: func(n int) bool { inUse += n; peak = max(peak, inUse); return true },
		Release: func(n int) { inUse -= n },
	})
	p.Feed(0, []byte(Preface))
	blk := enc.block([2]string{":method", "GET"}, [2]string{":path", "/"}, [2]string{"x-big", big})
	p.Feed(0, frame(FrameHeaders, FlagEndHeaders|FlagEndStream, 1, blk))
	p.ReleaseFields(1)
	blk2 := enc.block([2]string{":method", "GET"}, [2]string{":path", "/"}, [2]string{"x-big2", big})
	half := len(blk2) / 2
	p.Feed(0, frame(FrameHeaders, FlagEndStream, 3, blk2[:half]))
	p.Feed(0, frame(FrameContinuation, FlagEndHeaders, 3, blk2[half:]))
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	// pico: bloco montado inteiro (reservado) + os campos decodificados
	if peak < len(blk2) {
		t.Fatalf("bloco em montagem não reservado: pico %d < %d", peak, len(blk2))
	}
	p.ReleaseFields(3)
	if inUse != 0 {
		t.Fatalf("reserva em uso %d depois de soltar", inUse)
	}
	if cap(p.payload) > maxKeptBuf || cap(p.block) > maxKeptBuf {
		t.Fatalf("buffers presos: payload %d block %d", cap(p.payload), cap(p.block))
	}
}

// task 328: sem orçamento para o bloco em montagem, o HPACK para e o stream sai com FieldsCut.
func TestBlockReserveDenied(t *testing.T) {
	enc := newHPACKBlocks()
	p := NewParser(Options{Reserve: func(int) bool { return false }, Release: func(int) {}})
	p.Feed(0, []byte(Preface))
	p.Feed(0, frame(FrameHeaders, FlagEndHeaders, 1, enc.block([2]string{":method", "GET"})))
	if !errors.Is(p.Err(), ErrHeaderBlockLimit) || !p.Info().Streams[0].FieldsCut {
		t.Fatalf("err %v cut %v", p.Err(), p.Info().Streams[0].FieldsCut)
	}
}
