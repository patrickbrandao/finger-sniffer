package quicparse

import (
	"errors"
	"testing"
)

// task 134: o HEADERS reserva cada pedaço antes de guardar, devolve tudo quando o frame completa e solta o
// buffer; sem orçamento, ErrH3Budget.
func TestRequestStreamBudget(t *testing.T) {
	fields := AppendFieldSection(nil, [][2]string{{":method", "GET"}, {":path", "/"}, {"x-a", "1"}})
	frame := AppendH3Frame(nil, H3FrameHeaders, fields)
	frame = AppendH3Frame(frame, H3FrameData, []byte("body"))

	used, peak := 0, 0
	r := NewRequestStream(0, 0)
	r.SetBudget(func(n int) bool {
		used += n
		peak = max(peak, used)
		return true
	}, func(n int) { used -= n })
	for i := range frame { // byte a byte: várias reservas para o mesmo frame
		r.Feed(frame[i : i+1])
	}
	if r.Err() != nil || !r.HeadersSeen || len(r.Request.Fields) != 3 {
		t.Fatalf("%v %v %d", r.Err(), r.HeadersSeen, len(r.Request.Fields))
	}
	if used != 0 || peak != len(fields) || r.Held() != 0 || r.fr.buf != nil {
		t.Fatalf("used %d peak %d held %d buf %d", used, peak, r.Held(), len(r.fr.buf))
	}

	// Recusa no meio do frame: a capacidade cresce dobrando (512, 1024, ...) e cada crescimento é reservado
	// antes de alocar (ADR 0036); a recusa dá erro e o que já foi reservado fica em Held para quem chamou
	// devolver.
	big := AppendH3FrameHeader(nil, H3FrameHeaders, 4000)
	used = 0
	r = NewRequestStream(0, 0)
	r.SetBudget(func(n int) bool {
		if used+n > 1000 {
			return false
		}
		used += n
		return true
	}, func(n int) { used -= n })
	r.Feed(big)
	for range 20 {
		r.Feed(make([]byte, 100))
	}
	if !errors.Is(r.Err(), ErrH3Budget) || r.HeadersSeen || r.Held() != used || used != 512 || cap(r.fr.buf) != 512 {
		t.Fatalf("deny: %v held %d used %d cap %d", r.Err(), r.Held(), used, cap(r.fr.buf))
	}
}
