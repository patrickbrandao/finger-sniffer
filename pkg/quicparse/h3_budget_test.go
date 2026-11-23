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
	// Depois do frame só ficam reservados os campos decodificados (task 330), devolvidos por quem publica.
	if used != r.FieldsHeld() || used != 3*FieldOverhead+len(":methodGET:path/x-a1") || peak != max(len(fields), used) ||
		r.Held() != 0 || r.fr.buf != nil {
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

// task 330: o decodificado reserva do orçamento; sem reserva, ou acima de MAX_FIELD_SECTION_SIZE, ErrH3Budget
// sem guardar os campos.
func TestRequestStreamDecodedBudget(t *testing.T) {
	sec := AppendFieldSection(nil, [][2]string{{":method", "GET"}, {"x-a", "1"}})
	frame := AppendH3Frame(nil, H3FrameHeaders, sec)
	r := NewRequestStream(0, 0)
	r.SetBudget(func(n int) bool { return n <= len(sec) }, func(int) {}) // aceita o payload, recusa os campos
	r.Feed(frame)
	if !errors.Is(r.Err(), ErrH3Budget) || len(r.Request.Fields) != 0 || r.FieldsHeld() != 0 {
		t.Fatalf("err %v fields %d held %d", r.Err(), len(r.Request.Fields), r.FieldsHeld())
	}
	// Seção decodificada acima de 1 MiB (literais curtos repetidos), mesmo sem orçamento ligado.
	var fs [][2]string
	for range 40000 {
		fs = append(fs, [2]string{"x-a", "1"})
	}
	r = NewRequestStream(0, 1<<20)
	r.Feed(AppendH3Frame(nil, H3FrameHeaders, AppendFieldSection(nil, fs)))
	if !errors.Is(r.Err(), ErrH3Budget) || len(r.Request.Fields) != 0 {
		t.Fatalf("section: err %v fields %d", r.Err(), len(r.Request.Fields))
	}
}

// task 331: o stream de controle guarda frames até 64 KiB; acima, ErrH3FrameTooLarge sem alocar; com
// SetBudget a reserva acompanha o buffer e volta a zero ao completar.
func TestUniStreamControlBudget(t *testing.T) {
	u := NewUniStream()
	u.Feed([]byte{byte(StreamTypeControl)})
	u.Feed(AppendH3FrameHeader(nil, H3FrameSettings, 1<<20))
	u.Feed(make([]byte, 4096))
	if !errors.Is(u.Err(), ErrH3FrameTooLarge) || cap(u.fr.buf) != 0 {
		t.Fatalf("err %v cap %d", u.Err(), cap(u.fr.buf))
	}
	used, peak := 0, 0
	u = NewUniStream()
	u.SetBudget(func(n int) bool { used += n; peak = max(peak, used); return true }, func(n int) { used -= n })
	settings := AppendH3Frame([]byte{byte(StreamTypeControl)}, H3FrameSettings, []byte{0x06, 0x44, 0x00})
	for i := range settings {
		u.Feed(settings[i : i+1])
		if i < len(settings)-1 && u.Held() != used {
			t.Fatalf("held %d used %d", u.Held(), used)
		}
	}
	if u.Err() != nil || !u.SettingsSeen || used != 0 || peak == 0 || u.Held() != 0 {
		t.Fatalf("err %v seen %v used %d peak %d", u.Err(), u.SettingsSeen, used, peak)
	}
}
