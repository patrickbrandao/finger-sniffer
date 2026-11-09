package loadstat

import (
	"testing"
	"time"
)

func TestClockTrackFollowsRamp(t *testing.T) {
	t0 := time.Unix(1000, 0)
	c := NewClockTrack(t0, 268*time.Millisecond, 12*time.Millisecond)
	if got := c.Offset(); got != 268*time.Millisecond {
		t.Fatalf("offset inicial = %v", got)
	}
	// rampa do timesyncd: a medição nova vale
	if !c.Update(t0.Add(15*time.Second), 260*time.Millisecond, 14*time.Millisecond) {
		t.Fatal("medição com ida e volta boa rejeitada")
	}
	if got := c.Offset(); got != 260*time.Millisecond {
		t.Fatalf("offset depois da rampa = %v", got)
	}
	// ida e volta longa (fila no ssh): fica a anterior
	if c.Update(t0.Add(30*time.Second), 100*time.Millisecond, 80*time.Millisecond) {
		t.Fatal("medição com ida e volta ruim aceita")
	}
	if got := c.Offset(); got != 260*time.Millisecond {
		t.Fatalf("offset mudou por medição rejeitada: %v", got)
	}
	// limite: melhor + 10 ms quando 2× a melhor é menor
	c2 := NewClockTrack(t0, 0, 4*time.Millisecond)
	if !c2.Update(t0, time.Millisecond, 14*time.Millisecond) {
		t.Fatal("melhor + 10 ms deveria valer")
	}
	if c2.Update(t0, time.Millisecond, 15*time.Millisecond) {
		t.Fatal("acima de melhor + 10 ms deveria ser rejeitada")
	}
	lo, hi := c.OffsetRange()
	if lo != 260*time.Millisecond || hi != 268*time.Millisecond {
		t.Fatalf("faixa = %v..%v", lo, hi)
	}
	if n := len(c.Samples()); n != 3 {
		t.Fatalf("amostras = %d", n)
	}
}
