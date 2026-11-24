package agg

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"
)

// shapeReq é uma requisição com TTL e tempos do relay (ADR 0078).
func shapeReq(at time.Time, reused bool, os string, ttl int, quic, timed, gap, frac, first bool) Request {
	r := req(at, "192.0.2.10", "s.com", "/", reused, ClassHuman)
	r.OSClass, r.TTLInitial, r.QUIC = os, ttl, quic
	r.Timed, r.RelayGap, r.RelayFrac, r.RelayFirst = timed, gap, frac, first
	return r
}

func queryShape(a *Aggregator, now time.Time) Stats {
	return a.Query(netip.MustParseAddr("192.0.2.10"), "s.com", now)
}

// TestShapeFirstRequestOnly: máscaras e contagens só da primeira requisição de cada conexão; TTL fora de
// 32/64/128/255 não entra; a classe vazia ou desconhecida é other.
func TestShapeFirstRequestOnly(t *testing.T) {
	a := New(Config{})
	a.Observe(shapeReq(t0, false, OSClassUnix, 64, false, true, true, true, true))
	a.Observe(shapeReq(t0.Add(time.Second), true, OSClassUnix, 128, false, true, true, true, true)) // reuso: não entra
	a.Observe(shapeReq(t0.Add(2*time.Second), false, OSClassUnix, 60, false, true, false, true, false))
	a.Observe(shapeReq(t0.Add(3*time.Second), false, OSClassUnix, 128, true, false, true, true, true)) // h3 sem tempos
	a.Observe(shapeReq(t0.Add(4*time.Second), false, "", 255, false, false, false, false, false))
	a.Observe(shapeReq(t0.Add(5*time.Second), false, "bsd", 32, true, false, false, false, false))
	a.Observe(shapeReq(t0.Add(6*time.Second), false, OSClassWindows, 0, false, false, false, false, false))
	st := queryShape(a, t0.Add(7*time.Second))
	want := [3]TTLMasks{{}, {TCP: 0b0010, H3: 0b0100}, {TCP: 0b1000, H3: 0b0001}}
	if st.HourTTL != want {
		t.Fatalf("máscaras %+v, quer %+v", st.HourTTL, want)
	}
	if st.HourTimed != 2 || st.HourRelayGap != 1 || st.HourRelayFrac != 2 || st.HourRelayFirst != 1 {
		t.Fatalf("relay %d/%d/%d/%d", st.HourTimed, st.HourRelayGap, st.HourRelayFrac, st.HourRelayFirst)
	}
	if st.HourConns != 6 || st.HourReused != 1 {
		t.Fatalf("contagens %+v", st)
	}
}

// TestShapeSaturates: os contadores do relay saturam em 65 535 (ADR 0078 item 3).
func TestShapeSaturates(t *testing.T) {
	a := New(Config{})
	a.Observe(shapeReq(t0, false, OSClassUnix, 64, false, true, true, true, true))
	k := siteKey{ip: ipKey(netip.MustParseAddr("192.0.2.10")), site: "s.com"}
	sh := &a.sites[k].open[t0.Unix()/3600].shape
	sh.timed, sh.gap, sh.frac, sh.first = math.MaxUint16-1, math.MaxUint16-1, math.MaxUint16-1, math.MaxUint16-1
	for i := range 3 {
		a.Observe(shapeReq(t0.Add(time.Duration(i+1)*time.Second), false, OSClassUnix, 64, false, true, true, true, true))
	}
	st := queryShape(a, t0.Add(5*time.Second))
	if st.HourTimed != math.MaxUint16 || st.HourRelayGap != math.MaxUint16 || st.HourRelayFrac != math.MaxUint16 ||
		st.HourRelayFirst != math.MaxUint16 {
		t.Fatalf("saturação %+v", st)
	}
}

// TestShapeCurrentHourOnly: com relógio falso, os campos são só da hora corrente: zeram na troca da hora, não vão
// ao ip_hourly e não voltam no Load nem nas horas fechadas do cache.
func TestShapeCurrentHourOnly(t *testing.T) {
	ctx := context.Background()
	now := t0
	clock := func() time.Time { return now }
	db := openDB(t)
	a := New(Config{Now: clock})
	a.Observe(shapeReq(now, false, OSClassWindows, 128, false, true, true, true, true))
	a.Observe(shapeReq(now.Add(time.Second), false, OSClassWindows, 64, true, false, false, false, false))
	if st := queryShape(a, now.Add(2*time.Second)); st.HourTimed != 1 || st.HourTTL[0] != (TTLMasks{TCP: 0b0100, H3: 0b0010}) {
		t.Fatalf("hora corrente %+v", st)
	}
	if err := a.Flush(ctx, db, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	r := readHour(t, db, "192.0.2.10", "s.com", t0)
	if want := (hourRow{requests: 2, conns: 2, paths: 1, ivN: 1, ivSum: 1, ivSq: 1, human: 2}); r != want {
		t.Fatalf("ip_hourly %+v, quer %+v", r, want)
	}
	// a hora vira: a hora gravada passa ao cache sem os campos novos
	now = t0.Add(time.Hour + time.Minute)
	if err := a.Flush(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	st := queryShape(a, now)
	if st.DayRequests != 2 || st.HourRequests != 0 || st.HourTimed != 0 || st.HourTTL != ([3]TTLMasks{}) {
		t.Fatalf("depois da troca da hora %+v", st)
	}
	// a hora nova começa do zero
	a.Observe(shapeReq(now, false, OSClassUnix, 64, false, true, false, false, true))
	if st := queryShape(a, now.Add(time.Second)); st.HourTimed != 1 || st.HourRelayFirst != 1 || st.HourRelayGap != 0 ||
		st.HourTTL != ([3]TTLMasks{{}, {TCP: 0b0010}, {}}) {
		t.Fatalf("hora nova %+v", st)
	}
	// o Load (reinício) traz as contagens da hora do banco, nunca os campos novos
	b := New(Config{Now: clock})
	if err := b.Load(ctx, db, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if st := queryShape(b, t0.Add(30*time.Minute)); st.HourRequests != 2 || st.HourTimed != 0 || st.HourTTL != ([3]TTLMasks{}) {
		t.Fatalf("depois do Load %+v", st)
	}
}

// TestShapeForget: o forget apaga os campos com a entrada.
func TestShapeForget(t *testing.T) {
	a := New(Config{})
	a.Observe(shapeReq(t0, false, OSClassUnix, 64, true, true, true, true, true))
	if n := a.Forget(netip.MustParsePrefix("192.0.2.10/32")); n != 1 {
		t.Fatalf("forget %d", n)
	}
	// uma requisição de reuso recria a entrada sem conexão nova: nada das máscaras nem do relay volta
	a.Observe(shapeReq(t0.Add(time.Second), true, OSClassUnix, 64, true, true, true, true, true))
	st := queryShape(a, t0.Add(2*time.Second))
	if !st.Known || st.HourTimed != 0 || st.HourTTL != ([3]TTLMasks{}) {
		t.Fatalf("depois do forget %+v", st)
	}
}
