package store

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// dnsOnly deixa o probe da fixture só com a consulta DNS (a conexão encerrada perde o probe).
func dnsOnly(t *testing.T, f *apiFixture) {
	t.Helper()
	if _, err := f.in.db.Exec("UPDATE connections SET probe_id = NULL WHERE conn_id = ?", f.closed); err != nil {
		t.Fatal(err)
	}
}

func TestProbeWaitDNSOnlyThenConnection(t *testing.T) {
	f := newAPIFixture(t)
	dnsOnly(t, f)
	// A conexão do probe aparece 1 s depois (aberta) e fecha 300 ms mais tarde.
	closedAt := make(chan time.Time, 1)
	go func() {
		time.Sleep(time.Second)
		if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(300 * time.Millisecond)
		other := netip.MustParseAddrPort("192.0.2.20:50000")
		run(t, f.in, 9000, batch(other, mirror, protoTCP, fullTCP[4:]))
		closedAt <- time.Now()
	}()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=10s")
	done := time.Now()
	var p probeJSON
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || !p.AllClosed || len(p.Connections) != 1 || len(p.DNS) != 1 {
		t.Fatalf("%d %s", code, body)
	}
	select {
	case c := <-closedAt:
		if d := done.Sub(c); d > 500*time.Millisecond {
			t.Fatalf("respondeu %v depois do fechamento", d)
		}
	default:
		t.Fatal("respondeu antes de a conexão fechar")
	}
}

func TestProbeWaitNothingIs404AfterDeadline(t *testing.T) {
	f := newAPIFixture(t)
	start := time.Now()
	if code, _ := f.get(t, "/api/v1/probes/zzzzzzzz?wait=300ms"); code != 404 || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("%d em %v", code, time.Since(start))
	}
}

func TestProbeWaitDNSOnlyUntilDeadline(t *testing.T) {
	f := newAPIFixture(t)
	dnsOnly(t, f)
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=300ms")
	var p probeJSON
	if code != 200 || time.Since(start) < 300*time.Millisecond || json.Unmarshal([]byte(body), &p) != nil ||
		!p.AllClosed || len(p.Connections) != 0 || len(p.DNS) != 1 {
		t.Fatalf("%d %v %s", code, time.Since(start), body)
	}
}

func TestProbeNoWaitIsImmediate(t *testing.T) {
	f := newAPIFixture(t)
	dnsOnly(t, f)
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID)
	if code != 200 || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("%d %v %s", code, time.Since(start), body)
	}
	start = time.Now()
	if code, _ := f.get(t, "/api/v1/probes/zzzzzzzz"); code != 404 || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("%d %v", code, time.Since(start))
	}
}

// probeResp decodifica a resposta de /probes com wait_met.
func probeResp(t *testing.T, body string) (p probeJSON) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return p
}

// TestProbeWaitSettle: com settle=1s, duas conexões do probe separadas por 500 ms voltam juntas, com wait_met
// true, só depois de 1 s sem mudança (ADR 0029); sem settle a resposta sairia com a primeira.
func TestProbeWaitSettle(t *testing.T) {
	f := newAPIFixture(t)
	dnsOnly(t, f)
	secondAt := make(chan time.Time, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.closed); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(500 * time.Millisecond)
		if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
			t.Error(err)
			return
		}
		run(t, f.in, 9000, batch(netip.MustParseAddrPort("192.0.2.20:50000"), mirror, protoTCP, fullTCP[4:]))
		secondAt <- time.Now()
	}()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=10s&settle=1s")
	done := time.Now()
	p := probeResp(t, body)
	if code != 200 || len(p.Connections) != 2 || !p.AllClosed || p.WaitMet == nil || !*p.WaitMet {
		t.Fatalf("%d %s", code, body)
	}
	c := <-secondAt
	if d := done.Sub(c); d < time.Second || d > 1500*time.Millisecond {
		t.Fatalf("respondeu %v depois da última mudança (quer ~1 s)", d)
	}
}

// TestProbeWaitSettleFromStore: a mudança registrada pelo store antes da consulta (updated_ns) também conta.
func TestProbeWaitSettleFromStore(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("UPDATE connections SET updated_ns = ? WHERE conn_id = ?", time.Now().UnixNano(), f.closed); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=5s&settle=500ms")
	p := probeResp(t, body)
	if d := time.Since(start); code != 200 || d < 400*time.Millisecond || d > 1500*time.Millisecond || p.WaitMet == nil || !*p.WaitMet {
		t.Fatalf("%d em %v: %s", code, d, body)
	}
	// sem settle sai na hora, com wait_met true; sem wait, wait_met não aparece
	start = time.Now()
	code, body = f.get(t, "/api/v1/probes/"+probeID+"?wait=5s")
	if p := probeResp(t, body); code != 200 || time.Since(start) > 300*time.Millisecond || p.WaitMet == nil || !*p.WaitMet {
		t.Fatalf("%d %s", code, body)
	}
	if code, body = f.get(t, "/api/v1/probes/"+probeID); code != 200 || strings.Contains(body, "wait_met") {
		t.Fatalf("%d %s", code, body)
	}
}

// TestProbeWaitMinConns: min_conns=3 com duas conexões fechadas espera o prazo e volta com wait_met false.
func TestProbeWaitMinConns(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
		t.Fatal(err)
	}
	run(t, f.in, 9000, batch(netip.MustParseAddrPort("192.0.2.20:50000"), mirror, protoTCP, fullTCP[4:]))
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=2s&min_conns=3")
	p := probeResp(t, body)
	if d := time.Since(start); code != 200 || d < 2*time.Second || len(p.Connections) != 2 || !p.AllClosed || p.WaitMet == nil || *p.WaitMet {
		t.Fatalf("%d em %v: %s", code, d, body)
	}
	start = time.Now()
	code, body = f.get(t, "/api/v1/probes/"+probeID+"?wait=2s&min_conns=2&settle=0s")
	if p := probeResp(t, body); code != 200 || time.Since(start) > 300*time.Millisecond || !*p.WaitMet {
		t.Fatalf("%d %s", code, body)
	}
}

func TestProbeWaitParams400(t *testing.T) {
	f := newAPIFixture(t)
	for _, q := range []string{
		"?wait=10s&settle=11s", "?wait=10s&settle=abc", "?wait=10s&settle=1.5s", "?wait=10s&settle=1m",
		"?wait=10s&min_conns=0", "?wait=10s&min_conns=1001", "?wait=10s&min_conns=x", "?wait=10s&min_conns=-1",
		"?settle=1s", "?min_conns=2", "?wait=abc",
	} {
		if code, body := f.get(t, "/api/v1/probes/"+probeID+q); code != 400 || !strings.Contains(body, "error") {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
	for _, q := range []string{"?wait=1s&settle=10s&min_conns=1", "?wait=1s&settle=10000ms&min_conns=1000"} {
		if code, _ := f.get(t, "/api/v1/probes/"+probeID+q); code != 200 {
			t.Errorf("%s: %d", q, code)
		}
	}
}

// TestProbeWaitZeroHasWaitMet: wait=0s é um wait válido e a resposta traz wait_met (auditoria v0.2.0, D3).
func TestProbeWaitZeroHasWaitMet(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=0s")
	if p := probeResp(t, body); code != 200 || p.WaitMet == nil || !*p.WaitMet {
		t.Fatalf("%d %s", code, body)
	}
	if pw, err := parseProbeWait(func(k string) string { return map[string]string{"wait": "0s"}[k] }); err != nil || !pw.Given || pw.Wait != 0 {
		t.Fatalf("%+v %v", pw, err)
	}
}
