package store

import (
	"encoding/json"
	"net/netip"
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
