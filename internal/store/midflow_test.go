package store

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Avulsos de meio de fluxo (ADR 0041 item 5, task 245).

func midflowIngestor(t *testing.T) (*Ingestor, *storeMetrics) {
	t.Helper()
	in, _ := newTestIngestor(t, func(c *IngestConfig) { c.TCPIdle = 630 * time.Second; c.MaxOpen = 1000; c.MaxNewPerS = 150 })
	m := newStoreMetrics(metricsHealth, in.flows.open, nil)
	in.SetMetrics(m)
	return in, m
}

// TestStrayMidflow: sessão TCP sem o início (só ACK/dados) conta no midflow, menos o RST; SYN sem resposta e RST
// avulso contam só em fs_store_stray_packets_total.
func TestStrayMidflow(t *testing.T) {
	in, m := midflowIngestor(t)
	synOnly := netip.MustParseAddrPort("192.0.2.20:40000")
	rstOnly := netip.MustParseAddrPort("192.0.2.21:40000")
	stepAt(t, in, ms(100),
		batch(client, mirror, protoTCP, []pkt{
			{0, true, tcpACK | tcpPSH, 100}, {5, false, tcpACK, 0}, {10, true, tcpACK, 0}, {20, false, tcpRST, 0},
		}),
		batch(synOnly, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {1000, true, tcpSYN, 0}}),
		batch(rstOnly, mirror, protoTCP, []pkt{{30, true, tcpRST, 0}}))
	stepAt(t, in, 12*time.Second)
	if n := count(t, in.db, "SELECT count(*) FROM stray_packets"); n != 7 {
		t.Fatalf("stray packets: %d", n)
	}
	if v := testutil.ToFloat64(m.stray); v != 7 {
		t.Fatalf("fs_store_stray_packets_total %v", v)
	}
	if v := testutil.ToFloat64(m.midflow); v != 3 {
		t.Fatalf("fs_store_stray_midflow_total %v", v)
	}
	problems, err := testutil.GatherAndLint(m.reg, "fs_store_stray_midflow_total")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint %s: %s", p.Metric, p.Text)
	}
}

// TestLagNoStrays: com o ingest 20 s atrasado e lotes pequenos (o handshake de quase toda conexão partido entre
// lotes), 100 conexões do mix da carga oficial dão 100 registros, sem avulsos nem midflow.
func TestLagNoStrays(t *testing.T) {
	in, m := midflowIngestor(t)
	msgs, at := benchWorkload(t, 100)
	lag := 20 * time.Second
	for i := 0; i < len(msgs); i += 8 {
		j := min(i+8, len(msgs))
		stepAt(t, in, ms(at[j-1])+lag, msgs[i:j]...)
	}
	stepAt(t, in, ms(at[len(at)-1])+lag+5*time.Second)
	if n := count(t, in.db, "SELECT count(*) FROM connections"); n != 100 {
		t.Fatalf("connections: %d", n)
	}
	if n := count(t, in.db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL"); n != 0 {
		t.Fatalf("open: %d", n)
	}
	if n := count(t, in.db, "SELECT count(*) FROM stray_packets"); n != 0 {
		t.Fatalf("stray packets: %d", n)
	}
	if v := testutil.ToFloat64(m.midflow); v != 0 {
		t.Fatalf("midflow %v", v)
	}
}
