package store

import (
	"net/netip"
	"testing"
	"time"
)

// Fluxos abertos antes de uma lacuna do stream (ADR 0041 item 4, task 244).

// gapIngestor tem a ociosidade do TCP estabelecido de produção (630 s).
func gapIngestor(t *testing.T) *Ingestor {
	t.Helper()
	in, _ := newTestIngestor(t, func(c *IngestConfig) { c.TCPIdle = 630 * time.Second })
	return in
}

func seqAt(m fakeMsg, seq uint64, publishedMs int) seqMsg {
	return seqMsg{m, *mdAt(seq, time.Unix(0, base).Add(ms(publishedMs)), 0)}
}

func stepSeq(t *testing.T, in *Ingestor, wall time.Duration, msgs ...seqMsg) {
	t.Helper()
	in.now = func() time.Time { return time.Unix(0, base).Add(wall) }
	src := make([]msgSource, len(msgs))
	for i, m := range msgs {
		src[i] = m
	}
	if err := in.process(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	in.afterBatch(t.Context())
}

var otherCli = netip.MustParseAddrPort("192.0.2.99:50000")

// TestGapClosesStuckFlow: TCP estabelecido cujo FIN expirou no stream (salto de 2 para 5): fecha por ociosidade
// ~10 s depois do último pacote, não em 630 s, e sai da conta de vivas do modo degradado.
func TestGapClosesStuckFlow(t *testing.T) {
	in := gapIngestor(t)
	db := in.db
	stepSeq(t, in, ms(50), seqAt(batch(client, mirror, protoTCP, fullTCP[:6]), 1, 45))
	// 2..4 (o FIN e o ACK final) expiraram; a 5 é tráfego de outra 5-tupla publicado em 2 s
	stepSeq(t, in, ms(2010), seqAt(batch(otherCli, mirror, protoTCP, []pkt{{2000, true, tcpSYN, 0}}), 5, 2005))
	if lost, _, _ := in.stream.snapshot(); lost != 3 {
		t.Fatalf("lost %d", lost)
	}
	if in.flows.liveLimited() != 2 {
		t.Fatalf("live %d", in.flows.liveLimited())
	}
	stepSeq(t, in, ms(10_030)) // 9,99 s depois do último pacote (40 ms)
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL AND src_port = ?", int(client.Port())); n != 1 {
		t.Fatal("suspect flow closed before 10 s")
	}
	stepSeq(t, in, ms(10_051)) // C = 2000 + (parede − 2010): 10 s depois do último pacote
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL AND src_port = ?", int(client.Port())); n != 1 {
		t.Fatal("suspect flow still open 10 s after its last packet")
	}
	r := recordOf(t, in, mustID(t, in, client))
	if r.Close.How != "timeout" {
		t.Fatalf("close %+v", r.Close)
	}
	if in.flows.liveLimited() != 1 { // só o SYN de otherCli, que vence em 12 s
		t.Fatalf("live after close: %d", in.flows.liveLimited())
	}
}

// TestGapPacketClearsMark: um pacote depois do salto devolve o prazo normal; um fluxo cujo último pacote é
// posterior à mensagem do salto não é marcado.
func TestGapPacketClearsMark(t *testing.T) {
	in := gapIngestor(t)
	later := netip.MustParseAddrPort("192.0.2.11:41000")
	stepSeq(t, in, ms(50),
		seqAt(batch(client, mirror, protoTCP, fullTCP[:6]), 1, 45),
		seqAt(batch(later, mirror, protoTCP, []pkt{{3000, true, tcpSYN, 0}, {3001, false, tcpSYN | tcpACK, 0}, {3002, true, tcpACK, 0}}), 2, 3005))
	// salto revelado por uma mensagem publicada em 2 s: só client (último pacote em 40 ms) fica suspeito
	stepSeq(t, in, ms(2010), seqAt(batch(otherCli, mirror, protoTCP, []pkt{{2000, true, tcpSYN, 0}}), 6, 2000))
	if c := in.flows.connByID(mustID(t, in, client)); c == nil || !c.suspect {
		t.Fatal("flow before the gap must be suspect")
	}
	if c := in.flows.connByID(mustID(t, in, later)); c == nil || c.suspect {
		t.Fatal("flow seen after the gap message must not be suspect")
	}
	stepSeq(t, in, ms(5010), seqAt(batch(client, mirror, protoTCP, []pkt{{5000, true, tcpACK | tcpPSH, 10}}), 7, 5005))
	stepSeq(t, in, ms(60_000))
	for _, cli := range []netip.AddrPort{client, later} {
		if c := in.flows.connByID(mustID(t, in, cli)); c == nil || c.suspect {
			t.Fatalf("%s must stay open with the normal idle timeout", cli)
		}
	}
}

// mustID devolve o conn_id da conexão de cli (a mais recente).
func mustID(t *testing.T, in *Ingestor, cli netip.AddrPort) string {
	t.Helper()
	var id string
	if err := in.db.QueryRow("SELECT conn_id FROM connections WHERE src_port = ? AND src_ip = ? ORDER BY started_ns DESC LIMIT 1",
		int(cli.Port()), cli.Addr().String()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
