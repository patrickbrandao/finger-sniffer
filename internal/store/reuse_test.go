package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Testes da task 424: conexão nova na mesma 5-tupla (porta de origem reaproveitada) ganha registro próprio, com
// pacotes (Initial QUIC com DCID novo sem o close da anterior) e só com eventos (QUIC e TCP), sem quebrar as
// junções legítimas (eventos atrasados, Initial com o SCID do espelho, migração de caminho).

var (
	mirrorSCID = []byte{0x5c, 0x1d, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	probeA     = "a1b2c3d4"
	probeB     = "b1b2c3d4"
)

// quicInitialSCID é um Initial QUIC v1 de 1200 bytes com DCID e SCID dados.
func quicInitialSCID(dcid, scid []byte) []byte { return quicLong(0, dcid, scid, 1200) }

// quicHandshake é o início de uma conexão QUIC como o quic-go faz: Initial do cliente com o DCID original, Initial
// do espelho com o SCID dele, Initial seguinte do cliente já com esse SCID como DCID e trocas 1-RTT.
func quicHandshake(dcid []byte, at int) []udpPkt {
	return []udpPkt{
		{at, true, quicInitialSCID(dcid, []byte{0xc1, 0x1e})},
		{at + 10, false, quicInitialSCID([]byte{0xc1, 0x1e}, mirrorSCID)},
		{at + 15, true, quicInitialSCID(mirrorSCID, []byte{0xc1, 0x1e})},
		{at + 20, true, quicShort(60)},
		{at + 40, false, quicShort(900)},
	}
}

// h3Ev monta um evento h3 da 5-tupla cli → quicMirror com o DCID e o probe dados.
func h3Ev(t testing.TB, subject string, cli netip.AddrPort, dcid []byte, ms int, probe string, payload any) fakeMsg {
	t.Helper()
	flow := &event.Flow{
		L4: "udp", SrcIP: cli.Addr().String(), SrcPort: int(cli.Port()), DstIP: quicMirror.Addr().String(),
		DstPort: int(quicMirror.Port()), QUICDCIDHex: hex.EncodeToString(dcid),
	}
	env, err := event.New(event.ServiceWeb, "test", time.Unix(0, base+int64(ms)*1e6), flow, payload)
	if err != nil {
		t.Fatal(err)
	}
	env.ProbeID = &probe
	data, _ := json.Marshal(env)
	return fakeMsg{subject: subject, data: data}
}

// h3Requests são as 3 requisições da sondagem h3 do loadgen, a partir de ms.
func h3Requests(t testing.TB, dcid []byte, ms int, probe string) []fakeMsg {
	return []fakeMsg{
		h3Ev(t, event.SubjectWebHTTP3Connection, quicClient, dcid, ms, probe, h3Conn("h3", true, nil)),
		h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcid, ms+10, probe, h3Req(0, "/p/"+probe+"/", 200)),
		h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcid, ms+20, probe, h3Req(4, "/p/"+probe+"/", 200)),
		h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcid, ms+30, probe, h3Req(8, "/p/"+probe+"/", 200)),
	}
}

// h3CloseEv é o http3.connection final (CONNECTION_CLOSE do cliente) em ms.
func h3CloseEv(t testing.TB, dcid []byte, ms int, probe string) fakeMsg {
	cl := &event.HTTP3Close{By: "client", How: event.QUICCloseApplication, ErrorCode: ptrTo(uint64(0x100))}
	return h3Ev(t, event.SubjectWebHTTP3Connection, quicClient, dcid, ms, probe, h3Conn("h3", true, cl))
}

type connRow struct {
	id, probe string
	requests  int
	appEvents int
}

// connRows lista as conexões em ordem de início, com o probe, as requisições e os eventos de cada uma.
func connRows(t *testing.T, db *sql.DB) []connRow {
	t.Helper()
	rows, err := db.Query(`SELECT c.conn_id, coalesce(c.probe_id, ''), c.requests,
		(SELECT count(*) FROM app_events a WHERE a.conn_id = c.conn_id) FROM connections c ORDER BY c.started_ns`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []connRow
	for rows.Next() {
		var r connRow
		if err := rows.Scan(&r.id, &r.probe, &r.requests, &r.appEvents); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// wantProbes confere que há uma conexão por probe, na ordem dada, com n eventos de aplicação cada.
func wantProbes(t *testing.T, db *sql.DB, events []int, probes ...string) []connRow {
	t.Helper()
	got := connRows(t, db)
	if len(got) != len(probes) {
		t.Fatalf("%d connections %+v, want one per probe %v", len(got), got, probes)
	}
	for i, p := range probes {
		if got[i].probe != p || got[i].appEvents != events[i] {
			t.Fatalf("connection %d: %+v, want probe %s with %d events", i, got[i], p, events[i])
		}
	}
	return got
}

// TestQUICReuseNewDCIDWithoutClose: caso do Mac da task 296. O CONNECTION_CLOSE da primeira conexão se perdeu (o
// web só fecha na ociosidade), e 15 s depois o cliente reaproveita a porta de origem: o Initial com DCID novo abre
// conexão nova, e os eventos dela vão para o registro dela, não para o da primeira.
func TestQUICReuseNewDCIDWithoutClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)...)...)
	run(t, in, 15_100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 15_000))}, h3Requests(t, dcidB, 15_030, probeB)...)...)
	run(t, in, 15_200, h3CloseEv(t, dcidB, 15_100, probeB))
	run(t, in, 20_000)
	got := wantProbes(t, db, []int{4, 5}, probeA, probeB)
	if got[0].requests != 3 || got[1].requests != 3 {
		t.Fatalf("requests %+v", got)
	}
	if r := recordOf(t, in, got[1].id); r.Ended == nil || r.Close.How != "quic_close" {
		t.Fatalf("second connection must close with its own close: %+v", r.Close)
	}
	if r := recordOf(t, in, got[0].id); r.Ended == nil || r.Close.How == "quic_close" {
		t.Fatalf("first connection ends when the second starts, without the second's close: %+v", r.Close)
	}
}

// TestQUICSameConnectionInitials: os Initials do cliente da mesma conexão não dividem o registro: retransmissão
// com o DCID original e Initial com o SCID do espelho como DCID, mesmo depois de uma pausa; Initial com DCID novo
// num fluxo que ainda não viu cabeçalho longo do espelho com SCID também não (antes da task 424 era igual).
func TestQUICSameConnectionInitials(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)...)...)
	run(t, in, 5100, udpBatch(quicClient, quicMirror, []udpPkt{
		{3000, true, quicInitialSCID(dcidA, []byte{0xc1, 0x1e})},
		{5000, true, quicInitialSCID(mirrorSCID, []byte{0xc1, 0x1e})},
	}))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("Initials of the same connection split it: %d", n)
	}
	// Espelho que respondeu sem SCID (fluxo legado dos testes): o DCID novo sem close continua na mesma.
	other := netip.MustParseAddrPort("192.0.2.11:52001")
	run(t, in, 6100, udpBatch(other, quicMirror, quicPackets(dcidA, 6000)))
	run(t, in, 7100, udpBatch(other, quicMirror, []udpPkt{{7000, true, quicInitial(dcidB)}}))
	if n := count(t, db, "SELECT count(*) FROM connections WHERE src_port = ?", int(other.Port())); n != 1 {
		t.Fatalf("new DCID without the mirror's SCID split the flow: %d", n)
	}
}

// TestQUICReuseLateEventOfFirst: depois da divisão pelos pacotes, evento atrasado da primeira conexão (DCID
// antigo, de antes do início da segunda) continua na primeira.
func TestQUICReuseLateEventOfFirst(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)[:2]...)...)
	run(t, in, 15_100, udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 15_000)),
		h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 60, probeA, h3Req(4, "/late", 200)))
	run(t, in, 15_200, h3Requests(t, dcidB, 15_030, probeB)...)
	run(t, in, 200_000)
	wantProbes(t, db, []int{3, 4}, probeA, probeB)
}

// TestQUICMigrationKeepsRecord: na migração de caminho os pacotes passam a vir de outra porta (outra 5-tupla, só
// cabeçalho curto), e os eventos do web seguem com a 5-tupla e o DCID do início: continuam no mesmo registro.
func TestQUICMigrationKeepsRecord(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	migrated := netip.MustParseAddrPort("192.0.2.10:52999")
	run(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)[:2]...)...)
	run(t, in, 20_100, udpBatch(migrated, quicMirror, []udpPkt{{20_000, true, quicShort(50)}, {20_010, false, quicShort(500)}}),
		h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 20_020, probeA, h3Req(4, "/after-migration", 200)),
		h3CloseEv(t, dcidA, 20_050, probeA))
	run(t, in, 60_000)
	var n int
	if err := db.QueryRow("SELECT count(*) FROM connections WHERE probe_id = ? AND src_port = ?", probeA, int(quicClient.Port())).Scan(&n); err != nil || n != 1 {
		t.Fatalf("records of the migrated connection: %d %v", n, err)
	}
	if r := connRows(t, db)[0]; r.appEvents != 4 || r.requests != 2 {
		t.Fatalf("%+v", r)
	}
}

// TestQUICReuseEventOnly: caso da loopback da task 296 (sem pacotes). A segunda conexão reaproveita a porta 10 s
// depois da primeira: DCID novo nos eventos e reserva de conn_id própria. Antes da task 424 a reserva guardada para
// os pacotes atrasados da primeira era devolvida ao accept da segunda, e os eventos dela iam para a primeira.
func TestQUICReuseEventOnly(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	first, _, _ := in.flows.connID(protoUDP, quicClient, quicMirror, base, base)
	processAt(t, in, 100, append(h3Requests(t, dcidA, 0, probeA), h3CloseEv(t, dcidA, 3800, probeA))...)
	processAt(t, in, 4000)
	second, reserved, _ := in.flows.connID(protoUDP, quicClient, quicMirror, base+10_000e6, base+10_000e6)
	if !reserved || second == first {
		t.Fatalf("accept of a new connection got %s (reserved %v), first %s", second, reserved, first)
	}
	processAt(t, in, 10_100, append(h3Requests(t, dcidB, 10_000, probeB), h3CloseEv(t, dcidB, 13_800, probeB))...)
	processAt(t, in, 14_000)
	got := wantProbes(t, db, []int{5, 5}, probeA, probeB)
	if got[0].id != first || got[1].id != second || got[0].requests != 3 || got[1].requests != 3 {
		t.Fatalf("%+v want ids %s, %s", got, first, second)
	}
	if in.metrics.Get("store_event_only_connections_total") != 2 {
		t.Fatalf("event-only connections %v", in.metrics.Get("store_event_only_connections_total"))
	}
}

// TestQUICReuseEventOnlyByDCID: sem pedido de conn_id (web sem resposta do store), o DCID novo nos eventos basta;
// evento atrasado da primeira (DCID antigo, de antes do início da segunda) vai ao registro gravado dela.
func TestQUICReuseEventOnlyByDCID(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	reqs := h3Requests(t, dcidA, 0, probeA)
	processAt(t, in, 100, reqs[:3]...)
	processAt(t, in, 4000)
	processAt(t, in, 10_100, h3Requests(t, dcidB, 10_000, probeB)...)
	processAt(t, in, 10_200, reqs[3]) // atrasado: ts 30 ms
	processAt(t, in, 12_500)
	wantProbes(t, db, []int{4, 4}, probeA, probeB)
}

// TestQUICReuseEventOnlyAfterClose: sem pedido de conn_id e com o mesmo DCID (o web reaproveitou a análise do
// Initial da anterior), o evento bem depois do fim h3 da anterior é de outra conexão.
func TestQUICReuseEventOnlyAfterClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 100, append(h3Requests(t, dcidA, 0, probeA), h3CloseEv(t, dcidA, 3800, probeA))...)
	processAt(t, in, 4000)
	// Evento publicado no fechamento, dentro da folga: ainda da primeira.
	processAt(t, in, 5000, h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 4500, probeA, h3Req(12, "/closing", 200)))
	processAt(t, in, 10_100, h3Requests(t, dcidA, 10_000, probeB)...)
	processAt(t, in, 12_500)
	wantProbes(t, db, []int{6, 4}, probeA, probeB)
}

// TestTCPReuseEventOnly: TCP só de eventos (mix da task 256 pela loopback). Cada accept pede o conn_id; a segunda
// conexão na mesma 5-tupla, 5 s depois, ganha o ID e o registro próprios. Evento atrasado da primeira (publicado
// depois dos da segunda, com ts de antes do accept dela) continua na primeira; outro evento da segunda, 20 s
// depois, continua na segunda.
func TestTCPReuseEventOnly(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	first, _, _ := in.flows.connID(protoTCP, client, mirror, base, base)
	processAt(t, in, 100, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 30, probeA, hello),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 60, probeA, map[string]any{"index": 0}))
	processAt(t, in, 2500)
	second, reserved, _ := in.flows.connID(protoTCP, client, mirror, base+5000e6, base+5000e6)
	if !reserved || second == first {
		t.Fatalf("accept of a new connection got %s (reserved %v), first %s", second, reserved, first)
	}
	processAt(t, in, 5100, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 5030, probeB, hello),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 5060, probeB, map[string]any{"index": 0}),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 900, probeA, map[string]any{"index": 1}))
	processAt(t, in, 7500)
	processAt(t, in, 25_100, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 25_000, probeB, map[string]any{"index": 1}))
	got := wantProbes(t, db, []int{3, 3}, probeA, probeB)
	if got[0].id != first || got[1].id != second || got[0].requests != 2 || got[1].requests != 2 {
		t.Fatalf("%+v want ids %s, %s", got, first, second)
	}
	// A primeira saiu do conjunto das só de eventos quando a segunda tomou o lugar: o closed dela saiu.
	if r := recordOf(t, in, first); r.Ended == nil {
		t.Fatal("first must be closed")
	}
}

// TestTCPEventOnlyAcceptKeepsJoining: a conexão só de eventos criada com a reserva do accept continua recebendo os
// eventos dela (inclusive um de antes da criação, ainda na fila, e outro 25 s depois) e os pacotes atrasados dela
// a adotam; a reserva consumida não marca conexão nova.
func TestTCPEventOnlyAcceptKeepsJoining(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	id, _, _ := in.flows.connID(protoTCP, client, mirror, base, base)
	processAt(t, in, 100, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 30, probeA, hello))
	processAt(t, in, 2500, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 2400, probeA, map[string]any{"index": 0}))
	processAt(t, in, 27_500, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 27_400, probeA, map[string]any{"index": 1}))
	processAt(t, in, 27_600, batch(client, mirror, protoTCP, fullTCP))
	got := wantProbes(t, db, []int{3}, probeA)
	if got[0].id != id {
		t.Fatalf("id %s want %s", got[0].id, id)
	}
	if in.flows.reservations() != 0 {
		t.Fatalf("reservations %d", in.flows.reservations())
	}
}

// TestEventOnlyRollbackKeepsReservation: o lote que cria a conexão só de eventos com a reserva do accept é
// desfeito; a reserva volta, e a reentrega cria a conexão com o mesmo conn_id (o que o web mostrou ao cliente).
func TestEventOnlyRollbackKeepsReservation(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	id, _, _ := in.flows.connID(protoTCP, client, mirror, base, base)
	processAt(t, in, 100, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 30, probeA, hello))
	drop := failOn(t, db, "app_events")
	in.now = func() time.Time { return time.Unix(0, base+2500e6) }
	if err := processErr(in); err == nil {
		t.Fatal("want error")
	}
	if in.flows.reservations() != 1 || count(t, db, "SELECT count(*) FROM connections") != 0 {
		t.Fatalf("rollback must give the reservation back: %d", in.flows.reservations())
	}
	drop()
	processAt(t, in, 2600)
	if got := wantProbes(t, db, []int{1}, probeA); got[0].id != id {
		t.Fatalf("id %s want %s", got[0].id, id)
	}
}
