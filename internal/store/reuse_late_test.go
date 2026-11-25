package store

import (
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Testes da task 432: evento h3 de uma conexão nova que chega antes dos pacotes dela não cai na anterior da mesma
// 5-tupla (DCID diferente), e o close atrasado de uma conexão só de eventos volta ao registro dela mesmo depois de
// a seguinte pedir o conn_id.

// runAt é o run com o relógio do store em atMs (a espera dos pendentes conta nele).
func runAt(t *testing.T, in *Ingestor, atMs int, msgs ...fakeMsg) {
	t.Helper()
	in.now = func() time.Time { return time.Unix(0, base+int64(atMs)*1e6) }
	run(t, in, atMs, msgs...)
}

// TestQUICNewConnEventBeforePacketsOpen: caso do Mac da task 432. A primeira conexão continua na tabela (o close
// dela não chegou e a ociosidade QUIC é longa); o http3.request do stream 0 da segunda (DCID novo) chega antes dos
// pacotes dela. Antes da correção, openFor o dava à primeira (ts depois do início dela), e o stream 0 da segunda
// sobrescrevia o da primeira.
func TestQUICNewConnEventBeforePacketsOpen(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	runAt(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)...)...)
	reqsB := h3Requests(t, dcidB, 2_800, probeB)
	runAt(t, in, 2_830, reqsB[1]) // stream 0 da segunda, sem os pacotes dela
	runAt(t, in, 2_900, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 2_790)), reqsB[0]}, reqsB[2:]...)...)
	runAt(t, in, 3_000, h3CloseEv(t, dcidB, 2_950, probeB))
	runAt(t, in, 400_000)
	got := wantProbes(t, db, []int{4, 5}, probeA, probeB)
	if got[0].requests != 3 || got[1].requests != 3 {
		t.Fatalf("requests %+v", got)
	}
}

// TestQUICNewConnEventBeforePacketsStored: a primeira já saiu da tabela pela ociosidade (registro gravado há menos
// de lateSlack) quando o stream 0 da segunda chega antes dos pacotes dela. Antes da correção, o SELECT do registro
// gravado da 5-tupla casava a primeira sem olhar o DCID.
func TestQUICNewConnEventBeforePacketsStored(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.QUICIdle = 5 * time.Second })
	runAt(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3Requests(t, dcidA, 30, probeA)...)...)
	runAt(t, in, 6_000)
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL"); n != 1 {
		t.Fatalf("first connection must be stored: %d", n)
	}
	reqsB := h3Requests(t, dcidB, 8_000, probeB)
	runAt(t, in, 8_030, reqsB[1])
	runAt(t, in, 8_100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 7_990)), reqsB[0]}, reqsB[2:]...)...)
	runAt(t, in, 8_200, h3CloseEv(t, dcidB, 8_150, probeB))
	// Evento atrasado da primeira (DCID dela, de antes do início da segunda) continua indo ao registro gravado dela.
	runAt(t, in, 8_300, h3Ev(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 7_000, probeA, h3Req(12, "/late", 200)))
	runAt(t, in, 60_000)
	got := wantProbes(t, db, []int{5, 5}, probeA, probeB)
	if got[0].requests != 4 || got[1].requests != 3 {
		t.Fatalf("requests %+v", got)
	}
}

// TestQUICEventOnlyLateCloseAfterNextAccept: caso da loopback da task 432 (sem pacotes). O quic_close da primeira
// chega depois de o web pedir o conn_id da seguinte na mesma porta, com ts dentro da folga antes desse pedido
// (acceptSlack). Antes da correção, a reserva da seguinte tomava o close: virava um registro do probe da primeira
// com 0 requisição, com o conn_id da seguinte, e a seguinte ganhava outro ID.
func TestQUICEventOnlyLateCloseAfterNextAccept(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	first, _, _ := in.flows.connID(protoUDP, quicClient, quicMirror, base, base)
	processAt(t, in, 100, h3Requests(t, dcidA, 0, probeA)...)
	processAt(t, in, 2_500)
	second, reserved, _ := in.flows.connID(protoUDP, quicClient, quicMirror, base+3_950e6, base+3_950e6)
	if !reserved || second == first {
		t.Fatalf("accept of a new connection got %s (reserved %v), first %s", second, reserved, first)
	}
	processAt(t, in, 3_960, h3CloseEv(t, dcidA, 3_800, probeA))
	processAt(t, in, 4_000, h3Requests(t, dcidB, 3_900, probeB)...)
	processAt(t, in, 6_500)
	processAt(t, in, 40_000)
	got := wantProbes(t, db, []int{5, 4}, probeA, probeB)
	if got[0].id != first || got[1].id != second || got[0].requests != 3 || got[1].requests != 3 {
		t.Fatalf("%+v want ids %s, %s", got, first, second)
	}
	if r := recordOf(t, in, first); r.Close.How != "quic_close" {
		t.Fatalf("first must get its own close: %+v", r.Close)
	}
}
