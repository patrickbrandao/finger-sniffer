package store

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Testes da task 433: o http3.connection de fim por ociosidade do web sai a ociosidade QUIC negociada depois do
// último pacote (30 s com o cliente quic-go), logo além de lateSlack do fim gravado; com o DCID do registro ele é
// dessa conexão, mesmo com uma conexão nova na 5-tupla aberta pouco antes.

// h3ConnOf é o http3.connection com o dcid_hex do payload igual ao DCID do envelope, como o web publica.
func h3ConnOf(t testing.TB, dcid []byte, ms int, probe string, cl *event.HTTP3Close) fakeMsg {
	info := h3Conn("h3", true, cl)
	info.DCIDHex = hex.EncodeToString(dcid)
	return h3Ev(t, event.SubjectWebHTTP3Connection, quicClient, dcid, ms, probe, info)
}

// h3RequestsOf são as 3 requisições do loadgen (h3Requests) com o dcid_hex do payload igual ao do envelope.
func h3RequestsOf(t testing.TB, dcid []byte, ms int, probe string) []fakeMsg {
	reqs := h3Requests(t, dcid, ms, probe)
	reqs[0] = h3ConnOf(t, dcid, ms, probe, nil)
	return reqs
}

// h3IdleCloseEv é o http3.connection final por ociosidade (o web fecha, by server) em ms.
func h3IdleCloseEv(t testing.TB, dcid []byte, ms int, probe string) fakeMsg {
	return h3ConnOf(t, dcid, ms, probe, &event.HTTP3Close{By: "server", How: event.QUICCloseIdleTimeout})
}

// TestQUICIdleCloseBeyondLateSlack: caso do Mac da task 433. O CONNECTION_CLOSE da primeira se perdeu; a segunda
// (DCID novo, accept com conn_id reservado) abre na mesma porta e divide o fluxo, gravando a primeira com o fim no
// último pacote dela; o close por ociosidade da primeira chega 30 s + 1 ms depois desse fim. Antes da correção,
// virava um registro só de eventos com o probe da primeira e 0 requisição.
func TestQUICIdleCloseBeyondLateSlack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept bool // a segunda já fechou e o web pediu o conn_id de outra antes do close da primeira
	}{{"split by next initial", false}, {"next accept reserved", true}} {
		t.Run(tc.name, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			runAt(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3RequestsOf(t, dcidA, 30, probeA)...)...)
			closeB := h3ConnOf(t, dcidB, 33_050, probeB, &event.HTTP3Close{By: "client", How: event.QUICCloseApplication})
			msgsB := append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 29_950))}, h3RequestsOf(t, dcidB, 29_980, probeB)...)
			if tc.accept {
				closeB = h3ConnOf(t, dcidB, 29_995, probeB, &event.HTTP3Close{By: "client", How: event.QUICCloseApplication})
				msgsB = append(msgsB, closeB)
			}
			runAt(t, in, 30_000, msgsB...)
			if tc.accept {
				if _, reserved, _ := in.flows.connID(protoUDP, quicClient, quicMirror, base+30_010e6, base+30_010e6); !reserved {
					t.Fatal("accept of a third connection must reserve a conn_id")
				}
			}
			// Fim gravado da primeira: o último pacote dela (40 ms); o close sai 30 s + 1 ms depois.
			runAt(t, in, 30_100, h3IdleCloseEv(t, dcidA, 30_041, probeA))
			runAt(t, in, 33_000)
			if !tc.accept {
				runAt(t, in, 33_100, closeB)
			}
			runAt(t, in, 400_000)
			got := wantProbes(t, db, []int{5, 5}, probeA, probeB)
			if got[0].requests != 3 || got[1].requests != 3 {
				t.Fatalf("requests %+v", got)
			}
			if r := recordOf(t, in, got[0].id); r.Close.How != "timeout" {
				t.Fatalf("first connection must get its idle close: %+v", r.Close)
			}
			if r := recordOf(t, in, got[1].id); r.Close.How != "quic_close" {
				t.Fatalf("second connection must keep its own close: %+v", r.Close)
			}
		})
	}
}

// TestQUICLateEventSameDCIDBounded: a folga maior vale só até a ociosidade QUIC da tabela (FS_IDLE_DEFAULT + 30 s)
// e só para registro sem close h3; fora disso, o evento com o DCID do registro gravado não cai nele.
func TestQUICLateEventSameDCIDBounded(t *testing.T) {
	t.Run("beyond quic idle", func(t *testing.T) {
		in, db := newTestIngestor(t, func(c *IngestConfig) { c.QUICIdle = 60 * time.Second })
		runAt(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3RequestsOf(t, dcidA, 30, probeA)...)...)
		runAt(t, in, 30_000, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidB, 29_950))}, h3RequestsOf(t, dcidB, 29_980, probeB)...)...)
		runAt(t, in, 61_000, h3IdleCloseEv(t, dcidA, 60_041, probeA))
		runAt(t, in, 400_000)
		if n := count(t, db, "SELECT count(*) FROM connections"); n != 3 {
			t.Fatalf("event beyond the QUIC idle joined a stored record: %d connections", n)
		}
	})
	t.Run("record with h3 close", func(t *testing.T) {
		in, db := newTestIngestor(t, nil)
		runAt(t, in, 100, append([]fakeMsg{udpBatch(quicClient, quicMirror, quicHandshake(dcidA, 0))}, h3RequestsOf(t, dcidA, 30, probeA)...)...)
		runAt(t, in, 200, h3ConnOf(t, dcidA, 100, probeA, &event.HTTP3Close{By: "client", How: event.QUICCloseApplication}))
		runAt(t, in, 5_000)
		runAt(t, in, 40_100, h3RequestsOf(t, dcidA, 40_000, probeB)...)
		runAt(t, in, 400_000)
		wantProbes(t, db, []int{5, 4}, probeA, probeB)
	})
}
