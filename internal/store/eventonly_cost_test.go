package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// feedEventOnlyWS cria uma conexão só de eventos (capture parado) e manda n frames WebSocket em lotes de 64,
// como o consumidor faz. Devolve o ingestor e o conn_id.
func feedEventOnlyWS(t *testing.T, n int) (*Ingestor, string) {
	t.Helper()
	in, db := newTestIngestor(t, nil)
	ctx := context.Background()
	first := appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 0, "", event.WebSocketFrame{
		Dir: "in", Opcode: 1, Fin: true, Masked: true, Length: 5,
		Upgrade: &event.WebSocketUpgrade{Over: "http1.1", Path: "/ws"},
	})
	in.now = func() time.Time { return time.Unix(0, base) }
	if err := in.process(ctx, []msgSource{first}); err != nil {
		t.Fatal(err)
	}
	in.now = func() time.Time { return time.Unix(0, base+2100e6) }
	if err := in.process(ctx, nil); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.QueryRow("SELECT conn_id FROM connections").Scan(&id); err != nil {
		t.Fatal(err)
	}
	var lote []msgSource
	for i := 1; i < n; i++ {
		lote = append(lote, appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 2100+i, "", event.WebSocketFrame{Dir: "out", Opcode: 1, Fin: true, Length: 5}))
		if len(lote) == 64 || i == n-1 {
			in.now = func() time.Time { return time.Unix(0, base+int64(2100+i)*1e6) }
			if err := in.process(ctx, lote); err != nil {
				t.Fatal(err)
			}
			lote = nil
		}
	}
	return in, id
}

// TestEventOnlyLinear: 1000 eventos numa conexão só de eventos não relêem app_events (estado incremental em
// memória) e o registro é reescrito uma vez por lote, não por evento.
func TestEventOnlyLinear(t *testing.T) {
	in, id := feedEventOnlyWS(t, 1000)
	if in.appReloads != 0 {
		t.Fatalf("app_events reread %d times; want 0 (incremental)", in.appReloads)
	}
	_, r := onlyConn(t, in.db)
	if r.ConnID != id || r.WebSocket == nil || len(r.WebSocket.Frames) != 1000 || r.WebSocket.Path != "/ws" {
		t.Fatalf("record %+v", r.WebSocket)
	}
	if *r.Ended != event.FormatTime(time.Unix(0, base+3099e6)) {
		t.Fatalf("ended %v", *r.Ended)
	}
	if count(t, in.db, "SELECT count(*) FROM app_events WHERE conn_id = ?", id) != 1000 {
		t.Fatal("app_events")
	}
}

// TestEventOnlyAfterFailedBatch: lote desfeito descarta o estado em memória; o reenvio não duplica eventos no
// registro (o estado é relido de app_events uma vez).
func TestEventOnlyAfterFailedBatch(t *testing.T) {
	in, id := feedEventOnlyWS(t, 10)
	in.discardBatchState() // como process faz quando a transação falha
	processAt(t, in, 3000, appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 2990, "", event.WebSocketFrame{Dir: "out", Opcode: 1, Fin: true, Length: 5}))
	processAt(t, in, 3001, appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 2991, "", event.WebSocketFrame{Dir: "out", Opcode: 1, Fin: true, Length: 5}))
	if in.appReloads != 1 {
		t.Fatalf("reloads %d, want 1", in.appReloads)
	}
	_, r := onlyConn(t, in.db)
	if r.ConnID != id || len(r.WebSocket.Frames) != 12 {
		t.Fatalf("frames %d", len(r.WebSocket.Frames))
	}
}

// TestProcessErrorDiscardsState: erro no lote (contexto cancelado) limpa o estado sujo.
func TestProcessErrorDiscardsState(t *testing.T) {
	in, _ := feedEventOnlyWS(t, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := in.process(ctx, []msgSource{appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 2200, "", event.WebSocketFrame{Dir: "out"})})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	for _, eo := range in.eventOnly {
		if eo.app != nil {
			t.Fatal("in-memory state must be discarded")
		}
	}
	if len(in.dirty) != 0 {
		t.Fatal("dirty must be empty")
	}
}

// TestDrainPendingOnShutdown: no desligamento os eventos ainda pendentes viram conexão só de eventos.
func TestDrainPendingOnShutdown(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 0, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 0, "t1a2b3c4", hello))
	if len(in.pending) != 1 || count(t, db, "SELECT count(*) FROM connections") != 0 {
		t.Fatal("event must wait")
	}
	in.drainPending()
	if len(in.pending) != 0 || len(in.pendingKeys) != 0 {
		t.Fatal("pending must be drained")
	}
	if _, r := onlyConn(t, db); r.ProbeID == nil || *r.ProbeID != "t1a2b3c4" {
		t.Fatalf("%+v", r)
	}
}
