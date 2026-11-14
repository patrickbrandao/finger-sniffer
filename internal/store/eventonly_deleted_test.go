package store

import (
	"context"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Evento para conexão só de eventos cuja linha saiu do banco (task 140, ADR 0034 item 7).

// eventOnlyWithProbe cria a conexão só de eventos (evento sem pacotes, pendingWait vencido) e devolve o conn_id.
func eventOnlyWithProbe(t *testing.T, in *Ingestor) string {
	t.Helper()
	processAt(t, in, 0, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 0, probeID, http1Payload(0, "HTTP/1.1")))
	processAt(t, in, 2100)
	id, _ := onlyConn(t, in.db)
	return id
}

func TestEventOnlyDeletedRecreated(t *testing.T) {
	cases := []struct {
		name   string
		remove func(t *testing.T, in *Ingestor)
		next   func(t *testing.T) fakeMsg
	}{
		{"delete probe, http1", deleteProbe, http1At(3000)},
		{"delete probe, stream bytes", deleteProbe, func(t *testing.T) fakeMsg { return chunk(t, 3000, event.DirectionIn, 0, []byte("abc"), false) }},
		{"size purge", func(t *testing.T, in *Ingestor) {
			t.Helper()
			// o teto de tamanho apaga a linha encerrada mais antiga, qualquer que seja a idade
			if _, err := NewRetention(in.db, 0, 0).RunOnce(context.Background(), time.Unix(0, base+2200e6)); err != nil {
				t.Fatal(err)
			}
		}, http1At(3000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			old := eventOnlyWithProbe(t, in)
			c.remove(t, in)
			if count(t, db, "SELECT count(*) FROM connections") != 0 {
				t.Fatal("row must be gone")
			}
			// Antes, o INSERT do evento violava a FK e o lote voltava por Nak em laço.
			processAt(t, in, 3000, c.next(t))
			for _, eo := range in.eventOnly {
				if eo.id == old {
					t.Fatal("deleted conn_id still in memory")
				}
			}
			processAt(t, in, 5200) // pendingWait vencido: nova conexão só de eventos
			id, _ := onlyConn(t, db)
			if id == old || count(t, db, "SELECT (SELECT count(*) FROM app_events WHERE conn_id = ?1) + (SELECT count(*) FROM raw_streams WHERE conn_id = ?1)", id) != 1 {
				t.Fatalf("connection not recreated: %s", id)
			}
		})
	}
}

func deleteProbe(t *testing.T, in *Ingestor) {
	t.Helper()
	if err := NewQueries(in.db, in.flows.live, 65535).DeleteProbe(context.Background(), in.db, probeID); err != nil {
		t.Fatal(err)
	}
}

func http1At(ms int) func(t *testing.T) fakeMsg {
	return func(t *testing.T) fakeMsg {
		t.Helper()
		return appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, ms, probeID, http1Payload(1, "HTTP/1.1"))
	}
}
