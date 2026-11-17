package bot

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// heartbeatMessage monta um fs.v1.svc.heartbeat do serviço com o status.
func heartbeatMessage(t testing.TB, svc, status string) []byte {
	t.Helper()
	env, err := event.New(svc, "v0.4.0", time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), nil, event.Heartbeat{
		Status: status, Commit: "abc", StartedAt: "2026-11-16T11:00:00.000000000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestStoreFeedSilent: critério 3 da task 283 — relógio falso; com o store ok e nenhum fs.v1.store.connection por
// mais de 60 s o health mostra `store feed silent`; uma mensagem limpa; store sem heartbeat (down), degraded ou
// nunca visto não dá falso positivo; heartbeat de outro serviço não conta; o store que volta tem 60 s de novo.
func TestStoreFeedSilent(t *testing.T) {
	db, path := testDB(t)
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	s := New(testConfig(path), Deps{DB: db, Now: clock.Now})
	silent := func() bool {
		_, reasons := s.Status()
		return slices.Contains(reasons, "store feed silent")
	}
	// passa d mandando o heartbeat do serviço a cada 5 s ("" = nenhum heartbeat).
	run := func(d time.Duration, svc, status string) {
		for step := 5 * time.Second; d > 0; d -= step {
			clock.Advance(step)
			if svc != "" {
				s.store.heartbeat(heartbeatMessage(t, svc, status), clock.Now())
			}
		}
	}
	run(2*time.Minute, "", "")
	if silent() {
		t.Fatal("store nunca visto deu silêncio")
	}
	run(2*time.Minute, event.ServiceWeb, event.StatusOK)
	if silent() {
		t.Fatal("heartbeat do web contou como o do store")
	}
	run(55*time.Second, event.ServiceStore, event.StatusOK)
	if silent() {
		t.Fatal("silêncio antes de 60 s")
	}
	run(15*time.Second, event.ServiceStore, event.StatusOK)
	if !silent() {
		t.Fatal("store ok há 65 s sem mensagem sem `store feed silent`")
	}
	if st, _ := s.Status(); st != event.StatusDegraded {
		t.Fatalf("status %s", st)
	}
	if err := s.feed.Handle(storeMessage("opened", testStoreConnID, "203.0.113.9", 40000)); err != nil {
		t.Fatal(err)
	}
	if silent() {
		t.Fatal("mensagem não limpou o silêncio")
	}
	run(65*time.Second, event.ServiceStore, event.StatusOK)
	if !silent() {
		t.Fatal("silêncio depois da última mensagem")
	}
	// Store down: sem heartbeat por mais de 15 s.
	clock.Advance(16 * time.Second)
	if silent() {
		t.Fatal("falso positivo com o store down")
	}
	run(5*time.Minute, "", "")
	if silent() {
		t.Fatal("falso positivo com o store down por minutos")
	}
	run(2*time.Minute, event.ServiceStore, event.StatusDegraded)
	if silent() {
		t.Fatal("falso positivo com o store degraded")
	}
	// Store de volta ok: conta 60 s a partir da volta, não da última mensagem.
	run(30*time.Second, event.ServiceStore, event.StatusOK)
	if silent() {
		t.Fatal("silêncio logo depois de o store voltar")
	}
	run(40*time.Second, event.ServiceStore, event.StatusOK)
	if !silent() {
		t.Fatal("silêncio 65 s depois de o store voltar ok")
	}
	s.store.heartbeat([]byte(`{"lixo":1}`), clock.Now())
	if !silent() {
		t.Fatal("mensagem inválida mudou o estado")
	}
}
