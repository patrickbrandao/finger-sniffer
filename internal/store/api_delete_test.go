package store

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestAPIDeleteProbeOpenConnection: o DELETE leva também a conexão aberta do probe; ela some de todas as leituras
// na hora e o que ainda chega dela (pacotes, eventos, fechamento) é descartado sem erro e sem recriar a linha
// (task 150, ADR 0034 item 8).
func TestAPIDeleteProbeOpenConnection(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodDelete, f.srv.URL+"/api/v1/probes/"+probeID, nil) //nolint:noctx // teste
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if code, _ := f.get(t, "/api/v1/probes/"+probeID); code != 404 {
		t.Fatalf("probe: %d", code)
	}
	if code, body := f.get(t, "/api/v1/connections?probe="+probeID); code != 200 || body != "[]\n" && body != "[]" {
		t.Fatalf("connections?probe: %d %s", code, body)
	}
	for _, p := range []string{"/api/v1/connections/" + f.opened, "/api/v1/connections/" + f.opened + "/pcap"} {
		if code, _ := f.get(t, p); code != 404 {
			t.Fatalf("%s: %d", p, code)
		}
	}
	if !f.in.flows.isHidden(f.opened) {
		t.Fatal("open connection must be remembered by the ingest")
	}

	// O resto da conexão chega: pacotes, um evento de aplicação e o fechamento.
	other := netip.MustParseAddrPort("192.0.2.20:50000")
	run(t, f.in, 9000, batch(other, mirror, protoTCP, fullTCP[4:]),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", other, mirror, 1000, probeID, http1Payload(1, "HTTP/1.1")))
	for _, q := range []string{
		"SELECT count(*) FROM connections WHERE conn_id = ?", "SELECT count(*) FROM packets WHERE conn_id = ?",
		"SELECT count(*) FROM pcaps WHERE conn_id = ?", "SELECT count(*) FROM app_events WHERE conn_id = ?",
	} {
		if n := count(t, f.in.db, q, f.opened); n != 0 {
			t.Fatalf("%s: %d", q, n)
		}
	}
	if f.in.flows.isHidden(f.opened) || len(f.in.toFinalize) != 0 {
		t.Fatal("closed connection must leave the hidden set and the queue")
	}
	if code, _ := f.get(t, "/api/v1/probes/"+probeID); code != 404 {
		t.Fatalf("probe after close: %d", code)
	}
}

// TestDeleteProbeAtomic: falha no meio do DELETE desfaz tudo e não esconde a conexão aberta.
func TestDeleteProbeAtomic(t *testing.T) {
	f := newAPIFixture(t)
	db := f.in.db
	if _, err := db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_probe BEFORE DELETE ON probes BEGIN SELECT RAISE(ABORT, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	q := NewQueries(db, f.in.flows.live, 65535)
	q.SetHideOpen(f.in.flows.hide, f.in.flows.unhide)
	if _, err := db.Exec("INSERT OR IGNORE INTO probes (probe_id, first_seen, last_seen) VALUES (?, 0, 0)", probeID); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteProbe(context.Background(), db, probeID); err == nil {
		t.Fatal("want error")
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE probe_id = ?", probeID) != 2 || f.in.flows.isHidden(f.opened) {
		t.Fatal("failed delete must change nothing")
	}
}
