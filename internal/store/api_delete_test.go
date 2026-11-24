package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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
	req, _ := http.NewRequest(http.MethodDelete, f.srv.URL+"/api/v1/probes/"+probeID, nil)
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
	// As linhas saem em lotes pelo laço de retenção (ADR 0068).
	drainDeleted(t, f.in.db)
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

// TestDeleteProbeMissingSkipsWriter: 200 goroutines em laço de DELETE de probes inexistentes não abrem nenhuma
// transação no escritor (task 317). A latência do ingest simulado só vai para o log: no Mac ela varia mais com a
// CPU tomada pelas goroutines do que com a disputa da conexão, e um teto relativo ficaria instável.
func TestDeleteProbeMissingSkipsWriter(t *testing.T) {
	db, path := testDB(t)
	ctx := context.Background()
	// Leitor separado do escritor, como no store (OpenReadDB com 4 conexões).
	rdb, err := OpenReadDB(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	q := NewQueries(rdb, nil, 65535)
	ingestP99 := func(load bool) time.Duration {
		stop := make(chan struct{})
		var wg sync.WaitGroup
		if load {
			for g := range 200 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; ; i++ {
						select {
						case <-stop:
							return
						default:
						}
						id := fmt.Sprintf("nope%04d%06d", g, i%1000000)
						if err := q.DeleteProbe(ctx, db, id); !errors.Is(err, ErrNotFound) {
							t.Errorf("delete %s: %v", id, err)
							return
						}
					}
				}()
			}
		}
		rec, pcap, ev := strings.Repeat("r", 3000), make([]byte, 8000), strings.Repeat("e", 600)
		var lats []time.Duration
		for i := range 300 {
			t0 := time.Now()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := insertConn(ctx, tx, fmt.Sprintf("in%v%06d", load, i), time.Now().UnixNano(), rec, pcap, ev, 1); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			lats = append(lats, time.Since(t0))
			time.Sleep(time.Millisecond)
		}
		close(stop)
		wg.Wait()
		sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
		return lats[len(lats)*99/100]
	}
	base := ingestP99(false)
	loaded := ingestP99(true)
	t.Logf("ingest p99: %v without, %v with 200 DELETE loops", base, loaded)
	if n := q.deleteTx.Load(); n != 0 {
		t.Fatalf("missing probes opened %d writer transactions", n)
	}
}

// TestDeleteProbeOneAtATime: DELETE simultâneos de probes existentes nunca seguram juntos o escritor (task 317).
func TestDeleteProbeOneAtATime(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	q := NewQueries(db, nil, 65535)
	const n = 20
	for i := range n {
		id := fmt.Sprintf("real%010d", i)
		if _, err := db.Exec("INSERT INTO probes (probe_id, first_seen, last_seen) VALUES (?, 0, 0)", id); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := q.DeleteProbe(ctx, db, fmt.Sprintf("real%010d", i)); err != nil {
				t.Errorf("delete %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if q.deleteTx.Load() != n || q.deleteMax.Load() != 1 {
		t.Fatalf("writer transactions %d, max simultaneous %d; want %d and 1", q.deleteTx.Load(), q.deleteMax.Load(), n)
	}
	if c := count(t, db, "SELECT count(*) FROM probes"); c != 0 {
		t.Fatalf("probes left: %d", c)
	}
}
