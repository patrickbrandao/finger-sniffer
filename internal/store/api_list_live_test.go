package store

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestAPIConnectionsListOpenRequests: uma conexão aberta com 3 requisições HTTP vem com requests 3 na lista, como
// em GET /connections/{id}; a encerrada continua com o valor do banco (task 176).
func TestAPIConnectionsListOpenRequests(t *testing.T) {
	f := newAPIFixture(t)
	other := netip.MustParseAddrPort("192.0.2.20:50000")
	for i := range 3 {
		run(t, f.in, 5000, appMsg(t, event.SubjectWebHTTP1Request, "tcp", other, mirror, 50+i, "", http1Payload(i, "HTTP/1.1")))
	}
	if n := count(t, f.in.db, "SELECT count(*) FROM connections WHERE conn_id = ? AND ended_ns IS NULL", f.opened); n != 1 {
		t.Fatal("a conexão devia continuar aberta")
	}
	check := func(q *Queries) {
		t.Helper()
		list, err := q.Connections(t.Context(), ListFilter{DstPort: -1, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]summaryJSON{}
		for _, s := range list {
			got[s.ConnID] = s
		}
		if len(list) != 2 || list[0].ConnID != f.opened || got[f.opened].Requests != 3 || got[f.opened].Ended != nil ||
			got[f.closed].Requests != 1 {
			t.Fatalf("%+v", list)
		}
	}
	check(NewQueries(f.in.db, f.in.flows.live, 65535)) // pelo registro ao vivo (live)
	check(NewQueries(f.in.db, f.in.flows.live, 65535).WithOpenSummary(f.in.flows.openSummary))
	// a mesma contagem em GET /connections/{id} e na rota da lista
	_, body := f.get(t, "/api/v1/connections/"+f.opened)
	var r connectionJSON
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.Requests != 3 {
		t.Fatalf("%v %s", err, body)
	}
	_, body = f.get(t, "/api/v1/connections?src_ip=192.0.2.20")
	var list []summaryJSON
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list) != 1 || list[0].Requests != 3 {
		t.Fatalf("%v %s", err, body)
	}
}

// TestAPIPacketsSrcIPIsClient: src_ip de /packets é o IP do cliente (origem com dir=in, destino com dir=out); o IP
// do espelho não lista as saídas para todos os clientes; IPv4 mapeado em IPv6 vale o IPv4 (task 177).
func TestAPIPacketsSrcIPIsClient(t *testing.T) {
	f := newAPIFixture(t)
	ins := func(ts int64, dir int, src, dst string) {
		t.Helper()
		if _, err := f.in.db.Exec(`INSERT INTO stray_packets (ts_ns, dir, l4, src_ip, dst_ip, record_json, frame)
			VALUES (?, ?, 'tcp', ?, ?, '{}', x'00')`, ts, dir, src, dst); err != nil {
			t.Fatal(err)
		}
	}
	// a fixture já tem um RST de entrada de 192.0.2.10; mais um de saída para ele e um de entrada de outro cliente
	ins(base+1, 1, "170.247.40.86", "192.0.2.10")
	ins(base+2, 0, "198.51.100.7", "170.247.40.86")
	n := func(path string) int {
		t.Helper()
		code, body := f.get(t, path)
		var pk []json.RawMessage
		if code != 200 || json.Unmarshal([]byte(body), &pk) != nil {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		return len(pk)
	}
	for path, want := range map[string]int{
		"/api/v1/packets?src_ip=192.0.2.10":                            2,
		"/api/v1/packets?src_ip=::ffff:192.0.2.10":                     2,
		"/api/v1/packets?src_ip=198.51.100.7":                          1,
		"/api/v1/packets?src_ip=170.247.40.86":                         0,
		"/api/v1/packets":                                              3,
		"/api/v1/connections?src_ip=::ffff:192.0.2.10":                 1,
		"/api/v1/connections?src_ip=192.0.2.10":                        1,
		"/api/v1/packets?src_ip=192.0.2.10&until=2026-01-01T00:00:00Z": 0,
	} {
		if got := n(path); got != want {
			t.Errorf("%s: %d, quer %d", path, got, want)
		}
	}
}
