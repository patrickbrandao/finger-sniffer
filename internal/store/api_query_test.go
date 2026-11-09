package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"github.com/oklog/ulid/v2"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

const probeID = "t1a2b3c4"

// fixedIDs gera conn_ids determinísticos para os exemplos.
func fixedIDs() func(int64) string {
	n := uint64(0)
	return func(ts int64) string {
		n++
		var e [10]byte
		e[9] = byte(n)
		return ulid.MustNew(ulid.Timestamp(time.Unix(0, ts)), bytes.NewReader(e[:])).String()
	}
}

type apiFixture struct {
	in             *Ingestor
	srv            *httptest.Server
	closed, opened string
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	in, db := newTestIngestor(t, nil)
	in.flows.newID = fixedIDs()
	other := netip.MustParseAddrPort("192.0.2.20:50000")
	// Conexão encerrada: TLS + HTTP/1.1 com probe (eventos sintéticos no formato dos produtores).
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, probeID, tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 33, "", handshakePayload()),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, probeID, http1Payload(0, "HTTP/1.1")))
	run(t, in, 5000, batch(other, mirror, protoTCP, fullTCP[:4]), batch(client, mirror, protoTCP, []pkt{{6000, true, tcpRST, 0}}))

	var closed, opened string
	_ = db.QueryRow("SELECT conn_id FROM connections WHERE ended_ns IS NOT NULL").Scan(&closed)
	_ = db.QueryRow("SELECT conn_id FROM connections WHERE ended_ns IS NULL").Scan(&opened)
	if _, err := db.Exec("UPDATE connections SET probe_id = ?, record_json = json_set(record_json, '$.probe_id', ?) WHERE conn_id = ?", probeID, probeID, closed); err != nil {
		t.Fatal(err)
	}
	dns := `{"ts":"2026-11-07T11:59:59.900000000Z","probe_id":"t1a2b3c4","resolver":{"ip":"198.51.100.53","port":53124},
		"proto":"udp","conn_id":null,"id":4242,"opcode":0,"flags":{"rd":false,"cd":false,"ad":false},
		"qname":"T1a2B3c4.dns-monitor.tmsoft.com.br.","qtype":"A","qclass":"IN",
		"edns":{"version":0,"udp_size":1232,"do":false,"cookie_hex":null,"ecs":{"family":1,"source_prefix":24,"scope_prefix":0,"address":"200.1.2.0"},"padding_len":null,"options":[]},
		"response":{"rcode":"NOERROR","truncated":false,"answers":[{"name":"T1a2B3c4.dns-monitor.tmsoft.com.br.","type":"A","ttl":5,"data":"172.233.24.85"}]},
		"rate_limited":false,"raw_b64":"EJIAAAABAAAAAAAB"}`
	var compact bytes.Buffer
	_ = json.Compact(&compact, []byte(dns))
	if _, err := db.Exec(`INSERT INTO dns_queries (ts_ns, probe_id, resolver_ip, resolver_port, proto, qname, qtype, record_json)
		VALUES (?, ?, '198.51.100.53', 53124, 'udp', 'T1a2B3c4.dns-monitor.tmsoft.com.br.', 'A', ?)`, base-100e6, probeID, compact.String()); err != nil {
		t.Fatal(err)
	}

	q := NewQueries(db, in.flows.live, 65535)
	q.pollEvery = 20 * time.Millisecond
	api := &API{OpenAPI: []byte("x"), Health: func(context.Context, time.Time) Health { return Health{} }, Now: time.Now, Q: q, W: db}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &apiFixture{in: in, srv: srv, closed: closed, opened: opened}
}

func (f *apiFixture) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(f.srv.URL + path) //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPIConnectionsList(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, "/api/v1/connections")
	var list []summaryJSON
	if code != 200 || json.Unmarshal([]byte(body), &list) != nil || len(list) != 2 || list[0].ConnID != f.opened {
		t.Fatalf("%d %s", code, body)
	}
	for q, want := range map[string]int{
		"?src_ip=192.0.2.10": 1, "?dst_port=7700": 2, "?dst_port=80": 0, "?probe=" + probeID: 1, "?limit=1": 1,
		"?since=2026-11-07T12:00:01Z": 0, "?until=2026-11-07T12:00:01Z": 2,
	} {
		code, body := f.get(t, "/api/v1/connections"+q)
		_ = json.Unmarshal([]byte(body), &list)
		if code != 200 || len(list) != want {
			t.Errorf("%s: %d items (want %d) %s", q, len(list), want, body)
		}
	}
	for _, q := range []string{"?src_ip=x", "?dst_port=70000", "?since=yesterday", "?probe=BAD", "?limit=0", "?limit=1001"} {
		if code, body := f.get(t, "/api/v1/connections"+q); code != 400 || !strings.Contains(body, `"error"`) {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
}

func TestAPIConnectionGet(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, "/api/v1/connections/"+f.closed)
	var r connectionJSON
	if code != 200 || json.Unmarshal([]byte(body), &r) != nil || r.Ended == nil || r.Close.How != "fin" || *r.ProbeID != probeID {
		t.Fatalf("%d %s", code, body)
	}
	// Conexão aberta: registro ao vivo, com os dados que já chegaram.
	code, body = f.get(t, "/api/v1/connections/"+f.opened)
	if code != 200 || json.Unmarshal([]byte(body), &r) != nil || r.Ended != nil || r.Times.Established == nil || r.Totals.In.AppBytes != 100 {
		t.Fatalf("live: %d %s", code, body)
	}
	if code, _ := f.get(t, "/api/v1/connections/01JC0X3K8V2T7Q9N4M6P1R5S8W"); code != 404 {
		t.Fatalf("unknown: %d", code)
	}
	if code, _ := f.get(t, "/api/v1/connections/nope"); code != 400 {
		t.Fatalf("invalid: %d", code)
	}
}

func TestAPIPcap(t *testing.T) {
	f := newAPIFixture(t)
	for id, want := range map[string]int{f.closed: len(fullTCP), f.opened: 4} {
		resp, err := http.Get(f.srv.URL + "/api/v1/connections/" + id + "/pcap") //nolint:noctx // teste
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/vnd.tcpdump.pcap" {
			t.Fatalf("%d %v", resp.StatusCode, resp.Header)
		}
		r, err := pcapgo.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for {
			if _, _, err := r.ReadPacketData(); err != nil {
				break
			}
			n++
		}
		if n != want {
			t.Fatalf("%s: %d packets, want %d", id, n, want)
		}
	}
	if code, _ := f.get(t, "/api/v1/connections/01JC0X3K8V2T7Q9N4M6P1R5S8W/pcap"); code != 404 {
		t.Fatal("unknown pcap must be 404")
	}
	if code, _ := f.get(t, "/api/v1/connections/x/pcap"); code != 400 {
		t.Fatal("invalid id must be 400")
	}
}

func TestAPIRaw(t *testing.T) {
	f := newAPIFixture(t)
	if code, _ := f.get(t, "/api/v1/connections/"+f.closed+"/raw?dir=in"); code != 404 {
		t.Fatal("no raw bytes yet: 404")
	}
	if code, _ := f.get(t, "/api/v1/connections/"+f.closed+"/raw?dir=up"); code != 400 {
		t.Fatal("bad dir: 400")
	}
	if code, _ := f.get(t, "/api/v1/connections/x/raw?dir=in"); code != 400 {
		t.Fatal("bad id: 400")
	}
	if _, err := f.in.db.Exec("INSERT INTO raw_streams (conn_id, dir, offset, data) VALUES (?, 1, 0, ?), (?, 1, 9, ?)",
		f.closed, []byte("HTTP/1.1 "), f.closed, []byte("200 OK")); err != nil {
		t.Fatal(err)
	}
	if code, body := f.get(t, "/api/v1/connections/"+f.closed+"/raw?dir=out"); code != 200 || body != "HTTP/1.1 200 OK" {
		t.Fatalf("%d %q", code, body)
	}
}

func TestAPIPacketsAndDNS(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, "/api/v1/packets?src_ip=192.0.2.10")
	var pk []map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &pk) != nil || len(pk) != 1 || pk[0]["frame_b64"] == "" || pk[0]["tcp_flags"] != "R" {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := f.get(t, "/api/v1/packets?since=2026-11-07T13:00:00Z"); code != 200 || body != "[]\n" {
		t.Fatalf("%d %q", code, body)
	}
	code, body = f.get(t, "/api/v1/dns?probe="+probeID)
	if code != 200 || !strings.Contains(body, "T1a2B3c4.dns-monitor") {
		t.Fatalf("%d %s", code, body)
	}
	for _, p := range []string{"/api/v1/packets?limit=x", "/api/v1/dns?probe=X"} {
		if code, _ := f.get(t, p); code != 400 {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestAPIProbe(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, "/api/v1/probes/"+probeID)
	var p probeJSON
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || !p.AllClosed || len(p.Connections) != 1 || len(p.DNS) != 1 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := f.get(t, "/api/v1/probes/zzzzzzzz"); code != 404 {
		t.Fatal("unknown probe: 404")
	}
	for _, q := range []string{"/api/v1/probes/BAD", "/api/v1/probes/" + probeID + "?wait=10", "/api/v1/probes/" + probeID + "?wait=x"} {
		if code, _ := f.get(t, q); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
}

func TestAPIProbeWait(t *testing.T) {
	f := newAPIFixture(t)
	if _, err := f.in.db.Exec("UPDATE connections SET probe_id = ? WHERE conn_id = ?", probeID, f.opened); err != nil {
		t.Fatal(err)
	}
	// Sem fechar: espera o prazo e volta com all_closed=false.
	start := time.Now()
	code, body := f.get(t, "/api/v1/probes/"+probeID+"?wait=300ms")
	var p probeJSON
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || p.AllClosed || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("%d %v %s", code, time.Since(start), body)
	}
	// Fechando no meio da espera: volta assim que a última fecha.
	other := netip.MustParseAddrPort("192.0.2.20:50000")
	go func() {
		time.Sleep(150 * time.Millisecond)
		run(t, f.in, 9000, batch(other, mirror, protoTCP, fullTCP[4:]))
	}()
	start = time.Now()
	code, body = f.get(t, "/api/v1/probes/"+probeID+"?wait=10s")
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil || !p.AllClosed || time.Since(start) > 3*time.Second {
		t.Fatalf("%d %v %s", code, time.Since(start), body)
	}
}

func TestAPIDeleteProbe(t *testing.T) {
	f := newAPIFixture(t)
	del := func() int {
		req, _ := http.NewRequest(http.MethodDelete, f.srv.URL+"/api/v1/probes/"+probeID, nil) //nolint:noctx // teste
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := del(); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c := del(); c != 404 {
		t.Fatalf("second delete: %d", c)
	}
	if code, _ := f.get(t, "/api/v1/connections/"+f.closed); code != 404 {
		t.Fatal("connection must be gone")
	}
	req, _ := http.NewRequest(http.MethodDelete, f.srv.URL+"/api/v1/probes/BAD", nil) //nolint:noctx // teste
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatal("invalid probe: 400")
	}
	_ = resp.Body.Close()
}

// TestAPIExamples grava/confere os exemplos do contrato (validados pelo Redocly contra os schemas no verify).
func TestAPIExamples(t *testing.T) {
	f := newAPIFixture(t)
	examples := []struct{ file, path, summary string }{
		{"connections-list-example.json", "/api/v1/connections", "Uma conexão aberta e uma encerrada"},
		{"connection-example.json", "/api/v1/connections/" + f.closed, "Conexão tls/http1.1 encerrada pelo cliente"},
		{"packets-example.json", "/api/v1/packets", "RST sem conexão"},
		{"dns-list-example.json", "/api/v1/dns?probe=" + probeID, "Consulta A com ECS"},
		{"probe-example.json", "/api/v1/probes/" + probeID, "Probe com uma conexão e uma consulta DNS"},
	}
	for _, ex := range examples {
		code, body := f.get(t, ex.path)
		if code != 200 {
			t.Fatalf("%s: %d", ex.path, code)
		}
		var v any
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		got, _ := json.MarshalIndent(map[string]any{"summary": ex.summary, "value": v}, "", "  ")
		got = append(got, '\n')
		file := "../../cmd/finger-sniffer-store/testdata/" + ex.file
		if *update {
			if err := os.WriteFile(file, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%v (rode com -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s diverge de %s; rode go test ./internal/store -run TestAPIExamples -update", ex.path, ex.file)
		}
	}
}

func TestParseListFilterDefaults(t *testing.T) {
	f, err := ParseListFilter(func(string) string { return "" })
	if err != nil || f.Limit != 100 || f.DstPort != -1 {
		t.Fatalf("%+v %v", f, err)
	}
	if !ValidConnID("01JC0X3K8V2T7Q9N4M6P1R5S8W") || ValidConnID("01jc0x3k8v2t7q9n4m6p1r5s8w") {
		t.Fatal("ulid validation")
	}
	_ = fmt.Sprint(badRequest{"x"}.Error())
}
