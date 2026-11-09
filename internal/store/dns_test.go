package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

var (
	resolver = netip.MustParseAddrPort("198.51.100.53:33333")
	dnsSrv   = netip.MustParseAddrPort("172.233.24.85:53")
)

func dnsPayload(proto string) map[string]any {
	return map[string]any{
		"ts": "2026-11-07T12:00:00.000000000Z", "probe_id": "t1a2b3c4", "proto": proto,
		"resolver": map[string]any{"ip": resolver.Addr().String(), "port": resolver.Port()},
		"qname":    "T1a2B3c4.dns-monitor.tmsoft.com.br.", "qtype": "A", "qclass": "IN", "id": 7,
	}
}

func TestDNSQueryUDP(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 0, appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, 0, "t1a2b3c4", dnsPayload("udp")))
	var rec string
	var connID *string
	if err := db.QueryRow("SELECT record_json, conn_id FROM dns_queries WHERE probe_id = 't1a2b3c4' AND proto = 'udp' AND qtype = 'A'").Scan(&rec, &connID); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(rec), &m)
	if connID != nil || m["conn_id"] != nil || m["qname"] != "T1a2B3c4.dns-monitor.tmsoft.com.br." {
		t.Fatalf("%s", rec)
	}
	if count(t, db, "SELECT count(*) FROM probes WHERE probe_id = 't1a2b3c4'") != 1 || count(t, db, "SELECT count(*) FROM app_events") != 0 {
		t.Fatal("probe row expected, no app event for UDP")
	}
	p, err := NewQueries(db, in.flows.live, 65535).Probe(context.Background(), "t1a2b3c4", ProbeWait{})
	if err != nil || len(p.DNS) != 1 || len(p.Connections) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestDNSQueryTCP(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	dnsTCP := make([]pkt, len(fullTCP))
	copy(dnsTCP, fullTCP)
	run(t, in, 5000, batch(resolver, dnsSrv, protoTCP, dnsTCP),
		appMsg(t, event.SubjectDNSQuery, "tcp", resolver, dnsSrv, 30, "t1a2b3c4", dnsPayload("tcp")))
	id, r := onlyConn(t, db)
	var connID string
	var rec string
	if err := db.QueryRow("SELECT conn_id, record_json FROM dns_queries WHERE proto = 'tcp'").Scan(&connID, &rec); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(rec), &m)
	if connID != id || m["conn_id"] != id || r.ProbeID == nil {
		t.Fatalf("conn_id %s (want %s) %s", connID, id, rec)
	}
	p, err := NewQueries(db, in.flows.live, 65535).Probe(context.Background(), "t1a2b3c4", ProbeWait{})
	if err != nil || len(p.DNS) != 1 || len(p.Connections) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
}
