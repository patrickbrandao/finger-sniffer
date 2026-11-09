package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// appMsg monta um evento de aplicação sintético (envelope v1) da 5-tupla cli → srv em base+ms.
func appMsg(t *testing.T, subject string, l4 string, cli, srv netip.AddrPort, ms int, probeID string, payload any) fakeMsg {
	t.Helper()
	svc := event.ServiceWeb
	switch subject {
	case event.SubjectDNSQuery:
		svc = event.ServiceDNS
	case event.SubjectRawRead, event.SubjectRawSession:
		svc = event.ServiceRaw
	}
	flow := &event.Flow{L4: l4, SrcIP: cli.Addr().String(), SrcPort: int(cli.Port()), DstIP: srv.Addr().String(), DstPort: int(srv.Port())}
	env, err := event.New(svc, "test", time.Unix(0, base+int64(ms)*1e6), flow, payload)
	if err != nil {
		t.Fatal(err)
	}
	if probeID != "" {
		env.ProbeID = &probeID
	}
	data, _ := json.Marshal(env)
	return fakeMsg{subject: subject, data: data}
}

// process roda um lote sem encerrar conexões, com o relógio do store em base+atMs.
func processAt(t *testing.T, in *Ingestor, atMs int, msgs ...fakeMsg) {
	t.Helper()
	in.now = func() time.Time { return time.Unix(0, base+int64(atMs)*1e6) }
	src := make([]msgSource, len(msgs))
	for i, m := range msgs {
		src[i] = m
	}
	if err := in.process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
}

func recordOf(t *testing.T, in *Ingestor, id string) connectionJSON {
	t.Helper()
	raw, err := NewQueries(in.db, in.flows.live, 65535).Connection(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var r connectionJSON
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

var hello = map[string]any{"sni": "t1a2b3c4.dns-monitor.tmsoft.com.br"}

func TestParseAppEvent(t *testing.T) {
	m := appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 5, "t1a2b3c4", hello)
	ev, err := parseAppEvent(m.subject, m.data)
	if err != nil || ev.l4 != protoTCP || ev.client != client || ev.server != mirror || ev.ts != base+5e6 || *ev.env.ProbeID != "t1a2b3c4" {
		t.Fatalf("%+v %v", ev, err)
	}
	for _, bad := range []string{
		`{`, `{"schema_version":2}`,
		`{"schema_version":1,"service":"web","service_version":"v","ts":"x"}`,
		`{"schema_version":1,"service":"web","service_version":"v","ts":"2026-11-07T12:00:00Z","flow":{"l4":"sctp"}}`,
		`{"schema_version":1,"service":"web","service_version":"v","ts":"2026-11-07T12:00:00Z","flow":{"l4":"tcp","src_ip":"x"}}`,
	} {
		if _, err := parseAppEvent(event.SubjectWebTLSClientHello, []byte(bad)); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
	for s, want := range map[string]bool{
		event.SubjectWebHTTP1Request: true, event.SubjectRawSession: true, event.SubjectDNSQuery: true,
		event.SubjectHeartbeat: false, event.SubjectCapturePacket: false, event.SubjectDNSACMESet: false,
	} {
		if isAppSubject(s) != want {
			t.Errorf("isAppSubject(%s) != %v", s, want)
		}
	}
}

// TestAppEventsIgnoredWhenMalformed: evento inválido não derruba o lote.
func TestAppEventsIgnoredWhenMalformed(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	processAt(t, in, 0, fakeMsg{subject: event.SubjectWebHTTP1Request, data: []byte("{")}, batch(client, mirror, protoTCP, fullTCP[:3]))
	if count(t, db, "SELECT count(*) FROM connections") != 1 || in.metrics.Get("store_bad_events_total") != 1 {
		t.Fatal("bad event must be skipped")
	}
}
