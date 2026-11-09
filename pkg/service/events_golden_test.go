package service

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/version"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

var update = flag.Bool("update", false, "regrava os exemplos em testdata/events")

// TestHeartbeatGolden: o heartbeat publicado pelo produtor (envelope + HeartbeatPayload com metrics) tem a forma
// de testdata/events/svc.heartbeat.json, referenciado pelo asyncapi. -update o regrava.
func TestHeartbeatGolden(t *testing.T) {
	oldVersion, oldCommit := version.Version, version.Commit
	t.Cleanup(func() { version.Version, version.Commit = oldVersion, oldCommit })
	// Valores fixos: o golden não muda a cada commit.
	version.Version, version.Commit = "0.1.0", "768c24f"

	c := &fakeConn{connected: true}
	m := NewMetrics()
	s := &Service{
		Name: event.ServiceWeb, Metrics: m, Producer: NewProducer(c, time.Minute, 1<<20, m),
		started: time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC),
	}
	s.SetStatus(func() (string, []string) { return event.StatusDegraded, []string{"nats reconnecting"} })
	for range 3 {
		s.Producer.Publish(msg("x"))
	}
	hb, err := s.HeartbeatMessage(time.Date(2026, 11, 9, 12, 0, 0, 123456789, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s.Producer.Publish(hb)
	data := []byte(c.sent[len(c.sent)-1])
	env, err := event.Decode(data)
	if err != nil || env.Service != event.ServiceWeb {
		t.Fatalf("%+v %v", env, err)
	}
	var p event.Heartbeat
	if err := json.Unmarshal(env.Payload, &p); err != nil || p.Metrics[MetricPublished] != 3 || len(p.Reasons) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	checkEventGolden(t, "svc.heartbeat.json", data)
}

// TestConnIDRequestGolden: o pedido que RequestConnID publica tem a forma de
// testdata/events/store.conn_id.request.json (o store o usa como entrada no golden da resposta). -update o regrava.
func TestConnIDRequestGolden(t *testing.T) {
	f := &fakeRequester{reply: []byte(`{"conn_id":"01JC5Q8T0M3J9V7K2N4P6R8S0W","reserved":true}`)}
	flow := event.Flow{L4: "tcp", SrcIP: "203.0.113.7", SrcPort: 51000, DstIP: "198.51.100.1", DstPort: 443}
	if _, err := RequestConnID(context.Background(), f, flow, time.Date(2026, 11, 9, 12, 0, 0, 123456789, time.UTC)); err != nil {
		t.Fatal(err)
	}
	checkEventGolden(t, "store.conn_id.request.json", f.data)
}

// checkEventGolden compara a forma (chaves e aninhamento) de data com testdata/events/name, ou o regrava com -update.
func checkEventGolden(t *testing.T, name string, data []byte) {
	t.Helper()
	file := filepath.Join("testdata", "events", name)
	var got any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if *update {
		out, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil { //nolint:gosec // testdata versionado
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (rode go test -run %s -update)", err, t.Name())
	}
	var golden any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(jsonShape(golden))
	f, _ := json.Marshal(jsonShape(got))
	if !bytes.Equal(g, f) {
		t.Errorf("%s: shape changed (rode -update)\n golden %s\n now    %s", file, g, f)
	}
}

// jsonShape troca cada valor escalar por null e cada lista pelo seu primeiro item: sobra só a forma.
func jsonShape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			out[k] = jsonShape(vv)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{jsonShape(x[0])}
	default:
		return nil
	}
}
