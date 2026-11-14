package web

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
)

// TestH3SettingsTruncatedEvent: SETTINGS do cliente com 300 pares → h3_settings com 256 e
// h3_settings_truncated no http3.connection (task 171).
func TestH3SettingsTruncatedEvent(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	pc := startH3(t, h)
	c := dialRawH3(t, pc)
	u, err := c.qc.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	var p []byte
	for i := range 300 {
		p = quicparse.AppendVarint(p, uint64(0x21+31*i)) // GREASE: ids distintos sem significado
		p = quicparse.AppendVarint(p, uint64(i))
	}
	if _, err := u.Write(quicparse.AppendH3Frame([]byte{quicparse.StreamTypeControl}, quicparse.H3FrameSettings, p)); err != nil {
		t.Fatal(err)
	}
	c.readResponse(c.request("/p/" + testProbe + "/"))
	time.Sleep(50 * time.Millisecond)
	_ = c.qc.CloseWithError(h3NoError, "")
	settings := finalSettings(t, h, c.port())
	if len(settings) != quicparse.DefaultMaxSettings {
		t.Fatalf("%d pares", len(settings))
	}
	conns := h.events.find(t, event.SubjectWebHTTP3Connection, c.port())
	last := conns[len(conns)-1]
	if last.Payload["h3_settings_truncated"] != true {
		t.Fatalf("h3_settings_truncated %v", last.Payload["h3_settings_truncated"])
	}
	if _, ok := conns[0].Payload["h3_settings_truncated"]; ok {
		t.Fatal("marca no primeiro evento, antes do SETTINGS")
	}
	checkContract(t, contractBlocks(t), last)
}

// TestFitH3ConnTruncationMarks: ao encolher transport_params e h3_settings para caber no evento, o web
// liga as marcas; evento pequeno sai sem elas (ausente = false).
func TestFitH3ConnTruncationMarks(t *testing.T) {
	s := NewServer(testConfig(t.TempDir()), Deps{})
	flow := event.Flow{L4: "udp", SrcIP: "192.0.2.1", SrcPort: 1, DstIP: "192.0.2.2", DstPort: 443}
	small := &quicparse.Info{
		InitialFrames: []string{}, TransportParams: []quicparse.TransportParam{{ID: 1, Value: []byte{1}}},
		H3Settings: [][2]uint64{{1, 0}}, Requests: []quicparse.HTTP3Request{},
	}
	var m map[string]any
	if err := json.Unmarshal(s.fitH3Conn(&flow, "", small), &m); err != nil {
		t.Fatal(err)
	}
	pl, _ := m["payload"].(map[string]any)
	if pl == nil {
		t.Fatalf("evento sem payload: %v", m)
	}
	if _, ok := pl["transport_params_truncated"]; ok {
		t.Fatal("transport_params_truncated num evento pequeno")
	}
	if _, ok := pl["h3_settings_truncated"]; ok {
		t.Fatal("h3_settings_truncated num evento pequeno")
	}

	big := &quicparse.Info{InitialFrames: []string{}, Requests: []quicparse.HTTP3Request{}}
	for i := range quicparse.MaxTransportParams {
		big.TransportParams = append(big.TransportParams, quicparse.TransportParam{ID: uint64(i), Value: make([]byte, 1000)})
	}
	for i := range quicparse.DefaultMaxSettings {
		big.H3Settings = append(big.H3Settings, [2]uint64{uint64(i), 1})
	}
	data := s.fitH3Conn(&flow, "", big)
	if data == nil || len(data) > event.MaxEventBytes {
		t.Fatalf("evento %d bytes", len(data))
	}
	if !big.TransportParamsTruncated || !big.H3SettingsTruncated || len(big.TransportParams) >= quicparse.MaxTransportParams {
		t.Fatalf("marcas tp=%v settings=%v, %d params", big.TransportParamsTruncated, big.H3SettingsTruncated,
			len(big.TransportParams))
	}
}
