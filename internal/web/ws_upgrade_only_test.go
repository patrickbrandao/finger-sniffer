package web

import (
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/http2"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestWSUpgradeOnly (task 185): WebSocket aceito e fechado sem nenhum frame (HTTP/1 com o TCP fechado, h2
// com RST_STREAM) publica um websocket.frame com upgrade_only e o upgrade negociado; sessão com frames não
// ganha esse evento.
func TestWSUpgradeOnly(t *testing.T) {
	h := newHarness(t, harnessOpts{})

	var port int
	c, _ := wsDial(t, h.addr80, "ws://"+testSNI+"/p/"+testProbe+"/ws", &websocket.DialOptions{
		Subprotocols: []string{"chat"},
	}, &port)
	_ = c.CloseNow()
	evs := h.events.wsFrames(t, port, func(e []decoded) bool { return len(e) >= 1 })
	p := evs[0].Payload
	up, _ := p["upgrade"].(map[string]any)
	if p["upgrade_only"] != true || up["over"] != wsOverHTTP1 || up["path"] != "/p/"+testProbe+"/ws" ||
		up["subprotocol"] != "chat" || p["dir"] != "in" || num(t, p["opcode"]) != 0 || p["close"] != nil {
		t.Fatalf("h1 upgrade-only event %v", p)
	}

	cr := dial(t, h.addr80)
	r := newH2Raw(t, cr, true)
	_ = r.fr.WriteSettings()
	if st := h2WSConnect(t, r, 1); st != "200" {
		t.Fatalf("h2 status %s", st)
	}
	_ = r.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	evs = h.events.wsFrames(t, srcPort(cr), func(e []decoded) bool { return len(e) >= 1 })
	if up, _ := evs[0].Payload["upgrade"].(map[string]any); evs[0].Payload["upgrade_only"] != true || up["over"] != wsOverH2 {
		t.Fatalf("h2 upgrade-only event %v", evs[0].Payload)
	}

	// Com frames: o upgrade vai no primeiro frame e nenhum evento upgrade_only sai.
	c, _ = wsDial(t, h.addr80, "ws://"+testSNI+"/p/"+testProbe+"/ws", nil, &port)
	wsRoundTrip(t, c, websocket.MessageText, []byte("hi"))
	_ = c.Close(websocket.StatusNormalClosure, "")
	evs = h.events.wsFrames(t, port, func(e []decoded) bool { return hasClose(e) })
	time.Sleep(100 * time.Millisecond)
	ups := 0
	for _, e := range h.events.find(t, event.SubjectWebWebSocketFrame, port) {
		if e.Payload["upgrade_only"] == true {
			t.Fatalf("upgrade_only in a session with frames: %v", e.Payload)
		}
		if e.Payload["upgrade"] != nil {
			ups++
		}
	}
	if ups != 1 || len(evs) == 0 {
		t.Fatalf("upgrade in %d frames", ups)
	}
}
