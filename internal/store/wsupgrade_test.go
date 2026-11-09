package store

import (
	"net/http"
	"testing"
)

// TestCheckWSUpgrade: o pedido de upgrade é conferido antes do Accept (task 092).
func TestCheckWSUpgrade(t *testing.T) {
	ok := http.Header{
		"Connection": {"keep-alive, Upgrade"}, "Upgrade": {"WebSocket"},
		"Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="},
	}
	if err := checkWSUpgrade(&http.Request{Header: ok}); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(h http.Header){
		"no connection": func(h http.Header) { h.Del("Connection") },
		"no upgrade":    func(h http.Header) { h.Set("Upgrade", "h2c") },
		"version 8":     func(h http.Header) { h.Set("Sec-Websocket-Version", "8") },
		"no key":        func(h http.Header) { h.Del("Sec-Websocket-Key") },
		"short key":     func(h http.Header) { h.Set("Sec-Websocket-Key", "YWJj") },
	} {
		h := ok.Clone()
		mut(h)
		err := checkWSUpgrade(&http.Request{Header: h})
		if _, isBad := err.(badRequest); !isBad { //nolint:errorlint // tipo concreto do pacote
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestWaitFormat: só ^[0-9]+(ms|s)$ é aceito em ?wait.
func TestWaitFormat(t *testing.T) {
	for v, want := range map[string]bool{"10s": true, "500ms": true, "0s": true, "1.5s": false, "1us": false, "1m30s": false, "-1s": false, "s": false} {
		if waitRe.MatchString(v) != want {
			t.Fatalf("%q: want %v", v, want)
		}
	}
}
