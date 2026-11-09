package store

import (
	"encoding/json"
	"testing"
)

func TestProtoRule(t *testing.T) {
	hello := map[string]any{"sni": "x"}
	raw := json.RawMessage(`{}`)
	ws := &wsJSON{Over: "h2"}
	cases := []struct {
		name string
		l    layers
		want string
	}{
		{"none tcp", layers{}, "tcp"},
		{"tls only", layers{clientHello: hello}, "tls"},
		{"http1.1", layers{http1: map[int]json.RawMessage{0: raw}, http1Version: "HTTP/1.1"}, "http1.1"},
		{"http1.0", layers{http1: map[int]json.RawMessage{0: raw}, http1Version: "HTTP/1.0"}, "http1.0"},
		{"tls h1 ws", layers{clientHello: hello, http1: map[int]json.RawMessage{0: raw}, http1Version: "HTTP/1.1", ws: &wsJSON{Over: "http1.1"}}, "tls/http1.1/ws"},
		{"h2 alpn", layers{clientHello: hello, http2: map[string]any{"mode": "alpn"}}, "tls/h2"},
		{"h2 ws", layers{clientHello: hello, http2: map[string]any{"mode": "alpn"}, ws: ws}, "tls/h2/ws"},
		{"h2c prior", layers{http2: map[string]any{"mode": "prior-knowledge"}}, "h2c"},
		{"h2c upgrade", layers{http1: map[int]json.RawMessage{0: raw}, http2: map[string]any{"mode": "upgrade"}}, "h2c"},
		{"raw", layers{raw: raw}, "raw"},
		{"tls raw", layers{clientHello: hello, raw: raw}, "tls/raw"},
		{"raw unknown", layers{raw: raw, rawFromWeb: true}, "raw/unknown"},
		{"dns", layers{dns: true}, "dns"},
	}
	for _, c := range cases {
		if got := c.l.proto("tcp"); got != c.want {
			t.Errorf("%s: %q want %q", c.name, got, c.want)
		}
	}
	if (&layers{}).proto("udp") != "udp" {
		t.Fatal("udp")
	}
}
