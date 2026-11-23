package store

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestJSONWriteDeadlineSlowReader: um cliente que pede e não lê não prende o handler JSON para sempre: a escrita
// falha no prazo, o handler volta e a resposta montada sai da memória (task 319). Vale para writeJSON e
// writeProbe, usados por todas as rotas JSON.
func TestJSONWriteDeadlineSlowReader(t *testing.T) {
	old := jsonWriteTimeout
	jsonWriteTimeout = 300 * time.Millisecond
	t.Cleanup(func() { jsonWriteTimeout = old })

	big := strings.Repeat("x", 32<<20) // bem maior que os buffers de socket dos dois lados
	cases := map[string]http.HandlerFunc{
		"writeJSON": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"blob": big})
		},
		"writeProbe": func(w http.ResponseWriter, _ *http.Request) {
			writeProbe(w, probeJSON{ProbeID: big})
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				h(w, r)
			}))
			defer srv.Close()
			c, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetReadBuffer(4 << 10)
			}
			if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			// O cliente não lê nada.
			select {
			case <-done:
			case <-time.After(jsonWriteTimeout + 5*time.Second):
				t.Fatal("handler still blocked on Write past the deadline")
			}
		})
	}
}
