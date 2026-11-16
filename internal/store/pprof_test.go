package store

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// O pprof só responde a loopback e só na 9001 (task 246).
func TestPprofLoopbackOnly(t *testing.T) {
	a := &API{OpenAPI: []byte("x")}
	cases := []struct {
		name   string
		h      http.Handler
		remote string
		want   int
	}{
		{"9001 loopback v4", a.Handler(), "127.0.0.1:5555", http.StatusOK},
		{"9001 loopback v6", a.Handler(), "[::1]:5555", http.StatusOK},
		{"9001 remote", a.Handler(), "203.0.113.7:5555", http.StatusNotFound},
		{"9000 loopback", a.HTTPSHandler(), "127.0.0.1:5555", http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
			r.RemoteAddr = c.remote
			w := httptest.NewRecorder()
			c.h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}
