package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// API serve as rotas do store implementadas nesta fase: health, contrato e métricas (spec 004).
type API struct {
	OpenAPI []byte
	// Health monta a resposta de /api/v1/health no instante dado.
	Health func(ctx context.Context, now time.Time) Health
	Now    func() time.Time
}

// Handler devolve o http.Handler com CORS aberto (ADR 0007).
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/openapi.yaml", a.openapi)
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	return cors(mux)
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Health(r.Context(), a.Now()))
}

func (a *API) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(a.OpenAPI)
}

// metrics expõe as métricas de cada serviço (recebidas no heartbeat) no formato texto do Prometheus.
func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	h := a.Health(r.Context(), a.Now())
	var b strings.Builder
	b.WriteString("# TYPE fs_service_up gauge\n")
	for _, name := range sortedKeys(h.Services) {
		up := 0
		if h.Services[name].Status != event.StatusDown {
			up = 1
		}
		fmt.Fprintf(&b, "fs_service_up{service=%q} %d\n", name, up)
	}
	for _, name := range sortedKeys(h.Services) {
		m := h.Services[name].Metrics
		for _, k := range sortedKeys(m) {
			fmt.Fprintf(&b, "fs_%s{service=%q} %g\n", sanitize(k), name, m[k])
		}
	}
	if h.Host != nil {
		fmt.Fprintf(&b, "fs_host_syncookies_sent %d\n", h.Host.SyncookiesSent)
		if h.Host.Store != nil {
			fmt.Fprintf(&b, "fs_store_db_bytes %d\nfs_store_connections %d\n", h.Host.Store.DBBytes, h.Host.Store.Connections)
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}

// sanitize deixa só [a-zA-Z0-9_] no nome da métrica.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, s)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
