package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	// Q responde às consultas (nil desliga as rotas de consulta); W é o banco de escrita (DELETE).
	Q *Queries
	W *sql.DB
}

// Handler devolve o http.Handler da 9001 (HTTP) com CORS aberto (ADR 0007), incluindo /metrics.
func (a *API) Handler() http.Handler { return a.handler(true) }

// HTTPSHandler devolve o http.Handler da 9000 (HTTPS): as mesmas rotas, sem /metrics (spec 004 RF-10).
func (a *API) HTTPSHandler() http.Handler { return a.handler(false) }

func (a *API) handler(withMetrics bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/openapi.yaml", a.openapi)
	if withMetrics {
		mux.HandleFunc("GET /metrics", a.metrics)
	}
	if a.Q != nil {
		mux.HandleFunc("GET /api/v1/connections", a.listConnections)
		mux.HandleFunc("GET /api/v1/connections/{conn_id}", a.getConnection)
		mux.HandleFunc("GET /api/v1/connections/{conn_id}/pcap", a.getPcap)
		mux.HandleFunc("GET /api/v1/connections/{conn_id}/raw", a.getRaw)
		mux.HandleFunc("GET /api/v1/packets", a.listPackets)
		mux.HandleFunc("GET /api/v1/dns", a.listDNS)
		mux.HandleFunc("GET /api/v1/probes/{id}", a.getProbe)
		mux.HandleFunc("DELETE /api/v1/probes/{id}", a.deleteProbe)
	}
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

// writeErr converte erros de consulta em 400/404/500 com o schema Error.
func writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBadRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, context.Canceled):
		// cliente desistiu
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func (a *API) listConnections(w http.ResponseWriter, r *http.Request) {
	f, err := ParseListFilter(r.URL.Query().Get)
	if err != nil {
		writeErr(w, err)
		return
	}
	list, err := a.Q.Connections(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getConnection(w http.ResponseWriter, r *http.Request) {
	rec, err := a.Q.Connection(r.Context(), r.PathValue("conn_id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (a *API) getPcap(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("conn_id")
	data, err := a.Q.Pcap(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.pcap"`)
	_, _ = w.Write(data)
}

func (a *API) getRaw(w http.ResponseWriter, r *http.Request) {
	data, err := a.Q.Raw(r.Context(), r.PathValue("conn_id"), r.URL.Query().Get("dir"))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (a *API) listPackets(w http.ResponseWriter, r *http.Request) {
	f, err := ParseListFilter(r.URL.Query().Get)
	if err != nil {
		writeErr(w, err)
		return
	}
	list, err := a.Q.Packets(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) listDNS(w http.ResponseWriter, r *http.Request) {
	f, err := ParseListFilter(r.URL.Query().Get)
	if err != nil {
		writeErr(w, err)
		return
	}
	list, err := a.Q.DNS(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getProbe(w http.ResponseWriter, r *http.Request) {
	var wait time.Duration
	if v := r.URL.Query().Get("wait"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || (!strings.HasSuffix(v, "s") && !strings.HasSuffix(v, "ms")) {
			writeErr(w, bad("invalid wait %q (ex.: 10s)", v))
			return
		}
		wait = d
	}
	p, err := a.Q.Probe(r.Context(), r.PathValue("id"), wait)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *API) deleteProbe(w http.ResponseWriter, r *http.Request) {
	if err := a.Q.DeleteProbe(r.Context(), a.W, r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
