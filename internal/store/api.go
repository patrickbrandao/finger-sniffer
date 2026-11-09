package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	// Live é o hub do tempo real (nil desliga /stream e /ws).
	Live *Hub
	// Prom são as métricas do /metrics e da própria API (nil desliga /metrics).
	Prom *storeMetrics
}

// Handler devolve o http.Handler da 9001 (HTTP) com CORS aberto (ADR 0007), incluindo /metrics.
func (a *API) Handler() http.Handler { return a.handler(true) }

// HTTPSHandler devolve o http.Handler da 9000 (HTTPS): as mesmas rotas, sem /metrics (spec 004 RF-10).
func (a *API) HTTPSHandler() http.Handler { return a.handler(false) }

func (a *API) handler(withMetrics bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/openapi.yaml", a.openapi)
	if withMetrics && a.Prom != nil {
		mux.Handle("GET /metrics", a.Prom.handler)
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
	if a.Live != nil {
		mux.HandleFunc("GET /api/v1/stream", a.stream)
		mux.HandleFunc("GET /api/v1/ws", a.ws)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	return cors(a.Prom.instrument(mux))
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

// waitRe é o formato de ?wait e ?settle em /probes/{id} (openapi); minConnsRe, o de ?min_conns.
var (
	waitRe     = regexp.MustCompile(`^[0-9]+(ms|s)$`)
	minConnsRe = regexp.MustCompile(`^[0-9]{1,4}$`)
)

// parseProbeWait lê wait, settle e min_conns (spec 004, ADR 0029): settle e min_conns só valem com wait.
func parseProbeWait(get func(string) string) (ProbeWait, error) {
	var pw ProbeWait
	dur := func(name, v string) (time.Duration, error) {
		// Formato do contrato: ^[0-9]+(ms|s)$ (sem fração, sem outras unidades).
		d, err := time.ParseDuration(v)
		if err != nil || !waitRe.MatchString(v) {
			return 0, bad("invalid %s %q (ex.: 10s)", name, v)
		}
		return d, nil
	}
	wait, settle, minConns := get("wait"), get("settle"), get("min_conns")
	if wait == "" {
		if settle != "" || minConns != "" {
			return pw, bad("settle and min_conns require wait")
		}
		return pw, nil
	}
	var err error
	pw.Given = true
	if pw.Wait, err = dur("wait", wait); err != nil {
		return pw, err
	}
	if settle != "" {
		if pw.Settle, err = dur("settle", settle); err != nil {
			return pw, err
		}
		if pw.Settle > 10*time.Second {
			return pw, bad("invalid settle %q (0s to 10s)", settle)
		}
	}
	pw.MinConns = 1
	if minConns != "" {
		n, err := strconv.Atoi(minConns)
		if err != nil || !minConnsRe.MatchString(minConns) || n < 1 || n > 1000 {
			return pw, bad("invalid min_conns %q (1 to 1000)", minConns)
		}
		pw.MinConns = n
	}
	return pw, nil
}

func (a *API) getProbe(w http.ResponseWriter, r *http.Request) {
	pw, err := parseProbeWait(r.URL.Query().Get)
	if err != nil {
		writeErr(w, err)
		return
	}
	p, err := a.Q.Probe(r.Context(), r.PathValue("id"), pw)
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
