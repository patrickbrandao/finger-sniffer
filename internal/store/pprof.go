package store

import (
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"runtime"
	"strconv"
)

// pprofHandler serve o net/http/pprof na 9001 só para clientes de loopback (diagnóstico de vazão, task 246):
// quem está na própria máquina (ssh) perfila; de fora a rota responde como qualquer rota desconhecida.
// /debug/pprof/rates?block=N&mutex=N liga ou desliga os perfis de bloqueio e de mutex (0 desliga; padrão
// desligado, porque custam CPU em cada espera).
func pprofHandler(notFound http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/debug/pprof/rates", func(w http.ResponseWriter, r *http.Request) {
		if v, err := strconv.Atoi(r.URL.Query().Get("block")); err == nil && v >= 0 {
			runtime.SetBlockProfileRate(v)
		}
		if v, err := strconv.Atoi(r.URL.Query().Get("mutex")); err == nil && v >= 0 {
			runtime.SetMutexProfileFraction(v)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fromLoopback(r) {
			notFound.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// fromLoopback diz se a requisição veio de um endereço de loopback.
func fromLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}
