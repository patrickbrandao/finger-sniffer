package certs

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"
)

// countHandler guarda as mensagens e o atributo "in" (atraso da nova tentativa) dos registros.
type countHandler struct {
	mu     sync.Mutex
	msgs   []string
	delays []time.Duration
}

func (h *countHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *countHandler) WithGroup(string) slog.Handler            { return h }

func (h *countHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "in" {
			h.delays = append(h.delays, a.Value.Duration())
		}
		return true
	})
	return nil
}

func (h *countHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

func (h *countHandler) retries() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.delays)
}

const warnReload = "certs: recarga falhou, mantendo o anterior"

// TestReloadBackoff: par permanentemente inválido é relido com atraso dobrando até pollInterval e avisado
// uma vez por erro distinto; corrigido, é recarregado logo pelo evento do arquivo (task 170).
func TestReloadBackoff(t *testing.T) {
	dir := t.TempDir()
	writeBoth(t, dir, time.Now().Add(60*24*time.Hour))
	h := &countHandler{}
	s, err := Open(testConfig(dir), slog.New(h))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	addr := echoServer(t, s.TLSConfig())

	// chave de outro par: o certificado antigo continua servido
	_, otherKey := genPair(t, "outro", SplitNames(DefaultNamesHTTP01), time.Now().Add(80*24*time.Hour))
	if err := writeAtomic(dir, "http01.key", otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4*time.Second + 500*time.Millisecond)
	if n := h.count(warnReload); n != 1 {
		t.Fatalf("%d avisos de recarga, quer 1", n)
	}
	want := []time.Duration{retryDelay, 2 * retryDelay, 4 * retryDelay, 8 * retryDelay}
	if got := h.retries(); !slices.Equal(got, want) {
		t.Fatalf("tentativas %v, quer %v", got, want)
	}
	if c, cn := dial(t, addr, "", nil); cn != "cert-B" {
		_ = c.Close()
		t.Fatalf("durante o par inválido: %s", cn)
	} else {
		_ = c.Close()
	}

	// erro diferente: novo aviso, e o evento recomeça o backoff
	if err := writeAtomic(dir, "http01.key", []byte("lixo"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.count(warnReload) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("erro novo sem aviso")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := h.retries(); len(got) < 5 || got[4] != retryDelay {
		t.Fatalf("backoff não recomeçou: %v", got)
	}

	// par corrigido: recarregado pelo evento, bem antes do poll
	crt, key := genPair(t, "cert-B4", SplitNames(DefaultNamesHTTP01), time.Now().Add(80*24*time.Hour))
	if err := WritePair(dir, SlotHTTP01, crt, key); err != nil {
		t.Fatal(err)
	}
	if took := waitCN(t, addr, "", "cert-B4", 2*time.Second); took > time.Second {
		t.Fatalf("recarga em %v", took)
	}
}
