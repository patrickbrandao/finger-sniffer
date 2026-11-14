package store

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// bigLiveMsg é um http.request de ~900 KiB (o teto de evento do web).
func bigLiveMsg() *liveMsg {
	payload := []byte(`{"pad":"` + strings.Repeat("x", 900<<10) + `"}`)
	return newLiveMsg(LiveHTTPRequest, time.Now().UnixNano(), "A", "", client.Addr(), 443, payload)
}

// TestLiveClientByteCap: um cliente SSE parado segura no máximo 4 MiB de eventos na fila, por maior que seja o
// FS_LIVE_BUFFER; o excedente vira stream.dropped, entregue quando ele volta a ler (task 138, ADR 0034).
func TestLiveClientByteCap(t *testing.T) {
	_, h, srv := liveAPI(t, 1024, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/stream", nil)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	eventually(t, 2*time.Second, func() bool { return h.Stats().Clients["sse"] == 1 }, "client not joined")
	const n = 256
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	for range n {
		h.Publish(bigLiveMsg())
		if q := h.queued.Load(); q > liveClientMaxBytes {
			t.Fatalf("fila com %d bytes, teto %d", q, liveClientMaxBytes)
		}
	}
	// o que ficou retido: a fila (<= 4 MiB), o evento na mão do escritor e o buffer do socket
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if grow := int64(ms.HeapAlloc) - int64(before); grow > 16<<20 {
		t.Fatalf("heap retido cresceu %d MiB com o cliente parado", grow>>20)
	}
	if h.Stats().Dropped == 0 {
		t.Fatal("nada descartado")
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 2<<20), 2<<20)
	got, dropped, kind := 0, 0, ""
	for got+dropped < n && sc.Scan() {
		line := sc.Text()
		if k, ok := strings.CutPrefix(line, "event: "); ok {
			kind = k
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if kind == LiveStreamDrop {
			var d struct {
				Data struct {
					Dropped int `json:"dropped"`
				} `json:"data"`
			}
			_ = json.Unmarshal([]byte(data), &d)
			dropped += d.Data.Dropped
		} else {
			got++
		}
	}
	if dropped == 0 || got+dropped != n {
		t.Fatalf("got=%d dropped=%d, soma devia ser %d", got, dropped, n)
	}
	eventually(t, 2*time.Second, func() bool { return h.queued.Load() == 0 }, "bytes da fila não voltaram a 0")
}

// TestLiveHubByteCap: 64 clientes parados somam no máximo 64 MiB de filas (cada evento conta em cada fila); ao
// saírem, o hub volta a 0 (task 138).
func TestLiveHubByteCap(t *testing.T) {
	h := NewHub(1024, DefaultLiveMaxClients)
	var cs []*liveClient
	for range DefaultLiveMaxClients {
		c, err := h.join(LiveFilter{DstPort: -1}, "sse")
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
	}
	for range 8 {
		h.Publish(bigLiveMsg())
		if q := h.queued.Load(); q > liveHubMaxBytes {
			t.Fatalf("filas somam %d bytes, teto %d", q, liveHubMaxBytes)
		}
	}
	var sum int64
	for _, c := range cs {
		if q := c.queued.Load(); q > liveClientMaxBytes {
			t.Fatalf("cliente com %d bytes", q)
		}
		sum += c.queued.Load()
	}
	if sum != h.queued.Load() || sum < liveHubMaxBytes-(1<<20) || h.Stats().Dropped == 0 {
		t.Fatalf("soma %d, hub %d, descartes %d", sum, h.queued.Load(), h.Stats().Dropped)
	}
	// um cliente que lê devolve os bytes; os que saem devolvem o resto
	m := <-cs[0].ch
	h.take(cs[0], m)
	if h.queued.Load() != sum-int64(len(m.data)) {
		t.Fatal("take não devolveu os bytes")
	}
	for _, c := range cs {
		h.leave(c)
	}
	if h.queued.Load() != 0 {
		t.Fatalf("hub com %d bytes depois de todos saírem", h.queued.Load())
	}
}
