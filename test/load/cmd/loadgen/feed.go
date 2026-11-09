//go:build load

package main

// Clientes do feed global (/api/v1/ws e /api/v1/stream): anotam a chegada de cada evento já no relógio da
// vps602 (deslocamento medido por ssh) e o connection.closed de cada probe da carga.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// liveEvent é o LiveEvent do openapi (só os campos usados aqui).
type liveEvent struct {
	Kind    string          `json:"kind"`
	TS      time.Time       `json:"ts"`
	ConnID  *string         `json:"conn_id"`
	ProbeID *string         `json:"probe_id"`
	Data    json.RawMessage `json:"data"`
}

// summary é o ConnectionSummary do data de connection.*.
type summary struct {
	Proto    string     `json:"proto"`
	L4       string     `json:"l4"`
	Started  time.Time  `json:"started"`
	Ended    *time.Time `json:"ended"`
	Degraded bool       `json:"degraded"`
	Requests int        `json:"requests"`
}

// feedSample é um evento recebido: tipo, ts e chegada (ns, relógio da vps602).
type feedSample struct {
	Kind  string
	Proto string // data.proto de connection.* (separa o connection.updated do raw.session, ts = accept)
	TS    int64
	Recv  int64
}

// closedInfo é o connection.closed de um probe.
type closedInfo struct {
	Recv     int64 // chegada (relógio da vps602)
	Ended    int64 // data.ended
	ConnID   string
	Proto    string
	L4       string
	Degraded bool
	Requests int
}

// feed acumula o que um cliente de tempo real recebeu.
type feed struct {
	name    string
	offset  time.Duration // relógio da vps602 − relógio local
	mu      sync.Mutex
	samples []feedSample
	closed  map[string]closedInfo // por probe
	dropped int                   // soma de stream.dropped.dropped
	drops   int                   // quantos stream.dropped
	errors  []string
	recent  []recentConn // últimos fechados, para a amostragem da API
}

type recentConn struct{ connID, probe string }

func newFeed(name string, offset time.Duration) *feed {
	return &feed{name: name, offset: offset, closed: map[string]closedInfo{}}
}

func (f *feed) handle(b []byte, recv time.Time) {
	var ev liveEvent
	if err := json.Unmarshal(b, &ev); err != nil {
		f.mu.Lock()
		if len(f.errors) < 20 {
			f.errors = append(f.errors, "json: "+err.Error())
		}
		f.mu.Unlock()
		return
	}
	rv := recv.Add(f.offset).UnixNano()
	f.mu.Lock()
	defer f.mu.Unlock()
	fs := feedSample{Kind: ev.Kind, TS: ev.TS.UnixNano(), Recv: rv}
	var s summary
	if strings.HasPrefix(ev.Kind, "connection.") {
		_ = json.Unmarshal(ev.Data, &s)
		fs.Proto = s.Proto
	}
	f.samples = append(f.samples, fs)
	switch ev.Kind {
	case "stream.dropped":
		var d struct {
			Dropped int `json:"dropped"`
		}
		_ = json.Unmarshal(ev.Data, &d)
		f.dropped += d.Dropped
		f.drops++
	case "connection.closed":
		if ev.ProbeID == nil || !strings.HasPrefix(*ev.ProbeID, "ld") {
			return
		}
		ci := closedInfo{Recv: rv, Proto: s.Proto, L4: s.L4, Degraded: s.Degraded, Requests: s.Requests}
		if s.Ended != nil {
			ci.Ended = s.Ended.UnixNano()
		}
		if ev.ConnID != nil {
			ci.ConnID = *ev.ConnID
			f.recent = append(f.recent, recentConn{*ev.ConnID, *ev.ProbeID})
			if len(f.recent) > 512 {
				f.recent = f.recent[len(f.recent)-256:]
			}
		}
		// um probe da carga tem uma conexão; se vier outra (não deveria), guarda a primeira
		if _, ok := f.closed[*ev.ProbeID]; !ok {
			f.closed[*ev.ProbeID] = ci
		}
	}
}

func (f *feed) errorf(s string) {
	f.mu.Lock()
	if len(f.errors) < 20 {
		f.errors = append(f.errors, s)
	}
	f.mu.Unlock()
}

// pickRecent devolve um conn_id/probe recém-fechado (o i-ésimo a partir do fim).
func (f *feed) pickRecent(i int) (recentConn, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.recent) == 0 {
		return recentConn{}, false
	}
	return f.recent[len(f.recent)-1-i%min(len(f.recent), 32)], true
}

func (f *feed) closedOf(probe string) (closedInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ci, ok := f.closed[probe]
	return ci, ok
}

func wsURL(api string) string {
	switch {
	case strings.HasPrefix(api, "https://"):
		return "wss://" + strings.TrimPrefix(api, "https://")
	case strings.HasPrefix(api, "http://"):
		return "ws://" + strings.TrimPrefix(api, "http://")
	}
	return api
}

// runWS lê /api/v1/ws (sem filtro: feed global) até ctx acabar, reconectando se cair.
func runWS(ctx context.Context, api string, f *feed) {
	for ctx.Err() == nil {
		c, _, err := websocket.Dial(ctx, wsURL(api)+"/ws", &websocket.DialOptions{
			HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}},
		})
		if err != nil {
			f.errorf("ws dial: " + err.Error())
			sleepCtx(ctx, time.Second)
			continue
		}
		c.SetReadLimit(1 << 24)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				if ctx.Err() == nil {
					f.errorf("ws read: " + err.Error())
				}
				break
			}
			f.handle(b, time.Now())
		}
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
}

// runSSE lê /api/v1/stream até ctx acabar, reconectando se cair.
func runSSE(ctx context.Context, api string, f *feed) {
	client := &http.Client{Transport: &http.Transport{DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api+"/stream", nil)
		resp, err := client.Do(req)
		if err != nil {
			f.errorf("sse: " + err.Error())
			sleepCtx(ctx, time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			f.errorf("sse: status " + resp.Status)
			_ = resp.Body.Close()
			sleepCtx(ctx, time.Second)
			continue
		}
		br := bufio.NewReaderSize(resp.Body, 1<<20)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				if ctx.Err() == nil {
					f.errorf("sse read: " + err.Error())
				}
				break
			}
			if strings.HasPrefix(line, "data: ") {
				f.handle([]byte(strings.TrimRight(strings.TrimPrefix(line, "data: "), "\r\n")), time.Now())
			}
		}
		_ = resp.Body.Close()
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
