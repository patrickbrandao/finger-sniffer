//go:build e2e

package e2e

// Caso 13 da matriz da spec 017 (parte da API, task 060): tempo real por /api/v1/ws e /api/v1/stream (filtros,
// atraso < 1 s de um evento de requisição h1/h2/h3, stream.dropped para um cliente que não lê sem atrasar os
// outros, 503 no 65º cliente), long-poll de um probe só com DNS seguido de uma conexão atrasada (task 052) e
// /metrics com as métricas da spec 004 (task 054). Os testes que enchem o feed global ou ocupam todas as vagas
// de tempo real não são paralelos: rodam sozinhos, antes dos paralelos.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
)

// liveEvent é o LiveEvent do openapi.
type liveEvent struct {
	Kind    string          `json:"kind"`
	TS      time.Time       `json:"ts"`
	ConnID  *string         `json:"conn_id"`
	ProbeID *string         `json:"probe_id"`
	Data    json.RawMessage `json:"data"`
	// Recv é a hora de chegada nesta máquina, já no relógio da vps602 (clockOffset aplicado).
	Recv time.Time `json:"-"`
}

// delay é o atraso do evento: ts (relógio da vps602) até a chegada aqui.
func (e liveEvent) delay() time.Duration { return e.Recv.Sub(e.TS) }

// apiWS é a base ws:// da API em claro (9001).
func apiWS() string { return "ws" + strings.TrimPrefix(api, "http") }

// ---------------------------------------------------------------- relógio

// clockOffset estima quanto o relógio da vps602 está à frente do daqui: uma sessão ssh devolve time.time() a
// cada linha recebida; vale a amostra de menor ida e volta (erro ≤ metade dela).
var clockOffset = sync.OnceValues(func() (time.Duration, error) {
	cmd := sshCmd(`python3 -u -c 'import sys,time
for l in sys.stdin: print(repr(time.time()), flush=True)'`)
	in, _ := cmd.StdinPipe()
	outP, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	br := bufio.NewReader(outP)
	best, off := time.Hour, time.Duration(0)
	for range 15 {
		t0 := time.Now()
		if _, err := io.WriteString(in, "x\n"); err != nil {
			return 0, err
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		t1 := time.Now()
		f, err := strconv.ParseFloat(strings.TrimSpace(line), 64)
		if err != nil {
			return 0, fmt.Errorf("relógio da vps602: %q", line)
		}
		remoteT := time.Unix(0, int64(f*1e9))
		if rtt := t1.Sub(t0); rtt < best {
			best, off = rtt, remoteT.Sub(t0.Add(rtt/2))
		}
	}
	if best > 300*time.Millisecond {
		return 0, fmt.Errorf("ida e volta do ssh alta demais para medir o relógio: %v", best)
	}
	return off, nil
})

// vpsNow é a hora atual no relógio da vps602.
func vpsNow(t *testing.T) time.Time {
	t.Helper()
	off, err := clockOffset()
	if err != nil {
		t.Fatalf("relógio: %v", err)
	}
	return time.Now().Add(off)
}

// ---------------------------------------------------------------- clientes de tempo real

// liveClient junta os eventos de um /ws ou /stream num canal.
type liveClient struct {
	events chan liveEvent
	close  func()
}

// openWS abre /api/v1/ws com a query dada; devolve o status HTTP quando o upgrade falha.
func openWS(t *testing.T, query string) (*liveClient, int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c, resp, err := websocket.Dial(ctx, apiWS()+"/ws?"+query, nil)
	if err != nil {
		cancel()
		if resp != nil {
			return nil, resp.StatusCode
		}
		t.Fatalf("ws %s: %v", query, err)
	}
	c.SetReadLimit(1 << 22)
	lc := &liveClient{events: make(chan liveEvent, 4096)}
	var once sync.Once
	lc.close = func() {
		once.Do(func() {
			_ = c.Close(websocket.StatusNormalClosure, "")
			cancel()
		})
	}
	t.Cleanup(lc.close)
	go func() {
		defer close(lc.events)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			recv := vpsNow(t)
			var ev liveEvent
			if json.Unmarshal(b, &ev) == nil {
				ev.Recv = recv
				select {
				case lc.events <- ev:
				default:
				}
			}
		}
	}()
	return lc, http.StatusSwitchingProtocols
}

// openSSE abre /api/v1/stream; rcvbuf > 0 limita o buffer de recepção do socket (cliente lento). Com
// read=false o corpo só é lido depois de startReading.
type sseClient struct {
	*liveClient
	resp  *http.Response
	start chan struct{}
}

func openSSE(t *testing.T, query string, rcvbuf int, read bool) (*sseClient, int) {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	if rcvbuf > 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbuf) })
			if err != nil {
				return err
			}
			return serr
		}
	}
	tr := &http.Transport{DialContext: d.DialContext, DisableCompression: true}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api+"/stream?"+query, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		cancel()
		t.Fatalf("sse %s: %v", query, err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusBadRequest {
			checkErrorBody(t, b)
		}
		return nil, resp.StatusCode
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("sse: Content-Type %q, Cache-Control %q", ct, resp.Header.Get("Cache-Control"))
	}
	sc := &sseClient{liveClient: &liveClient{events: make(chan liveEvent, 8192)}, resp: resp, start: make(chan struct{})}
	var once sync.Once
	sc.close = func() {
		once.Do(func() {
			cancel()
			_ = resp.Body.Close()
			tr.CloseIdleConnections()
		})
	}
	t.Cleanup(sc.close)
	if read {
		close(sc.start)
	}
	go func() {
		defer close(sc.events)
		<-sc.start
		br := bufio.NewReaderSize(resp.Body, 1<<16)
		var kind string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "event: "):
				kind = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				recv := vpsNow(t)
				var ev liveEvent
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev) == nil {
					if ev.Kind != kind {
						t.Errorf("sse: event: %s com data.kind %s", kind, ev.Kind)
					}
					ev.Recv = recv
					select {
					case sc.events <- ev:
					default:
					}
				}
			}
		}
	}()
	return sc, http.StatusOK
}

// checkErrorBody confere que o corpo é um Error do openapi ({"error": "..."}).
func checkErrorBody(t *testing.T, b []byte) {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil || e.Error == "" {
		t.Errorf("corpo de erro fora do schema Error: %q", b)
	}
}

// collect junta os eventos até que done aceite a lista ou o prazo acabe.
func collect(ch <-chan liveEvent, d time.Duration, done func([]liveEvent) bool) []liveEvent {
	var out []liveEvent
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
			if done != nil && done(out) {
				return out
			}
		case <-timer.C:
			return out
		}
	}
}

// ---------------------------------------------------------------- requisições de teste

// probeRequests faz uma requisição h1 (TLS), uma h2 e uma h3 ao probe e devolve quantas fez.
func probeRequests(t *testing.T, id string) int {
	t.Helper()
	url := "https://" + probeHost(id) + "/p/" + id + "/"
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{}
		tr.Protocols = new(http.Protocols)
		if h2 {
			tr.Protocols.SetHTTP2(true)
		} else {
			tr.Protocols.SetHTTP1(true)
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
	}
	tr := newH3Transport(nil)
	resp, err := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = tr.Close()
	return 3
}

// reqProto diz de qual protocolo é o data de um http.request (HTTP1Request, HTTP2Stream ou HTTP3Request).
func reqProto(data json.RawMessage) string {
	var d map[string]json.RawMessage
	_ = json.Unmarshal(data, &d)
	switch {
	case d["request_line"] != nil:
		return "h1"
	case d["fields"] != nil && d["body_len"] != nil:
		return "h3"
	case d["stream_id"] != nil:
		return "h2"
	}
	return "?"
}

// ---------------------------------------------------------------- testes

// TestCase13LiveFilters: /ws e /stream com filtros (probe, kind, dst_port, src_ip), filtro inválido → 400, e
// cada http.request de h1/h2/h3 chega em < 1 s do ts do evento.
func TestCase13LiveFilters(t *testing.T) {
	id := newID(t)
	other := newID(t)
	mac := macIPv4(t)
	for _, q := range []string{"dst_port=abc", "kind=nope", "probe=" + strings.Repeat("x", 300), "dst_port=70000"} {
		if _, st := openSSE(t, q, 0, true); st != http.StatusBadRequest {
			t.Errorf("/stream?%s: %d, esperava 400", q, st)
		}
		if _, st := openWS(t, q); st != http.StatusBadRequest {
			t.Errorf("/ws?%s: %d, esperava 400", q, st)
		}
	}
	wsReq, _ := openWS(t, "probe="+id+"&kind=http.request")
	wsAll, _ := openWS(t, "probe="+id)
	wsOther, _ := openWS(t, "probe="+other)
	sse443, _ := openSSE(t, "probe="+id+"&dst_port=443&src_ip="+mac, 0, true)
	sse53, _ := openSSE(t, "probe="+id+"&dst_port=53", 0, true)
	time.Sleep(300 * time.Millisecond) // assinaturas ativas antes do tráfego
	// DNS do probe direto ao autoritativo (dns.query com dst_port 53 e src_ip = esta máquina)
	query(t, vps4+":53", "udp", probeHost(id)+".", dns.TypeA, nil, false)
	n := probeRequests(t, id)

	isReq := func(evs []liveEvent) bool {
		k := 0
		for _, e := range evs {
			if e.Kind == "http.request" {
				k++
			}
		}
		return k >= n
	}
	reqs := collect(wsReq.events, 15*time.Second, isReq)
	protos := map[string]time.Duration{}
	for _, e := range reqs {
		if e.Kind != "http.request" || e.ProbeID == nil || *e.ProbeID != id {
			t.Errorf("/ws?kind=http.request&probe=%s recebeu %s probe=%s", id, e.Kind, deref(e.ProbeID))
			continue
		}
		protos[reqProto(e.Data)] = e.delay()
	}
	for _, p := range []string{"h1", "h2", "h3"} {
		d, ok := protos[p]
		switch {
		case !ok:
			t.Errorf("/ws: sem http.request %s (recebidos %v)", p, protos)
		case d >= time.Second:
			t.Errorf("/ws: http.request %s chegou %v depois do ts (máx 1 s)", p, d)
		default:
			t.Logf("/ws: http.request %s chegou %.0f ms depois do ts", p, d.Seconds()*1000)
		}
	}
	// o /ws sem kind recebe também as conexões (abertura e fechamento das 3)
	all := collect(wsAll.events, 10*time.Second, func(evs []liveEvent) bool {
		c := 0
		for _, e := range evs {
			if e.Kind == "connection.closed" {
				c++
			}
		}
		return c >= n
	})
	kinds := map[string]int{}
	for _, e := range all {
		kinds[e.Kind]++
		if e.ProbeID == nil || *e.ProbeID != id {
			t.Errorf("/ws?probe=%s recebeu evento de outro probe: %s %s", id, e.Kind, deref(e.ProbeID))
		}
	}
	// connection.opened não aparece com filtro de probe: na abertura (SYN) o probe_id ainda não é conhecido
	for _, k := range []string{"connection.updated", "connection.closed", "http.request", "dns.query"} {
		if kinds[k] == 0 {
			t.Errorf("/ws?probe: sem %s (recebidos %v)", k, kinds)
		}
	}
	t.Logf("/ws?probe=%s: %v", id, kinds)
	requireEventFields(t, all)
	checkPorts := func(name string, evs []liveEvent, port int) {
		t.Helper()
		seen := 0
		for _, e := range evs {
			seen++
			if e.ProbeID == nil || *e.ProbeID != id {
				t.Errorf("%s: evento de outro probe %s", name, e.Kind)
			}
			if port == 53 && e.Kind != "dns.query" || port == 443 && e.Kind == "dns.query" {
				t.Errorf("%s: recebeu %s", name, e.Kind)
			}
		}
		if seen == 0 {
			t.Errorf("%s: nenhum evento", name)
		}
	}
	checkPorts("/stream?dst_port=443&src_ip", collect(sse443.events, 2*time.Second, nil), 443)
	checkPorts("/stream?dst_port=53", collect(sse53.events, 500*time.Millisecond, nil), 53)
	if evs := collect(wsOther.events, 200*time.Millisecond, nil); len(evs) > 0 {
		t.Errorf("/ws?probe=%s (sem tráfego) recebeu %d eventos: %s", other, len(evs), evs[0].Kind)
	}
}

// metricValue soma as amostras da métrica (com o prefixo de rótulos dado) no /metrics.
func metricValue(t *testing.T, name string) float64 {
	t.Helper()
	b := metricsText(t)
	sum := 0.0
	for l := range strings.Lines(string(b)) {
		if !strings.HasPrefix(l, name+"{") && !strings.HasPrefix(l, name+" ") {
			continue
		}
		f := strings.Fields(l)
		v, _ := strconv.ParseFloat(f[len(f)-1], 64)
		sum += v
	}
	return sum
}

func metricsText(t *testing.T) []byte {
	t.Helper()
	resp, err := http.Get(strings.TrimSuffix(api, "/api/v1") + "/metrics") //nolint:gosec // URL do teste
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics: %d", resp.StatusCode)
	}
	return b
}

// TestCase13LiveDropped: um cliente SSE que não lê (buffer de recepção de 4 KiB) perde eventos e, quando volta a
// ler, recebe stream.dropped; enquanto isso, um cliente normal continua recebendo em < 1 s e o probe fica
// completo na API (o ingest não atrasa).
func TestCase13LiveDropped(t *testing.T) {
	id := newID(t)
	slow, _ := openSSE(t, "probe="+id, 4096, false)
	fast, _ := openWS(t, "probe="+id+"&kind=http.request")
	droppedBefore := metricValue(t, "fs_store_live_dropped_total")

	// enxurrada: 1600 requisições h2 em 4 conexões a 150/s (cada uma vira um http.request no feed do probe). O
	// ritmo fica perto do uso real; sem ele (~1000/s, como na primeira versão deste teste) o feed de todos os clientes atrasa e o teste deixa de medir
	// o isolamento do cliente lento.
	const conns, perConn, perSecond = 4, 400, 150
	tick := time.NewTicker(time.Second / perSecond)
	defer tick.Stop()
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for range conns {
		wg.Go(func() {
			tr := &http.Transport{}
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetHTTP2(true)
			defer tr.CloseIdleConnections()
			cl := &http.Client{Transport: tr, Timeout: 60 * time.Second}
			// a primeira requisição sozinha abre a conexão h2; as outras multiplexam nela
			if resp, err := cl.Get("https://" + probeHost(id) + "/p/" + id + "/"); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			sem := make(chan struct{}, 50)
			var iw sync.WaitGroup
			for range perConn - 1 {
				sem <- struct{}{}
				<-tick.C
				iw.Go(func() {
					defer func() { <-sem }()
					resp, err := cl.Get("https://" + probeHost(id) + "/p/" + id + "/")
					if err != nil {
						mu.Lock()
						failed++
						mu.Unlock()
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				})
			}
			iw.Wait()
		})
	}
	wg.Wait()
	if failed > 0 {
		t.Errorf("%d requisições da enxurrada falharam", failed)
	}
	// o cliente rápido recebeu as requisições sem atraso
	got := collect(fast.events, 20*time.Second, func(evs []liveEvent) bool { return len(evs) >= conns*perConn })
	var delays []time.Duration
	for _, e := range got {
		delays = append(delays, e.delay())
	}
	sort.Slice(delays, func(i, j int) bool { return delays[i] < delays[j] })
	if len(delays) < conns*perConn {
		t.Errorf("cliente rápido recebeu %d de %d http.request", len(delays), conns*perConn)
	}
	if len(delays) > 0 {
		p95 := delays[len(delays)*95/100]
		t.Logf("cliente rápido: %d eventos, atraso p50 %.0f ms, p95 %.0f ms, máx %.0f ms", len(delays),
			delays[len(delays)/2].Seconds()*1000, p95.Seconds()*1000, delays[len(delays)-1].Seconds()*1000)
		if p95 >= time.Second {
			t.Errorf("cliente rápido: p95 do atraso %v durante a enxurrada (máx 1 s)", p95)
		}
	}
	// o ingest não atrasou: o probe fica completo na API
	p, _ := waitProbeRaw(t, id, func(p *probeResp) bool {
		n := 0
		for _, c := range p.Connections {
			n += h2Streams(c)
		}
		return n >= conns*perConn
	})
	t.Logf("probe %s: %d conexões no registro", id, len(p.Connections))

	// o lento volta a ler: tem de aparecer um stream.dropped
	close(slow.start)
	evs := collect(slow.events, 30*time.Second, func(evs []liveEvent) bool {
		return slices.ContainsFunc(evs, func(e liveEvent) bool { return e.Kind == "stream.dropped" })
	})
	i := slices.IndexFunc(evs, func(e liveEvent) bool { return e.Kind == "stream.dropped" })
	if i < 0 {
		t.Fatalf("cliente lento: nenhum stream.dropped em %d eventos", len(evs))
	}
	var d struct {
		Dropped int `json:"dropped"`
	}
	_ = json.Unmarshal(evs[i].Data, &d)
	if d.Dropped < 1 {
		t.Errorf("stream.dropped com dropped=%d", d.Dropped)
	}
	t.Logf("cliente lento: stream.dropped dropped=%d depois de %d eventos", d.Dropped, i)
	if after := metricValue(t, "fs_store_live_dropped_total"); after <= droppedBefore {
		t.Errorf("fs_store_live_dropped_total não subiu (%v → %v)", droppedBefore, after)
	}
}

// TestCase13LiveMaxClients: com FS_LIVE_MAX_CLIENTS (64) clientes de tempo real (SSE + WS), o próximo recebe
// 503 nos dois transportes; ao fechar, as vagas voltam.
func TestCase13LiveMaxClients(t *testing.T) {
	const maxClients = 64
	time.Sleep(time.Second) // clientes fechados pelos testes anteriores saem da contagem
	base := metricValue(t, "fs_store_live_clients")
	var opened []*liveClient
	defer func() {
		for _, c := range opened {
			c.close()
		}
	}()
	got503 := false
	for i := 0; i < maxClients+5; i++ {
		var c *liveClient
		var st int
		if i%2 == 0 {
			c, st = openWS(t, "kind=packet.stray")
		} else {
			var s *sseClient
			s, st = openSSE(t, "kind=packet.stray", 0, true)
			if s != nil {
				c = s.liveClient
			}
		}
		if st == http.StatusServiceUnavailable {
			got503 = true
			now := metricValue(t, "fs_store_live_clients")
			t.Logf("503 depois de abrir %d clientes (%v já conectados antes, %v agora)", len(opened), base, now)
			if now != maxClients {
				t.Errorf("503 com %v clientes de tempo real, esperava %d", now, maxClients)
			}
			// o outro transporte também recusa
			if i%2 == 0 {
				_, st = openSSE(t, "kind=packet.stray", 0, true)
			} else {
				_, st = openWS(t, "kind=packet.stray")
			}
			if st != http.StatusServiceUnavailable {
				t.Errorf("com as vagas cheias o outro transporte respondeu %d", st)
			}
			break
		}
		if st != http.StatusOK && st != http.StatusSwitchingProtocols {
			t.Fatalf("cliente %d: status %d", i, st)
		}
		opened = append(opened, c)
	}
	if !got503 {
		t.Fatalf("nenhum 503 com %d clientes abertos (+%v antes)", len(opened), base)
	}
	for _, c := range opened {
		c.close()
	}
	opened = nil
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && metricValue(t, "fs_store_live_clients") > base {
		time.Sleep(200 * time.Millisecond)
	}
	if now := metricValue(t, "fs_store_live_clients"); now > base {
		t.Errorf("depois de fechar, ainda %v clientes de tempo real (antes %v)", now, base)
	}
}

// TestCase13LongPoll: probe só com DNS; o long-poll espera a primeira conexão (que chega 3 s depois) fechar
// (task 052) em vez de responder na hora com só a consulta.
func TestCase13LongPoll(t *testing.T) {
	t.Parallel()
	id := newID(t)
	query(t, vps4+":53", "udp", probeHost(id)+".", dns.TypeA, nil, false)
	time.Sleep(time.Second) // a consulta chega ao store
	type result struct {
		p    probeResp
		b    []byte
		took time.Duration
		err  error
	}
	ch := make(chan result, 1)
	t0 := time.Now()
	go func() {
		resp, err := http.Get(api + "/probes/" + id + "?wait=30s") //nolint:gosec // URL do teste
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer resp.Body.Close() //nolint:errcheck // leitura
		b, _ := io.ReadAll(resp.Body)
		var p probeResp
		err = json.Unmarshal(b, &p)
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("status %d: %s", resp.StatusCode, b)
		}
		ch <- result{p: p, b: b, took: time.Since(t0), err: err}
	}()
	time.Sleep(3 * time.Second)
	select {
	case r := <-ch:
		t.Fatalf("long-poll respondeu com só DNS em %v: %v %s", r.took, r.err, r.b)
	default:
	}
	c := dialTCP(t, 80)
	c.send(t, "GET /p/"+id+"/ HTTP/1.1\r\nHost: "+probeHost(id)+"\r\nConnection: close\r\n\r\n")
	if r := c.readResponse(t); r.Status != 200 {
		t.Fatalf("GET /p/: %d", r.Status)
	}
	_ = c.Close()
	sent := time.Since(t0)
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	addLive("probe-example.json", r.b)
	if r.took < sent {
		t.Errorf("long-poll respondeu em %v, antes da conexão terminar (%v)", r.took, sent)
	}
	if len(r.p.Connections) != 1 || !r.p.AllClosed || len(r.p.DNS) == 0 {
		t.Errorf("long-poll: %d conexões, all_closed=%v, %d consultas DNS", len(r.p.Connections), r.p.AllClosed, len(r.p.DNS))
	}
	t.Logf("long-poll respondeu %.0f ms depois do fim da conexão", (r.took-sent).Seconds()*1000)
}

// idInRoute acha um conn_id (ULID) ou probe ID do e2e num rótulo route.
var idInRoute = regexp.MustCompile(`[0-9A-Z]{26}|f3[a-z0-9]{14}`)

// sshCmd monta o ssh para a vps602 (sem rodar).
func sshCmd(cmd string) *exec.Cmd {
	return exec.Command("ssh", "-4", "-p", vpsPort, "-o", "BatchMode=yes", vpsSSH, cmd)
}

// storeMetrics são as métricas próprias do store da spec 004 RF-10.
var storeMetrics = []string{
	"fs_service_up", "fs_service_info", "fs_store_events_ingested_total", "fs_store_ingest_lag_seconds",
	"fs_store_connections_open", "fs_store_connections_total", "fs_store_connections_degraded_total",
	"fs_store_stray_packets_total", "fs_store_dns_queries_total", "fs_store_purged_total", "fs_store_db_bytes",
	"fs_store_record_ready_seconds", "fs_store_live_clients", "fs_store_live_events_total",
	"fs_store_live_dropped_total", "fs_store_live_delay_seconds", "fs_store_api_requests_total",
	"fs_store_api_request_duration_seconds",
}

// TestCase13Metrics: /metrics na 9001 com as métricas da spec 004 (e as gauges dos heartbeats), rótulos route sem
// IDs; a 9000 não serve /metrics.
func TestCase13Metrics(t *testing.T) {
	t.Parallel()
	get(t, "/connections?limit=1", nil) // garante ao menos uma rota com contagem
	b := metricsText(t)
	types := map[string]string{}
	for l := range strings.Lines(string(b)) {
		if f := strings.Fields(l); len(f) == 4 && f[1] == "TYPE" {
			types[f[2]] = f[3]
		}
	}
	for _, m := range storeMetrics {
		if types[m] == "" {
			t.Errorf("/metrics sem %s", m)
		}
	}
	for _, m := range []string{"fs_store_ingest_lag_seconds", "fs_store_record_ready_seconds", "fs_store_live_delay_seconds", "fs_store_api_request_duration_seconds"} {
		if types[m] != "histogram" {
			t.Errorf("%s é %q, esperava histogram", m, types[m])
		}
	}
	for _, svc := range []string{"capture", "web", "raw", "dns", "store"} {
		if !bytes.Contains(b, []byte(`fs_service_up{service="`+svc+`"} 1`)) {
			t.Errorf("fs_service_up do %s não é 1", svc)
		}
	}
	if !bytes.Contains(b, []byte(`l4="udp",proto="quic/h3"`)) && !bytes.Contains(b, []byte(`proto="quic/h3"`)) {
		t.Errorf("fs_store_connections_total sem proto quic/h3")
	}
	for l := range strings.Lines(string(b)) {
		if strings.HasPrefix(l, "fs_store_api_requests_total{") && strings.Contains(l, "route=") {
			i := strings.Index(l, `route="`)
			route, _, _ := strings.Cut(l[i+7:], `"`)
			if idInRoute.MatchString(route) {
				t.Errorf("route com ID no rótulo: %q", route)
			}
		}
	}
	resp, err := http.Get("https://" + vpsHost + ":9000/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("https://%s:9000/metrics: %d, esperava 404 (só 9001)", vpsHost, resp.StatusCode)
	}
}
