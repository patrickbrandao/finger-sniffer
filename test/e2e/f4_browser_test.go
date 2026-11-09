//go:build e2e

package e2e

// Critério de saída da F4 e casos 12/13 da spec 017 com navegadores reais (task 060): Chrome headless (CDP) e
// Firefox headless (WebDriver BiDi), com o sandbox ligado e sem forçar QUIC por linha de comando. Cada um abre a
// página do htdocs em https://vps602.tmsoft.com.br/, espera o feed ficar "live", clica em "Run probe" e confere:
//   - o registro do probe mostra uma requisição em quic/h3 (a segunda, pelo Alt-Svc, ou já a primeira pelo HTTPS
//     RR);
//   - cada linha do probe aparece no DOM do feed em < 1 s do ts do evento (MutationObserver injetado antes da
//     página, hora do DOM convertida para o relógio da vps602 por clockOffset);
//   - nenhuma requisição da página sai para host fora da vps602 e de *.dns-monitor (lista do CDP/BiDi).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const firefoxBin = "/Applications/Firefox.app/Contents/MacOS/firefox"

// pageURL é a página do htdocs servida nas portas capturadas.
func pageURL() string { return "https://" + vpsHost + "/" }

// domObserver registra cada <li> novo do feed com a hora local (ms) e os textos das colunas.
const domObserver = `(() => {
  window.__fsDOM = [];
  const start = () => {
    const feed = document.getElementById("feed");
    if (!feed) { setTimeout(start, 5); return; }
    new MutationObserver((muts) => {
      const now = Date.now();
      for (const m of muts) for (const n of m.addedNodes) {
        if (n.nodeType !== 1 || n.tagName !== "LI") continue;
        const txt = (c) => { const e = n.querySelector("." + c); return e ? e.textContent : ""; };
        window.__fsDOM.push({ t: now, ts: txt("ts"), kind: txt("kind"), proto: txt("proto"), what: txt("what") });
      }
    }).observe(feed, { childList: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})()`

// ---------------------------------------------------------------- JSON-RPC sobre WebSocket (CDP e BiDi)

type rpcMsg struct {
	ID        *int            `json:"id,omitempty"`
	Type      string          `json:"type,omitempty"` // BiDi: success | error | event
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     json.RawMessage `json:"error,omitempty"`
	Message   string          `json:"message,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

type rpcConn struct {
	c       *websocket.Conn
	mu      sync.Mutex
	next    int
	pending map[int]chan rpcMsg
	evMu    sync.Mutex
	events  []rpcMsg
}

func dialRPC(ctx context.Context, wsURL string) (*rpcConn, error) {
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(64 << 20)
	r := &rpcConn{c: c, pending: map[int]chan rpcMsg{}}
	go func() {
		for {
			_, b, err := c.Read(context.Background())
			if err != nil {
				r.mu.Lock()
				for id, ch := range r.pending {
					close(ch)
					delete(r.pending, id)
				}
				r.mu.Unlock()
				return
			}
			var m rpcMsg
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			if m.ID != nil && m.Type != "event" {
				r.mu.Lock()
				ch := r.pending[*m.ID]
				delete(r.pending, *m.ID)
				r.mu.Unlock()
				if ch != nil {
					ch <- m
				}
				continue
			}
			r.evMu.Lock()
			r.events = append(r.events, m)
			r.evMu.Unlock()
		}
	}()
	return r, nil
}

// call manda um comando e espera a resposta (session vazio = alvo do browser no CDP).
func (r *rpcConn) call(ctx context.Context, session, method string, params any) (json.RawMessage, error) {
	r.mu.Lock()
	r.next++
	id := r.next
	ch := make(chan rpcMsg, 1)
	r.pending[id] = ch
	r.mu.Unlock()
	if params == nil {
		params = map[string]any{}
	}
	msg := map[string]any{"id": id, "method": method, "params": params}
	if session != "" {
		msg["sessionId"] = session
	}
	b, _ := json.Marshal(msg)
	if err := r.c.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return nil, errors.New("conexão de depuração fechada")
		}
		if len(m.Error) > 0 || m.Type == "error" {
			return nil, fmt.Errorf("%s: %s %s", method, m.Error, m.Message)
		}
		return m.Result, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", method, ctx.Err())
	}
}

func (r *rpcConn) eventsOf(method string) []json.RawMessage {
	r.evMu.Lock()
	defer r.evMu.Unlock()
	var out []json.RawMessage
	for _, m := range r.events {
		if m.Method == method {
			out = append(out, m.Params)
		}
	}
	return out
}

// ---------------------------------------------------------------- navegadores

// browser é o que o teste da página precisa de um navegador controlado.
type browser interface {
	navigate(ctx context.Context, u string) error
	eval(ctx context.Context, expr string) (string, error) // expressão que devolve string
	requests() []string                                    // URLs pedidas pela página (http, https, ws, wss)
	protocols() map[string][]string                        // protocolo das respostas, por URL
	close()
}

// startProcess roda o navegador e devolve a primeira linha do stderr que casa com re.
func startProcess(t *testing.T, re *regexp.Regexp, bin string, args ...string) (*exec.Cmd, string) {
	t.Helper()
	cmd := exec.Command(bin, args...) //nolint:gosec // navegador local
	stderr, _ := cmd.StderrPipe()
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: %v", bin, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	found := make(chan string, 1)
	var log strings.Builder
	go func() {
		sc := bufio.NewScanner(stderr)
		sent := false
		for sc.Scan() {
			if !sent {
				log.WriteString(sc.Text() + "\n")
			}
			if m := re.FindStringSubmatch(sc.Text()); m != nil && !sent {
				found <- m[1]
				sent = true
			}
		}
		if !sent {
			close(found)
		}
	}()
	select {
	case u, ok := <-found:
		if !ok {
			t.Fatalf("%s saiu sem abrir a depuração:\n%s", bin, log.String())
		}
		return cmd, u
	case <-time.After(30 * time.Second):
		t.Fatalf("%s não abriu a depuração em 30 s", bin)
	}
	return nil, ""
}

// chrome via CDP, numa aba nova com o domínio Network ligado.
type chrome struct {
	r       *rpcConn
	session string
}

func startChrome(t *testing.T) browser {
	t.Helper()
	dir := t.TempDir()
	_, wsURL := startProcess(t, regexp.MustCompile(`DevTools listening on (ws://\S+)`), chromeBin,
		"--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir="+dir, "--remote-debugging-port=0", "about:blank")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := dialRPC(ctx, wsURL)
	if err != nil {
		t.Fatalf("CDP: %v", err)
	}
	res, err := r.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	var tg struct {
		TargetID string `json:"targetId"`
	}
	_ = json.Unmarshal(res, &tg)
	res, err = r.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": tg.TargetID, "flatten": true})
	if err != nil {
		t.Fatal(err)
	}
	var at struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(res, &at)
	c := &chrome{r: r, session: at.SessionID}
	for _, m := range []string{"Network.enable", "Page.enable", "Runtime.enable"} {
		if _, err := r.call(ctx, c.session, m, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.call(ctx, c.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": domObserver}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *chrome) navigate(ctx context.Context, u string) error {
	_, err := c.r.call(ctx, c.session, "Page.navigate", map[string]any{"url": u})
	return err
}

func (c *chrome) eval(ctx context.Context, expr string) (string, error) {
	res, err := c.r.call(ctx, c.session, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true})
	if err != nil {
		return "", err
	}
	var v struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	_ = json.Unmarshal(res, &v)
	if v.Exception != nil {
		return "", fmt.Errorf("eval %q: %s", expr, v.Exception.Text)
	}
	s, _ := v.Result.Value.(string)
	return s, nil
}

func (c *chrome) requests() []string {
	var out []string
	for _, p := range c.r.eventsOf("Network.requestWillBeSent") {
		var e struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		_ = json.Unmarshal(p, &e)
		out = append(out, e.Request.URL)
	}
	for _, p := range c.r.eventsOf("Network.webSocketCreated") {
		var e struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(p, &e)
		out = append(out, e.URL)
	}
	return out
}

func (c *chrome) protocols() map[string][]string {
	out := map[string][]string{}
	for _, p := range c.r.eventsOf("Network.responseReceived") {
		var e struct {
			Response struct {
				URL      string `json:"url"`
				Protocol string `json:"protocol"`
			} `json:"response"`
		}
		_ = json.Unmarshal(p, &e)
		out[e.Response.URL] = append(out[e.Response.URL], e.Response.Protocol)
	}
	return out
}

func (c *chrome) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.r.call(ctx, "", "Browser.close", nil)
}

// firefox via WebDriver BiDi.
type firefox struct {
	r   *rpcConn
	ctx string
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // só a porta
	return l.Addr().(*net.TCPAddr).Port
}

func startFirefox(t *testing.T) browser {
	t.Helper()
	dir := t.TempDir()
	port := freePort(t)
	_, wsBase := startProcess(t, regexp.MustCompile(`WebDriver BiDi listening on (ws://\S+)`), firefoxBin,
		"--headless", "--no-remote", "--profile", dir, fmt.Sprintf("--remote-debugging-port=%d", port), "about:blank")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := dialRPC(ctx, strings.TrimSuffix(wsBase, "/")+"/session")
	if err != nil {
		t.Fatalf("BiDi: %v", err)
	}
	if _, err := r.call(ctx, "", "session.new", map[string]any{"capabilities": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.call(ctx, "", "session.subscribe", map[string]any{"events": []string{"network.beforeRequestSent", "network.responseCompleted"}}); err != nil {
		t.Fatal(err)
	}
	res, err := r.call(ctx, "", "browsingContext.getTree", nil)
	if err != nil {
		t.Fatal(err)
	}
	var tree struct {
		Contexts []struct {
			Context string `json:"context"`
		} `json:"contexts"`
	}
	_ = json.Unmarshal(res, &tree)
	if len(tree.Contexts) == 0 {
		t.Fatal("BiDi: sem browsingContext")
	}
	if _, err := r.call(ctx, "", "script.addPreloadScript", map[string]any{"functionDeclaration": "() => " + domObserver}); err != nil {
		t.Fatal(err)
	}
	return &firefox{r: r, ctx: tree.Contexts[0].Context}
}

func (f *firefox) navigate(ctx context.Context, u string) error {
	_, err := f.r.call(ctx, "", "browsingContext.navigate", map[string]any{"context": f.ctx, "url": u, "wait": "interactive"})
	return err
}

func (f *firefox) eval(ctx context.Context, expr string) (string, error) {
	res, err := f.r.call(ctx, "", "script.evaluate", map[string]any{
		"expression": expr, "target": map[string]any{"context": f.ctx}, "awaitPromise": false,
	})
	if err != nil {
		return "", err
	}
	var v struct {
		Type   string `json:"type"`
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	_ = json.Unmarshal(res, &v)
	if v.Type == "exception" {
		return "", fmt.Errorf("eval %q: %s", expr, v.Exception)
	}
	s, _ := v.Result.Value.(string)
	return s, nil
}

func (f *firefox) requests() []string {
	var out []string
	for _, p := range f.r.eventsOf("network.beforeRequestSent") {
		var e struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		_ = json.Unmarshal(p, &e)
		out = append(out, e.Request.URL)
	}
	return out
}

func (f *firefox) protocols() map[string][]string {
	out := map[string][]string{}
	for _, p := range f.r.eventsOf("network.responseCompleted") {
		var e struct {
			Response struct {
				URL      string `json:"url"`
				Protocol string `json:"protocol"`
			} `json:"response"`
		}
		_ = json.Unmarshal(p, &e)
		out[e.Response.URL] = append(out[e.Response.URL], e.Response.Protocol)
	}
	return out
}

func (f *firefox) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = f.r.call(ctx, "", "browser.close", nil)
}

// ---------------------------------------------------------------- teste da página

// waitEval repete a expressão até devolver um valor aceito por ok.
func waitEval(ctx context.Context, b browser, expr string, ok func(string) bool) (string, error) {
	var last string
	var err error
	for ctx.Err() == nil {
		if last, err = b.eval(ctx, expr); err == nil && ok(last) {
			return last, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last, fmt.Errorf("%q: último valor %q (%v)", expr, last, err)
}

// allowedPageHost diz se a página pode falar com o host (spec 014: só a vps602 e a zona dos probes).
func allowedPageHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return true // data:, blob:, about: não saem da máquina
	}
	h := u.Hostname()
	return h == vpsHost || strings.HasSuffix(h, "."+zone)
}

type domRow struct {
	T     int64  `json:"t"`
	TS    string `json:"ts"`
	Kind  string `json:"kind"`
	Proto string `json:"proto"`
	What  string `json:"what"`
}

// runPageProbe abre a página, roda o "Run probe" e confere o critério de saída da F4.
func runPageProbe(t *testing.T, name string, b browser) {
	t.Helper()
	defer b.close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := b.navigate(ctx, pageURL()); err != nil {
		t.Fatalf("%s: navegar: %v", name, err)
	}
	if _, err := waitEval(ctx, b, `String(document.getElementById("feed-state") && document.getElementById("feed-state").dataset.state)`,
		func(s string) bool { return s == "live" }); err != nil {
		t.Fatalf("%s: feed não ficou live: %v", name, err)
	}
	id, err := b.eval(ctx, `(() => { document.getElementById("run-probe").click(); return document.getElementById("f-probe").value; })()`)
	if err != nil || !regexp.MustCompile(`^[a-z0-9]{12}$`).MatchString(id) {
		t.Fatalf("%s: run probe: %q %v", name, id, err)
	}
	t.Logf("%s: probe %s", name, id)
	steps, err := waitEval(ctx, b, `(() => { const r = document.querySelector("#probe-result a"); if (!r) return "";
		return Array.from(document.querySelectorAll("#probe-steps li, #probe-result li")).map((l) => l.textContent).join("\n"); })()`,
		func(s string) bool { return s != "" })
	if err != nil {
		t.Fatalf("%s: o probe não terminou na página: %v", name, err)
	}
	t.Logf("%s: painel do probe:\n%s", name, steps)
	time.Sleep(1500 * time.Millisecond) // últimos connection.closed chegam ao feed

	// h3 no registro do probe
	// (o Firefox mantém as conexões abertas até a ociosidade; não dá para esperar all_closed)
	var h3Conn *record
	var order []string
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && h3Conn == nil; {
		p := probeNow(t, id)
		order = order[:0]
		for _, c := range p.conns(443) {
			order = append(order, c.Proto)
			if c.Proto == "quic/h3" && c.HTTP3 != nil && len(c.HTTP3.Requests) > 0 && h3Conn == nil {
				h3Conn = &c
			}
		}
		if h3Conn == nil {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if h3Conn == nil {
		t.Errorf("%s: nenhuma requisição do probe em quic/h3 (conexões na 443: %v)", name, order)
	} else {
		via := "Alt-Svc (segunda requisição)"
		if order[0] == "quic/h3" {
			via = "HTTPS RR (já a primeira)"
		}
		ja4 := ""
		if h3Conn.HTTP3.ClientHello != nil {
			ja4 = h3Conn.HTTP3.ClientHello.JA4
		}
		t.Logf("%s: h3 via %s; conexões na 443 em ordem: %v; JA4 %s", name, via, order, ja4)
	}

	// atraso até o DOM
	raw, err := b.eval(ctx, `JSON.stringify(window.__fsDOM || [])`)
	if err != nil {
		t.Fatal(err)
	}
	var rows []domRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("%s: __fsDOM: %v", name, err)
	}
	off, err := clockOffset()
	if err != nil {
		t.Fatal(err)
	}
	var delays, closedDelays []time.Duration
	var closedRows []domRow
	var worst domRow
	for _, r := range rows {
		if !strings.Contains(r.What, "[probe "+id+"]") {
			continue
		}
		dom := time.UnixMilli(r.T).Add(off).UTC()
		ts, err := time.Parse("2006-01-02 15:04:05.000", dom.Format("2006-01-02")+" "+r.TS)
		if err != nil {
			t.Errorf("%s: ts da linha %q: %v", name, r.TS, err)
			continue
		}
		if ts.Sub(dom) > 12*time.Hour { // virada do dia
			ts = ts.Add(-24 * time.Hour)
		}
		d := dom.Sub(ts)
		if r.Kind == "conn closed" {
			// o ts do connection.closed é o fim da conexão (último pacote ou CONNECTION_CLOSE); o store só grava o
			// registro depois da folga de fechamento (1 s em TCP, para o último ACK; 2 s em QUIC, ADR 0019).
			// Conferido à parte: folga + 1 s.
			closedRows = append(closedRows, r)
			closedDelays = append(closedDelays, d)
			continue
		}
		if len(delays) == 0 || d > delays[len(delays)-1] {
			worst = r
		}
		delays = append(delays, d)
		sort.Slice(delays, func(i, j int) bool { return delays[i] < delays[j] })
	}
	if len(delays) == 0 {
		t.Errorf("%s: nenhuma linha do probe %s no feed (%d linhas)", name, id, len(rows))
	} else {
		maxD := delays[len(delays)-1]
		t.Logf("%s: %d linhas do probe no feed, atraso ts→DOM p50 %.0f ms, máx %.0f ms (%s %s %s)", name, len(delays),
			delays[len(delays)/2].Seconds()*1000, maxD.Seconds()*1000, worst.Kind, worst.Proto, worst.What)
		if maxD >= time.Second {
			t.Errorf("%s: linha do feed apareceu %v depois do ts (máx 1 s): %+v", name, maxD, worst)
		}
	}

	for i, d := range closedDelays {
		limit := 2 * time.Second // folga TCP de 1 s + 1 s
		if strings.HasPrefix(closedRows[i].Proto, "quic") {
			limit = 3 * time.Second // folga QUIC de 2 s + 1 s (e o ≤ 3 s da spec 004/011)
		}
		t.Logf("%s: conn closed %s no feed %.0f ms depois do fim (máx %v)", name, closedRows[i].Proto, d.Seconds()*1000, limit)
		if d >= limit {
			t.Errorf("%s: fechamento %s no feed %v depois do fim (máx %v)", name, closedRows[i].Proto, d, limit)
		}
	}

	// nenhuma requisição a terceiros
	reqs := b.requests()
	if len(reqs) == 0 {
		t.Errorf("%s: nenhuma requisição registrada pela depuração", name)
	}
	hosts := map[string]int{}
	for _, u := range reqs {
		if pu, err := url.Parse(u); err == nil {
			hosts[pu.Scheme+"://"+pu.Host]++
		}
		if !allowedPageHost(u) {
			t.Errorf("%s: requisição a host de terceiros: %s", name, u)
		}
	}
	t.Logf("%s: %d requisições da página por origem: %v", name, len(reqs), hosts)
	for u, ps := range b.protocols() {
		if strings.Contains(u, "/p/"+id+"/") {
			t.Logf("%s: %s → %v", name, u, ps)
		}
	}
}

// TestF4PageChrome: Chrome headless (sandbox ligado, sem --origin-to-force-quic-on).
func TestF4PageChrome(t *testing.T) {
	if _, err := os.Stat(chromeBin); err != nil {
		t.Skipf("%s não está instalado nesta máquina", chromeBin)
	}
	runPageProbe(t, "chrome", startChrome(t))
}

// TestF4PageFirefox: Firefox headless (sandbox ligado, sem exceções de h3 no perfil).
func TestF4PageFirefox(t *testing.T) {
	if _, err := os.Stat(firefoxBin); err != nil {
		t.Skipf("%s não está instalado nesta máquina", firefoxBin)
	}
	runPageProbe(t, "firefox", startFirefox(t))
}
