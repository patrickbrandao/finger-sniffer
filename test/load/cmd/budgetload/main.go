//go:build load

// Comando budgetload: carga do orçamento de memória de entrada do web (task 214, critério que ficou da task 155;
// spec 005 RF-12, ADR 0033). Roda na máquina cliente (fora do servidor) e segura, ao mesmo tempo:
//
//   - -h1 conexões HTTP/1 em claro com cabeçalho parcial de ~1 MiB (abaixo do teto de 1 MiB e de 1024 campos),
//     que nunca termina: o web reserva o cabeçalho do orçamento e, sem espaço, responde 431;
//   - -ws sessões WebSocket (/p/<id>/ws) mandando mensagens de ~1 MiB sem ler o eco (janela do cliente zerada);
//   - -h3 conexões QUIC com um HEADERS declarado de ~2 MiB que nunca completa (recusa H3_EXCESSIVE_LOAD).
//
// Cada trabalhador reabre a conexão quando o servidor responde ou fecha. A cada segundo lê o health da 9001
// (web_input_budget_used_bytes, web_input_budget_denied_total, conexões ativas) e grava health.csv; no fim grava
// summary.json em -out. A memória do cgroup vem do loadmon (budget.sh).
//
//	budgetload -out DIR [-host finger-01.badblock.net.br] [-duration 3m] [-h1 220] [-ws 16] [-h3 14]
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/patrickbrandao/finger-sniffer/pkg/quicparse"
	"github.com/patrickbrandao/finger-sniffer/test/load/loadstat"
)

// zone é a zona dos probes; webPorts e quicPort são as portas do web no finger-01 (ADR 0038 itens 2 e 3).
const (
	zone     = "finger-west-01.badblock.net.br"
	quicPort = "8443"
)

var webPorts = []int{8080}

// contadores do cliente, por caminho
type counters struct {
	Dials      atomic.Int64
	DialErrors atomic.Int64
	Held       atomic.Int64 // h1: cabeçalho de ~1 MiB inteiro enviado sem resposta
	Status431  atomic.Int64
	Status101  atomic.Int64
	Status503  atomic.Int64
	OtherResp  atomic.Int64
	Closed     atomic.Int64 // encerrada sem linha de resposta (h1/WS: soma de causes; h3: conexão ou stream caiu)
	Excessive  atomic.Int64 // h3: stream recusado com H3_EXCESSIVE_LOAD
	ResetOther atomic.Int64
	SentBytes  atomic.Int64
	Active     atomic.Int64
	MaxActive  atomic.Int64
	// WebSocket: sessões com 101 de pé ao mesmo tempo
	Sessions    atomic.Int64
	MaxSessions atomic.Int64
	// causas das encerradas sem resposta no h1 e no WebSocket (task 220; loadstat.CloseCauses)
	causes sync.Map // string → *atomic.Int64
	// WebSocket: como terminaram as sessões com 101 (mesmas causas, vistas na escrita das mensagens)
	sessionEnds sync.Map
}

func addCause(m *sync.Map, cause string) {
	v, _ := m.LoadOrStore(cause, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

func causeMap(m *sync.Map) map[string]int64 {
	out := make(map[string]int64, len(loadstat.CloseCauses))
	for _, k := range loadstat.CloseCauses {
		out[k] = 0
	}
	m.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// noResponse conta uma conexão encerrada sem linha de resposta, pela causa.
func (c *counters) noResponse(cause string) {
	c.Closed.Add(1)
	addCause(&c.causes, cause)
}

func (c *counters) snapshot() map[string]any {
	return map[string]any{
		"dials": c.Dials.Load(), "dial_errors": c.DialErrors.Load(), "held_full_head": c.Held.Load(),
		"status_431": c.Status431.Load(), "status_101": c.Status101.Load(), "status_503": c.Status503.Load(),
		"other_response": c.OtherResp.Load(), "closed_no_response": c.Closed.Load(),
		"close_causes": causeMap(&c.causes), "ws_session_ends": causeMap(&c.sessionEnds),
		"h3_excessive_load": c.Excessive.Load(), "h3_reset_other": c.ResetOther.Load(),
		"sent_bytes": c.SentBytes.Load(), "max_active": c.MaxActive.Load(), "max_ws_sessions": c.MaxSessions.Load(),
	}
}

func (c *counters) enter() { raise(&c.Active, &c.MaxActive) }

func (c *counters) enterSession() { raise(&c.Sessions, &c.MaxSessions) }

// raise soma 1 em cur e guarda o máximo em peak.
func raise(cur, peak *atomic.Int64) {
	n := cur.Add(1)
	for {
		m := peak.Load()
		if n <= m || peak.CompareAndSwap(m, n) {
			return
		}
	}
}

func newProbeID() string {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 14)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return "bg" + string(b)
}

// sleepCtx dorme d ou até o fim da carga.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// h1Worker: cabeçalho parcial de headBytes, em pedaços de 64 KiB a cada 250 ms, e depois 1 byte a cada 5 s
// (sem fechar o cabeçalho) até o servidor responder ou fechar ou passar hold. Sem resposta, separa a causa
// (task 220): FIN/RST do servidor visto na leitura ou na escrita, prazo de 10 s da escrita vencido (o servidor
// parou de ler), prazo da leitura vencido ou o cliente desistiu depois de hold.
func h1Worker(ctx context.Context, host string, port, headBytes int, hold time.Duration, c *counters) {
	line := "X-Fill: " + strings.Repeat("a", 1100) + "\r\n"
	type readResult struct {
		line string
		err  error
	}
	for ctx.Err() == nil {
		id := newProbeID()
		c.Dials.Add(1)
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			c.DialErrors.Add(1)
			sleepCtx(ctx, time.Second)
			continue
		}
		c.enter()
		resp := make(chan readResult, 1)
		go func() {
			// primeira linha da resposta, ou o erro quando o servidor fecha sem responder
			_ = conn.SetReadDeadline(time.Now().Add(hold + time.Minute))
			l, err := bufio.NewReader(conn).ReadString('\n')
			resp <- readResult{l, err}
		}()
		var buf strings.Builder
		buf.WriteString("GET /p/" + id + "/r HTTP/1.1\r\nHost: " + id + "." + zone + "\r\nUser-Agent: fs-budgetload\r\n")
		var (
			sent        int
			rr          readResult
			gotRead     bool
			writeErr    error
			holdExpired bool
		)
		write := func(s string) bool {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, err := io.WriteString(conn, s)
			sent += n
			c.SentBytes.Add(int64(n))
			writeErr = err
			return err == nil
		}
		for sent < headBytes && !gotRead && ctx.Err() == nil {
			for buf.Len() < 64<<10 && sent+buf.Len() < headBytes {
				buf.WriteString(line)
			}
			if !write(buf.String()) {
				break
			}
			buf.Reset()
			select {
			case rr = <-resp:
				gotRead = true
			case <-ctx.Done():
			case <-time.After(250 * time.Millisecond):
			}
		}
		if !gotRead && writeErr == nil && ctx.Err() == nil && sent >= headBytes {
			c.Held.Add(1)
			end := time.After(hold)
		trickle:
			for {
				select {
				case rr = <-resp:
					gotRead = true
					break trickle
				case <-ctx.Done():
					break trickle
				case <-end:
					holdExpired = true
					break trickle
				case <-time.After(5 * time.Second):
					if !write("b") {
						break trickle
					}
				}
			}
		}
		if !gotRead {
			// resposta ou fechamento em trânsito: espera 1 s antes de fechar do lado do cliente
			select {
			case rr = <-resp:
				gotRead = true
			case <-time.After(time.Second):
			}
		}
		_ = conn.Close()
		switch {
		case gotRead && strings.Contains(rr.line, " 431 "):
			c.Status431.Add(1)
		case gotRead && rr.line != "":
			c.OtherResp.Add(1)
		case ctx.Err() != nil:
			// fim da carga: não conta
		case gotRead && rr.err != nil:
			c.noResponse(loadstat.CloseCause(rr.err, false))
		case writeErr != nil:
			c.noResponse(loadstat.CloseCause(writeErr, true))
		case holdExpired:
			c.noResponse(loadstat.CauseClientHoldExpired)
		default:
			c.noResponse(loadstat.CauseOther)
		}
		c.Active.Add(-1)
		// recuo para não passar de FS_MAX_NEW_CONNS_PER_S com 220 trabalhadores
		sleepCtx(ctx, time.Second)
	}
}

// wsFrame monta um frame binário mascarado (cliente → servidor) de n bytes de payload zerado: o payload
// mascarado é a própria máscara repetida.
func wsFrame(n int) []byte {
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	f := []byte{0x82, 0x80 | 127}
	f = binary.BigEndian.AppendUint64(f, uint64(n)) //nolint:gosec // n >= 0 (flag)
	f = append(f, mask[:]...)
	for i := range n {
		f = append(f, mask[i%4])
	}
	return f
}

// wsWorker: Upgrade em /p/<id>/ws e mensagens de ~1 MiB sem ler o eco; o servidor encerra a sessão quando o eco
// não consegue escrever (30 s) ou o orçamento recusa o Upgrade (503).
func wsWorker(ctx context.Context, host string, port int, frame []byte, c *counters) {
	for ctx.Err() == nil {
		id := newProbeID()
		c.Dials.Add(1)
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			c.DialErrors.Add(1)
			sleepCtx(ctx, time.Second)
			continue
		}
		c.enter()
		req := "GET /p/" + id + "/ws HTTP/1.1\r\nHost: " + id + "." + zone + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = io.WriteString(conn, req)
		wrote := err == nil
		var st string
		if wrote {
			st, err = bufio.NewReader(conn).ReadString('\n')
		}
		switch {
		case err != nil && ctx.Err() != nil:
			// fim da carga: não conta
		case err != nil:
			c.noResponse(loadstat.CloseCause(err, !wrote))
		case strings.Contains(st, " 101 "):
			c.Status101.Add(1)
			c.enterSession()
			_ = conn.SetDeadline(time.Time{})
			// não lê mais nada: a janela de recepção do cliente enche e o eco do servidor trava
			for ctx.Err() == nil {
				_ = conn.SetWriteDeadline(time.Now().Add(45 * time.Second))
				n, err := conn.Write(frame)
				c.SentBytes.Add(int64(n))
				if err != nil {
					if ctx.Err() == nil {
						addCause(&c.sessionEnds, loadstat.CloseCause(err, true))
					}
					break
				}
			}
			c.Sessions.Add(-1)
		case strings.Contains(st, " 503 "):
			c.Status503.Add(1)
		default:
			c.OtherResp.Add(1)
		}
		_ = conn.Close()
		c.Active.Add(-1)
		sleepCtx(ctx, time.Second)
	}
}

// h3Worker: uma conexão QUIC por vez; em cada uma, streams paralelos com HEADERS declarado de declared bytes
// (até o teto de 1 MiB por frame) e só sent enviados; cada um, recusado ou vencido o prazo de 10 s, é trocado
// por outro até a conexão cair. Dois streams de ~1 MiB enchem o teto de 2 MiB da conexão.
func h3Worker(ctx context.Context, host string, streams, declared, sent int, c *counters) {
	frame := quicparse.AppendH3FrameHeader(nil, quicparse.H3FrameHeaders, uint64(declared)) //nolint:gosec // flag positiva
	frame = append(frame, make([]byte, sent)...)
	for ctx.Err() == nil {
		id := newProbeID()
		c.Dials.Add(1)
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		qc, err := quic.DialAddr(dctx, net.JoinHostPort(host, quicPort),
			&tls.Config{ServerName: id + "." + zone, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
		cancel()
		if err != nil {
			c.DialErrors.Add(1)
			sleepCtx(ctx, time.Second)
			continue
		}
		c.enter()
		var wg sync.WaitGroup
		for range streams {
			wg.Go(func() { h3Streams(ctx, qc, frame, c) })
		}
		wg.Wait()
		if qc.Context().Err() != nil && ctx.Err() == nil {
			c.Closed.Add(1)
		}
		_ = qc.CloseWithError(0, "")
		c.Active.Add(-1)
		sleepCtx(ctx, time.Second)
	}
}

// h3Streams abre um stream depois do outro na conexão até ela cair ou a carga acabar.
func h3Streams(ctx context.Context, qc *quic.Conn, frame []byte, c *counters) {
	for ctx.Err() == nil && qc.Context().Err() == nil {
		str, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return
		}
		go func() {
			n, _ := str.Write(frame)
			c.SentBytes.Add(int64(n))
		}()
		b, err := io.ReadAll(str)
		var se *quic.StreamError
		switch {
		case errors.As(err, &se) && se.ErrorCode == 0x107:
			c.Excessive.Add(1)
		case err != nil:
			c.ResetOther.Add(1)
		case len(b) > 0:
			c.OtherResp.Add(1)
		default:
			c.Closed.Add(1)
		}
		str.CancelWrite(0x10c) // H3_REQUEST_CANCELLED
		sleepCtx(ctx, 200*time.Millisecond)
	}
}

// webHealth é o recorte do health da 9001 usado aqui.
type webHealth struct {
	Services map[string]struct {
		Status  string             `json:"status"`
		Metrics map[string]float64 `json:"metrics"`
	} `json:"services"`
}

func main() {
	host := flag.String("host", "finger-01.badblock.net.br", "alvo (nome ou IP)")
	h3Family := flag.String("h3-family", "6", "família do h3 (4 ou 6): do Mac ao finger-01 o UDP IPv4 grande se perde")
	out := flag.String("out", "", "pasta dos resultados (health.csv, summary.json)")
	duration := flag.Duration("duration", 3*time.Minute, "duração da carga")
	nH1 := flag.Int("h1", 220, "conexões HTTP/1 com cabeçalho parcial")
	nWS := flag.Int("ws", 16, "sessões WebSocket")
	nH3 := flag.Int("h3", 14, "conexões h3 com HEADERS parcial")
	head := flag.Int("head", 1<<20-48<<10, "bytes do cabeçalho parcial h1 (abaixo do teto de 1 MiB)")
	hold := flag.Duration("hold", 60*time.Second, "quanto o h1 segura o cabeçalho completo antes de reabrir")
	wsMsg := flag.Int("ws-msg", 1<<20-64, "payload das mensagens WebSocket (até 1 MiB)")
	h3Streams := flag.Int("h3-streams", 2, "streams h3 simultâneos por conexão")
	h3Decl := flag.Int("h3-declared", 1<<20-1024, "tamanho declarado do HEADERS h3 (teto de 1 MiB por frame)")
	h3Sent := flag.Int("h3-sent", 1<<20-2048, "bytes do HEADERS h3 enviados")
	wsDelay := flag.Duration("ws-delay", 0, "atraso do início dos WebSocket depois da rampa do h1 (janela C da task 215)")
	wsRamp := flag.Duration("ws-ramp", 0, "intervalo entre as aberturas iniciais dos WebSocket (100ms = 10/s)")
	analyze := flag.String("analyze", "", "só analisa um cgroup.csv do loadmon: memória do web por janela de 30 s")
	nstatDelta := flag.String("nstat-delta", "", "só compara duas saídas de nstat -asz: ANTES,DEPOIS (task 215)")
	flag.Parse()
	if *nstatDelta != "" {
		before, after, ok := strings.Cut(*nstatDelta, ",")
		if !ok {
			log.Fatal("-nstat-delta ANTES,DEPOIS")
		}
		b, err := os.ReadFile(before) //nolint:gosec // caminho do operador
		if err != nil {
			log.Fatal(err)
		}
		a, err := os.ReadFile(after) //nolint:gosec // caminho do operador
		if err != nil {
			log.Fatal(err)
		}
		loadstat.NstatDelta(os.Stdout, string(b), string(a))
		return
	}
	if *analyze != "" {
		ws, err := loadstat.MemWindowsFile(*analyze, "web", 30*time.Second)
		if err != nil {
			log.Fatal(err)
		}
		loadstat.PrintMemWindows(os.Stdout, ws)
		return
	}
	if *out == "" {
		log.Fatal("-out obrigatório")
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}
	ips, err := net.LookupIP(*host)
	if err != nil || len(ips) == 0 {
		log.Fatalf("resolver %s: %v", *host, err)
	}
	ip := ips[0].String()
	for _, a := range ips {
		if a.To4() != nil {
			ip = a.String()
			break
		}
	}
	h3IP := ip
	if *h3Family == "6" {
		for _, a := range ips {
			if a.To4() == nil {
				h3IP = a.String()
				break
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	var h1c, wsc, h3c counters
	var wg sync.WaitGroup
	start := time.Now()
	frame := wsFrame(*wsMsg)
	ports := webPorts
	for i := range *nH1 {
		wg.Go(func() { h1Worker(ctx, ip, ports[i%len(ports)], *head, *hold, &h1c) })
		time.Sleep(15 * time.Millisecond) // rampa: ~65 novas/s no início, abaixo do limitador depois do recuo
	}
	// WebSocket: começa -ws-delay depois da rampa do h1 e abre um a cada -ws-ramp (sem bloquear o amostrador)
	wg.Go(func() {
		if *wsDelay > 0 && !sleepCtx(ctx, *wsDelay) {
			return
		}
		for i := range *nWS {
			wg.Go(func() { wsWorker(ctx, ip, ports[i%len(ports)], frame, &wsc) })
			if *wsRamp > 0 && !sleepCtx(ctx, *wsRamp) {
				return
			}
		}
	})
	for range *nH3 {
		wg.Go(func() { h3Worker(ctx, h3IP, *h3Streams, *h3Decl, *h3Sent, &h3c) })
	}

	// amostrador do health
	f, err := os.Create(filepath.Join(*out, "health.csv"))
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintln(w, "t_s,web_status,budget_used_bytes,budget_denied_total,web_connections_active,h1_active,ws_active,ws_sessions,h3_active")
	var (
		maxUsed, denied0, denied1 float64
		first                     = true
		healthErr                 int
		statuses                  = map[string]int{}
	)
	hc := &http.Client{Timeout: 3 * time.Second}
	tick := time.NewTicker(time.Second)
	for loop := true; loop; {
		select {
		case <-ctx.Done():
			loop = false
		case <-tick.C:
		}
		resp, err := hc.Get("http://" + *host + ":9001/api/v1/health")
		if err != nil {
			healthErr++
			continue
		}
		var h webHealth
		_ = json.NewDecoder(resp.Body).Decode(&h)
		_ = resp.Body.Close()
		web := h.Services["web"]
		m := web.Metrics
		used, den := m["web_input_budget_used_bytes"], m["web_input_budget_denied_total"]
		if first {
			denied0, first = den, false
		}
		denied1 = den
		maxUsed = max(maxUsed, used)
		statuses[web.Status]++
		_, _ = fmt.Fprintf(w, "%.0f,%s,%.0f,%.0f,%.0f,%d,%d,%d,%d\n", time.Since(start).Seconds(), web.Status, used, den,
			m["web_connections_active"], h1c.Active.Load(), wsc.Active.Load(), wsc.Sessions.Load(), h3c.Active.Load())
		_ = w.Flush()
	}
	tick.Stop()
	wg.Wait()
	_ = w.Flush()
	_ = f.Close()

	sum := map[string]any{
		"target": *host, "ip": ip, "h3_ip": h3IP, "start": start.UTC().Format(time.RFC3339), "end": time.Now().UTC().Format(time.RFC3339),
		"duration_s": time.Since(start).Seconds(), "h1_workers": *nH1, "ws_workers": *nWS, "h3_workers": *nH3,
		"h1_head_bytes": *head, "ws_msg_bytes": *wsMsg, "h3_streams": *h3Streams, "h3_declared": *h3Decl, "h3_sent": *h3Sent,
		"h1": h1c.snapshot(), "ws": wsc.snapshot(), "h3": h3c.snapshot(),
		"budget_used_max_bytes": maxUsed, "budget_denied_start": denied0, "budget_denied_end": denied1,
		"budget_denied_delta": denied1 - denied0, "health_errors": healthErr, "web_status_samples": statuses,
	}
	b, _ := json.MarshalIndent(sum, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "summary.json"), b, 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
