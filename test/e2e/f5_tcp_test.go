//go:build e2e

package e2e

// Caso 11 da matriz da spec 017 no caminho direto (task 066): impressão TCP e relógio. N=3 execuções do mesmo
// cliente (curl do sistema e Go net/http) a partir desta máquina, cada uma uma conexão HTTPS com duas requisições
// (a primeira com delay_head, para a conexão durar o bastante para estimar o relógio TSval). Critério (spec 017,
// ADR 0022): consistência entre execuções — JA4T, assinatura p0f, TTL observado/inicial e saltos iguais; Hz do
// TSval estável; grupo de relógio coerente; RTT do handshake × RTT da aplicação (spec 013 RF-04, RF-07, RF-10,
// RF-11).

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

const case11Runs = 3

// tcpRun é o que o caso 11 compara de cada conexão.
type tcpRun struct {
	connID     string
	ja4t, p0f  string
	osGuess    string
	ttl        int
	ttlInitial int
	hops       int
	rttHS      float64
	rttApp     *float64
	hz         *float64
	tsInitial  *float64
	group      string
}

type case11Client struct {
	name string
	run  func(ctx context.Context, id string) error
}

func case11URLs(id string) []string {
	base := "https://" + probeHost(id) + "/p/" + id + "/"
	return []string{base + "r?delay_head=300", base + "?second=1"}
}

func curlCase11(ctx context.Context, id string) error {
	args := []string{
		"-4", "-s", "--http1.1", "--resolve", probeHost(id) + ":443:" + vps4, "-o", "/dev/null", "-o", "/dev/null",
		"-w", "%{http_code}\n", "-A", "fs-e2e-case11-curl",
	}
	args = append(args, case11URLs(id)...)
	out, err := exec.CommandContext(ctx, "/usr/bin/curl", args...).CombinedOutput() //nolint:gosec // argumentos do teste
	if err != nil || strings.Count(string(out), "200") != 2 {
		return fmt.Errorf("curl: %v %q", err, out)
	}
	return nil
}

func goCase11(ctx context.Context, id string) error {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", vps4+":443")
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		// HTTP/1.1 só: as duas requisições na mesma conexão TCP
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	for _, u := range case11URLs(id) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "fs-e2e-case11-go")
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %d", u, resp.StatusCode)
		}
	}
	return nil
}

func TestCase11TCPConsistency(t *testing.T) {
	t.Parallel()
	for _, cl := range []case11Client{{"curl", curlCase11}, {"go", goCase11}} {
		t.Run(cl.name, func(t *testing.T) {
			t.Parallel()
			var runs []tcpRun
			for i := range case11Runs {
				id := newID(t)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := cl.run(ctx, id)
				cancel()
				if err != nil {
					t.Fatalf("execução %d: %v", i+1, err)
				}
				p := waitProbe(t, id, atLeast(1, 443))
				cs := p.conns(443)
				if len(cs) != 1 || len(cs[0].HTTP) != 2 {
					t.Fatalf("execução %d: %d conexões (esperado 1 com 2 requisições)", i+1, len(cs))
				}
				requireConnFields(t, cs, "11")
				runs = append(runs, tcpRunOf(t, cs[0].ConnID))
				time.Sleep(time.Second)
			}
			for i, r := range runs {
				t.Logf("execução %d %s: ja4t=%s p0f=%s os=%s ttl=%d/%d hops=%d rtt_hs=%.3f rtt_app=%s hz=%s ts_initial=%s grupo=%s",
					i+1, r.connID, r.ja4t, r.p0f, r.osGuess, r.ttl, r.ttlInitial, r.hops, r.rttHS, fmtF(r.rttApp), fmtF(r.hz),
					fmtF(r.tsInitial), r.group)
			}
			checkCase11(t, runs)
		})
	}
}

func tcpRunOf(t *testing.T, connID string) tcpRun {
	t.Helper()
	m := connRaw(t, connID)
	ip, _ := m["ip"].(map[string]any)
	tc, _ := m["tcp"].(map[string]any)
	str := func(v any) string { s, _ := v.(string); return s }
	num := func(v any) int { f, _ := v.(float64); return int(f) }
	fp := func(v any) *float64 {
		if f, ok := v.(float64); ok {
			return &f
		}
		return nil
	}
	r := tcpRun{
		connID: connID, ja4t: str(tc["ja4t"]), p0f: str(tc["p0f"]), osGuess: str(tc["os_guess"]),
		ttl: num(ip["ttl"]), ttlInitial: num(ip["ttl_initial"]), hops: num(ip["hops"]),
		rttApp: fp(tc["rtt_app_ms"]), hz: fp(tc["ts_clock_hz"]), tsInitial: fp(tc["ts_initial"]), group: str(tc["ts_clock_group"]),
	}
	if v := fp(tc["rtt_handshake_ms"]); v != nil {
		r.rttHS = *v
	}
	return r
}

func checkCase11(t *testing.T, runs []tcpRun) {
	t.Helper()
	first := runs[0]
	for i, r := range runs[1:] {
		n := i + 2
		if r.ja4t != first.ja4t {
			t.Errorf("execução %d: ja4t %s, a 1ª teve %s", n, r.ja4t, first.ja4t)
		}
		if r.p0f != first.p0f {
			t.Errorf("execução %d: p0f %s, a 1ª teve %s", n, r.p0f, first.p0f)
		}
		if r.ttl != first.ttl || r.ttlInitial != first.ttlInitial || r.hops != first.hops {
			t.Errorf("execução %d: ttl=%d/%d hops=%d, a 1ª teve %d/%d hops=%d", n, r.ttl, r.ttlInitial, r.hops,
				first.ttl, first.ttlInitial, first.hops)
		}
	}
	for i, r := range runs {
		if r.ttlInitial < r.ttl || r.hops != r.ttlInitial-r.ttl {
			t.Errorf("execução %d: ttl=%d ttl_initial=%d hops=%d incoerentes", i+1, r.ttl, r.ttlInitial, r.hops)
		}
		if r.rttHS <= 0 {
			t.Errorf("execução %d: rtt_handshake_ms = %v", i+1, r.rttHS)
		}
		if r.hz == nil || r.tsInitial == nil || r.group == "" {
			t.Errorf("execução %d: relógio TSval sem estimativa (hz=%s ts_initial=%s grupo=%q)", i+1, fmtF(r.hz), fmtF(r.tsInitial), r.group)
		}
	}
	// RTT do handshake estável entre execuções (mesmo caminho): a maior não passa de 3× a menor + 5 ms
	lo, hi := math.Inf(1), 0.0
	for _, r := range runs {
		lo, hi = math.Min(lo, r.rttHS), math.Max(hi, r.rttHS)
	}
	if hi > 3*lo+5 {
		t.Errorf("RTT do handshake instável entre execuções: %.3f–%.3f ms", lo, hi)
	}

	// Hz do TSval: o mesmo valor nominal (±10%) em todas as execuções
	t.Run("ts_clock_hz", func(t *testing.T) {
		var base float64
		for i, r := range runs {
			if r.hz == nil {
				t.Fatalf("execução %d sem ts_clock_hz", i+1)
			}
			if base == 0 {
				base = *r.hz
			}
			if math.Abs(*r.hz-base) > base*0.1 {
				t.Errorf("execução %d: ts_clock_hz %.2f, a 1ª teve %.2f", i+1, *r.hz, base)
			}
		}
	})

	// Grupo de relógio: com o deslocamento do TSval por conexão (macOS, net.inet.tcp.randomize_timestamps=1,
	// RFC 7323 §5.4) cada conexão começa num ponto aleatório e o store não pode juntá-las — cada uma tem o seu
	// grupo; sem ele (Linux usa o mesmo deslocamento para o mesmo par de IPs) todas caem no mesmo grupo.
	t.Run("ts_clock_group", func(t *testing.T) {
		groups := map[string]int{}
		for _, r := range runs {
			groups[r.group]++
		}
		if randomizedTS(t) {
			if len(groups) != len(runs) {
				t.Errorf("TSval com deslocamento aleatório por conexão, mas o store juntou execuções num grupo: %v", groups)
			}
			t.Logf("TSval com deslocamento aleatório por conexão nesta máquina: %d grupos distintos, como esperado", len(groups))
			return
		}
		if len(groups) != 1 {
			t.Errorf("mesmo host com relógio TSval contínuo em %d grupos: %v", len(groups), groups)
		}
	})

	// RTT da aplicação (spec 013 RF-11): no caminho direto, perto do RTT do handshake
	t.Run("rtt_app", func(t *testing.T) {
		for i, r := range runs {
			if r.rttApp == nil {
				t.Errorf("execução %d: tcp.rtt_app_ms = null (spec 013 RF-11)", i+1)
				continue
			}
			if *r.rttApp <= 0 || *r.rttApp > 3*r.rttHS+20 {
				t.Errorf("execução %d: rtt_app_ms %.3f × rtt_handshake_ms %.3f (caminho direto)", i+1, *r.rttApp, r.rttHS)
			}
		}
	})
}

// randomizedTS diz se esta máquina desloca o TSval por conexão.
func randomizedTS(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return false
	}
	out, err := exec.Command("sysctl", "-n", "net.inet.tcp.randomize_timestamps").Output()
	if err != nil {
		t.Logf("sysctl net.inet.tcp.randomize_timestamps: %v (assumindo deslocamento aleatório, padrão do macOS)", err)
		return true
	}
	return strings.TrimSpace(string(out)) != "0"
}

func fmtF(f *float64) string {
	if f == nil {
		return "null"
	}
	return fmt.Sprintf("%.2f", *f)
}
