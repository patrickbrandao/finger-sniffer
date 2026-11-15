//go:build e2e

package e2e

// MSS/MTU implícito e tipo da origem no caminho direto (spec 013 RF-05a/RF-06a, ADR 0031, task 197): uma conexão
// curl ao servidor por família traz tcp.syn_mss não nulo, mtu_implied = syn_mss + 40 (IPv4) ou + 60 (IPv6),
// mss_reduction = 1460/1440 − syn_mss e ip.src_kind = global (esta máquina sai por um endereço público). O
// syn_mss é conferido com o ["mss",N] de tcp.syn.options e, com tshark no PATH, com tcp.options.mss_val do pcap
// da própria conexão.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSynMSSDirect(t *testing.T) {
	t.Parallel()
	for _, fam := range []string{"4", "6"} {
		t.Run("ipv"+fam, func(t *testing.T) {
			t.Parallel()
			id := newID(t)
			addr := vps4
			if fam == "6" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", vpsHost)
				cancel()
				if err != nil || len(ips) == 0 {
					t.Skipf("sem AAAA para %s: %v", vpsHost, err)
				}
				addr = "[" + ips[0].String() + "]"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "/usr/bin/curl", "-"+fam, "-s", "--http1.1", //nolint:gosec // argumentos do teste
				"--resolve", probeHost(id)+onTLS+":"+addr, "-o", "/dev/null", "-w", "%{http_code}",
				"-A", "fs-e2e-mss", "https://"+probeHost(id)+onTLS+"/p/"+id+"/").CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "200" {
				var ee *exec.ExitError
				// curl 7 = não conectou: esta máquina sem rota IPv6 até o servidor
				if fam == "6" && errors.As(err, &ee) && ee.ExitCode() == 7 {
					t.Skipf("sem conectividade IPv6: %s", out)
				}
				t.Fatalf("curl -%s: %v %q", fam, err, out)
			}
			p := waitProbe(t, id, atLeast(1, portTLS))
			cs := p.conns(portTLS)
			if len(cs) != 1 {
				t.Fatalf("%d conexões na %d (esperado 1)", len(cs), portTLS)
			}
			m := connRaw(t, cs[0].ConnID)
			ip, _ := m["ip"].(map[string]any)
			tc, _ := m["tcp"].(map[string]any)
			if ip == nil || tc == nil {
				t.Fatalf("registro sem ip/tcp: %v", m)
			}
			wantFam := 4
			hdr, ref := 40, 1460
			if fam == "6" {
				wantFam, hdr, ref = 6, 60, 1440
			}
			if f, _ := m["family"].(float64); int(f) != wantFam {
				t.Errorf("family = %v, quer %d", m["family"], wantFam)
			}
			if ip["src_kind"] != "global" {
				t.Errorf("ip.src_kind = %v, quer global", ip["src_kind"])
			}
			mss, ok := tc["syn_mss"].(float64)
			if !ok || mss <= 0 {
				t.Fatalf("tcp.syn_mss = %v, quer não nulo", tc["syn_mss"])
			}
			n := int(mss)
			if v, _ := tc["mtu_implied"].(float64); int(v) != n+hdr {
				t.Errorf("mtu_implied = %v, quer syn_mss+%d = %d", tc["mtu_implied"], hdr, n+hdr)
			}
			if v, ok := tc["mss_reduction"].(float64); !ok || int(v) != ref-n {
				t.Errorf("mss_reduction = %v, quer %d−syn_mss = %d", tc["mss_reduction"], ref, ref-n)
			}
			if got := synOptMSS(tc); got != n {
				t.Errorf("syn_mss %d diferente do [\"mss\",N] de tcp.syn.options (%d)", n, got)
			}
			t.Logf("ipv%s %s: syn_mss=%d mtu_implied=%v mss_reduction=%v src_kind=%v", fam, cs[0].ConnID, n,
				tc["mtu_implied"], tc["mss_reduction"], ip["src_kind"])

			// conferência com o tshark sobre o pcap da própria conexão
			ts, err := exec.LookPath("tshark")
			if err != nil {
				t.Log("tshark fora do PATH: conferência do pcap pulada")
				return
			}
			path := filepath.Join(t.TempDir(), "c.pcap")
			if err := os.WriteFile(path, pcapOf(t, cs[0].ConnID), 0o600); err != nil {
				t.Fatal(err)
			}
			raw, err := exec.Command(ts, "-r", path, "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0", //nolint:gosec // argumentos do teste
				"-T", "fields", "-e", "tcp.options.mss_val").Output()
			if err != nil {
				t.Fatalf("tshark: %v", err)
			}
			first, _, _ := bytes.Cut(bytes.TrimSpace(raw), []byte("\n"))
			if v, err := strconv.Atoi(string(first)); err != nil || v != n {
				t.Errorf("tshark tcp.options.mss_val = %q, syn_mss = %d", first, n)
			}
		})
	}
}

// synOptMSS devolve o N do primeiro ["mss",N] de tcp.syn.options (-1 sem a opção).
func synOptMSS(tc map[string]any) int {
	syn, _ := tc["syn"].(map[string]any)
	opts, _ := syn["options"].([]any)
	for _, o := range opts {
		if a, ok := o.([]any); ok && len(a) == 2 && a[0] == "mss" {
			if v, ok := a[1].(float64); ok {
				return int(v)
			}
		}
	}
	return -1
}
