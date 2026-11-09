package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ethtoolK imita a saída de `ethtool -k` de uma virtio: alguns offloads ligados, sub-features indentadas e
// tx-udp-segmentation [fixed] (como na vps602).
const ethtoolK = `Features for eth0:
rx-checksumming: on [fixed]
tx-checksumming: off
	tx-checksum-ipv4: off [fixed]
tcp-segmentation-offload: off
	tx-tcp-segmentation: off
generic-segmentation-offload: off
generic-receive-offload: off
large-receive-offload: off [fixed]
rx-gro-hw: off [fixed]
tx-udp-segmentation: off [fixed]
rx-udp-gro-forwarding: off
`

// fakeNetTools cria ethtool, sysctl, nft e lsmod falsos que registram as chamadas em calls.log.
func fakeNetTools(t *testing.T, features string) (bin, calls string) {
	t.Helper()
	bin = t.TempDir()
	calls = filepath.Join(bin, "calls.log")
	featFile := filepath.Join(bin, "features.txt")
	writeFile(t, featFile, features, 0o644)
	scripts := map[string]string{
		"ethtool": `echo "ethtool $*" >>"` + calls + `"
[ "$1" = -k ] && cat "` + featFile + `"
exit 0`,
		"sysctl": `echo "sysctl $*" >>"` + calls + `"`,
		"nft":    `exit 0`,
		"lsmod":  `echo "Module Size Used by"`,
	}
	for name, body := range scripts {
		writeFile(t, filepath.Join(bin, name), "#!/bin/sh\n"+body+"\n", 0o755)
	}
	return bin, calls
}

// runNet executa deploy/net/finger-sniffer-net.sh com as ferramentas falsas e devolve o net-status.json.
func runNet(t *testing.T, features string) (map[string]any, string) {
	t.Helper()
	bin, calls := fakeNetTools(t, features)
	status := filepath.Join(t.TempDir(), "run", "net-status.json")
	cmd := exec.Command("sh", "net/finger-sniffer-net.sh")
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FS_CAPTURE_IFACE=eth0",
		"FS_NET_STATUS_FILE="+status,
		"FS_NET_SYSCTL_FILE=sysctl/90-finger-sniffer.conf",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("finger-sniffer-net.sh: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("net-status.json inválido: %v\n%s", err, raw)
	}
	log, _ := os.ReadFile(calls)
	return st, string(log)
}

func TestNetDisablesOffloadsIncludingUDPSegmentation(t *testing.T) {
	_, calls := runNet(t, ethtoolK)
	for _, o := range []string{
		"gro", "rx-gro-hw", "lro", "tso", "gso", "tx-checksumming", "rx-udp-gro-forwarding",
		"tx-udp-segmentation",
	} {
		if !strings.Contains(calls, "ethtool -K eth0 "+o+" off\n") {
			t.Errorf("offload %s não desligado; chamadas:\n%s", o, calls)
		}
	}
	if !strings.Contains(calls, "sysctl -q -p sysctl/90-finger-sniffer.conf") {
		t.Errorf("sysctl não aplicado; chamadas:\n%s", calls)
	}
}

func TestNetStatusReportsUDPSegmentation(t *testing.T) {
	st, _ := runNet(t, ethtoolK)
	off, ok := st["offloads"].(map[string]any)
	if !ok {
		t.Fatalf("sem offloads: %v", st)
	}
	want := []string{
		"generic-receive-offload", "rx-gro-hw", "large-receive-offload", "tcp-segmentation-offload",
		"generic-segmentation-offload", "tx-checksumming", "rx-udp-gro-forwarding", "tx-udp-segmentation",
	}
	for _, k := range want {
		if off[k] != "off" {
			t.Errorf("offloads[%s] = %v, quer off", k, off[k])
		}
	}
	if st["aggregating_offload"] != false || st["conntrack_loaded"] != false || st["nft_ruleset_lines"] != float64(0) {
		t.Errorf("estado inesperado: %v", st)
	}
}

func TestNetStatusIndentedFeatureAndAggregation(t *testing.T) {
	// driver que lista tx-udp-segmentation indentado e deixa o GRO ligado
	features := strings.Replace(ethtoolK, "tx-udp-segmentation: off [fixed]", "\ttx-udp-segmentation: on", 1)
	features = strings.Replace(features, "generic-receive-offload: off", "generic-receive-offload: on", 1)
	st, _ := runNet(t, features)
	off := st["offloads"].(map[string]any)
	if off["tx-udp-segmentation"] != "on" {
		t.Errorf("tx-udp-segmentation = %v, quer on", off["tx-udp-segmentation"])
	}
	if st["aggregating_offload"] != true {
		t.Errorf("GRO ligado deveria marcar aggregating_offload: %v", st)
	}
}
