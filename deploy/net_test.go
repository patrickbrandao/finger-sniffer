package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ethtoolK imita a saída de `ethtool -k` da vmxnet3 do finger-01 (ens192) depois do script: sub-features
// indentadas, recursos [fixed] e tx-udp-segmentation fixo em off. A vmxnet3 não lista tx-checksumming fixo, mas
// lista todos os oito recursos que o health lê.
const ethtoolK = `Features for ens192:
rx-checksumming: on
tx-checksumming: off
	tx-checksum-ipv4: off [fixed]
	tx-checksum-ip-generic: off
scatter-gather: on
tcp-segmentation-offload: off
	tx-tcp-segmentation: off
generic-segmentation-offload: off
generic-receive-offload: off
large-receive-offload: off
rx-gro-hw: off [fixed]
tx-udp-segmentation: off [fixed]
rx-gro-list: off
rx-udp-gro-forwarding: off
`

// dockerRuleset é um ruleset no formato do iptables-nft do Docker publicando só as portas do traefik
// (80/443/8081 TCP e 443 UDP) e mascarando a bridge: não toca as portas do espelho. Contadores, IPv6 com "::7" e
// comentários com números de porta do espelho não podem contar.
const dockerRuleset = `table ip nat {
	chain DOCKER {
		iifname "br-net-public" counter packets 53 bytes 9000 return
		iifname != "br-net-public" meta l4proto tcp ip daddr 0.0.0.0/0 tcp dport 80 counter packets 7 bytes 22 dnat to 10.249.0.2:80
		iifname != "br-net-public" meta l4proto tcp tcp dport 443 counter packets 0 bytes 0 dnat to 10.249.0.2:443
		iifname != "br-net-public" meta l4proto tcp tcp dport 8081 counter packets 0 bytes 0 dnat to 10.249.0.2:8081
		iifname != "br-net-public" meta l4proto udp udp dport 443 counter packets 0 bytes 0 dnat to 10.249.0.2:443 comment "nao 8443"
	}
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.249.0.0/16 oifname != "br-net-public" counter packets 25 bytes 1500 masquerade
	}
}
table ip6 nat {
	chain DOCKER {
		iifname != "br-net-public" ip6 daddr 2804:231c:e500:cafe::7 tcp dport 443 dnat to [fd00::53]:443
	}
}
`

// netOpts são as entradas falsas do script de rede.
type netOpts struct {
	features string
	ruleset  string // saída do nft list ruleset
	iptNAT   string // saída do iptables-save -t nat ("" = sem iptables-save)
	env      []string
}

// fakeNetTools cria ethtool, sysctl, nft, iptables-save e lsmod falsos que registram as chamadas em calls.log.
func fakeNetTools(t *testing.T, o netOpts) (bin, calls string) {
	t.Helper()
	bin = t.TempDir()
	calls = filepath.Join(bin, "calls.log")
	featFile := filepath.Join(bin, "features.txt")
	rulesFile := filepath.Join(bin, "ruleset.txt")
	writeFile(t, featFile, o.features, 0o644)
	writeFile(t, rulesFile, o.ruleset, 0o644)
	scripts := map[string]string{
		"ethtool": `echo "ethtool $*" >>"` + calls + `"
[ "$1" = -k ] && cat "` + featFile + `"
exit 0`,
		"sysctl": `echo "sysctl $*" >>"` + calls + `"`,
		// o script só pode listar: qualquer outra subcomando do nft é registrada e reprova o teste
		"nft": `echo "nft $*" >>"` + calls + `"
[ "$*" = "list ruleset" ] && cat "` + rulesFile + `"
exit 0`,
		"lsmod": `echo "Module Size Used by"`,
	}
	if o.iptNAT != "" {
		iptFile := filepath.Join(bin, "ipt.txt")
		writeFile(t, iptFile, o.iptNAT, 0o644)
		scripts["iptables-save"] = `echo "iptables-save $*" >>"` + calls + `"
cat "` + iptFile + `"`
	}
	for name, body := range scripts {
		writeFile(t, filepath.Join(bin, name), "#!/bin/sh\n"+body+"\n", 0o755)
	}
	return bin, calls
}

// runNetWith executa deploy/net/finger-sniffer-net.sh com as ferramentas falsas e devolve o net-status.json, as
// chamadas registradas e a saída.
func runNetWith(t *testing.T, o netOpts) (st map[string]any, calls, out string) {
	t.Helper()
	bin, callsFile := fakeNetTools(t, o)
	status := filepath.Join(t.TempDir(), "run", "net-status.json")
	cmd := exec.Command("sh", "net/finger-sniffer-net.sh")
	// sem herdar FS_* de quem roda o teste; sem iptables-save do sistema (PATH só com o bin falso + utilitários)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "FS_") && !strings.HasPrefix(kv, "PATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env,
		"PATH="+bin+string(os.PathListSeparator)+"/usr/bin:/bin",
		"FS_NET_STATUS_FILE="+status,
		"FS_NET_SYSCTL_FILE=sysctl/90-finger-sniffer.conf",
	)
	cmd.Env = append(cmd.Env, o.env...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("finger-sniffer-net.sh: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("net-status.json inválido: %v\n%s", err, raw)
	}
	log, _ := os.ReadFile(callsFile)
	for _, line := range strings.Split(string(log), "\n") {
		if strings.HasPrefix(line, "nft ") && line != "nft list ruleset" {
			t.Errorf("o script mudou o firewall: %q", line)
		}
	}
	return st, string(log), string(b)
}

// runNet: interface padrão (ens192, sem FS_CAPTURE_IFACE) e ruleset vazio.
func runNet(t *testing.T, features string) (map[string]any, string) {
	t.Helper()
	st, calls, _ := runNetWith(t, netOpts{features: features})
	return st, calls
}

func TestNetDisablesOffloadsIncludingUDPSegmentation(t *testing.T) {
	st, calls := runNet(t, ethtoolK)
	for _, o := range []string{
		"gro", "rx-gro-hw", "lro", "tso", "gso", "tx-checksumming", "rx-udp-gro-forwarding",
		"tx-udp-segmentation",
	} {
		// ens192 é o padrão sem FS_CAPTURE_IFACE (ADR 0038)
		if !strings.Contains(calls, "ethtool -K ens192 "+o+" off\n") {
			t.Errorf("offload %s não desligado; chamadas:\n%s", o, calls)
		}
	}
	if !strings.Contains(calls, "sysctl -q -p sysctl/90-finger-sniffer.conf") {
		t.Errorf("sysctl não aplicado; chamadas:\n%s", calls)
	}
	if st["iface"] != "ens192" {
		t.Errorf("iface = %v, quer ens192", st["iface"])
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
	if st["aggregating_offload"] != false || st["conntrack_loaded"] != false || st["nft_ruleset_lines"] != float64(0) ||
		st["nat_on_mirror_ports"] != false {
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

// Recurso que o driver não lista sai unknown (valores do contrato: on, off, unknown); o fixo ligado fica on.
func TestNetStatusUnknownAndFixedFeatures(t *testing.T) {
	features := strings.Replace(ethtoolK, "rx-udp-gro-forwarding: off\n", "", 1)
	features = strings.Replace(features, "rx-gro-hw: off [fixed]", "rx-gro-hw: on [fixed]", 1)
	st, _ := runNet(t, features)
	off := st["offloads"].(map[string]any)
	if off["rx-udp-gro-forwarding"] != "unknown" {
		t.Errorf("rx-udp-gro-forwarding = %v, quer unknown", off["rx-udp-gro-forwarding"])
	}
	if off["rx-gro-hw"] != "on" || st["aggregating_offload"] != true {
		t.Errorf("rx-gro-hw fixo ligado: offloads=%v aggregating=%v", off["rx-gro-hw"], st["aggregating_offload"])
	}
}

// ADR 0038 item 7: o ruleset do Docker que só toca 80/443/8081 não é NAT nas portas do espelho, e o nft com
// regras é só informativo (sem aviso).
func TestNetNATDockerRulesetIsNotMirror(t *testing.T) {
	st, _, out := runNetWith(t, netOpts{features: ethtoolK, ruleset: dockerRuleset})
	if st["nat_on_mirror_ports"] != false {
		t.Errorf("nat_on_mirror_ports = %v, quer false\n%s", st["nat_on_mirror_ports"], out)
	}
	if n, _ := st["nft_ruleset_lines"].(float64); n < 10 {
		t.Errorf("nft_ruleset_lines = %v, quer as linhas do ruleset", st["nft_ruleset_lines"])
	}
	if strings.Contains(out, "aviso: nftables") || strings.Contains(out, "aviso: regra de NAT") {
		t.Errorf("aviso indevido:\n%s", out)
	}
}

func TestNetNATOnMirrorPorts(t *testing.T) {
	cases := map[string]netOpts{
		"DNAT para 8443": {ruleset: dockerRuleset + `table ip filter2 {
	chain PRE {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 443 dnat to 170.247.40.86:8443
	}
}
`},
		"dport do espelho em conjunto": {ruleset: `table inet x {
	chain p {
		tcp dport { 22, 8080 } counter packets 0 bytes 0 dnat ip to 10.0.0.1
	}
}
`},
		"redirect para a 53":     {ruleset: "\t\tudp dport 5353 redirect to :53\n"},
		"faixa que cobre a 9000": {ruleset: "\t\ttcp dport 8990-9010 dnat to 10.0.0.1\n"},
		"raw do env": {
			ruleset: "\t\ttcp dport 2525 dnat to 10.0.0.1:2525\n",
			env:     []string{"FS_RAW_PORTS=2525:banner"},
		},
		"iptables-save DNAT na 9001": {iptNAT: `*nat
:PREROUTING ACCEPT [0:0]
[3:180] -A PREROUTING -p tcp -m tcp --dport 9001 -j DNAT --to-destination 10.249.0.2:80
COMMIT
`},
		"iptables-save multiport com 8443": {iptNAT: `*nat
-A PREROUTING -p udp -m multiport --dports 443,8443 -j REDIRECT --to-ports 4443
COMMIT
`},
	}
	for name, o := range cases {
		o.features = ethtoolK
		st, _, out := runNetWith(t, o)
		if st["nat_on_mirror_ports"] != true {
			t.Errorf("%s: nat_on_mirror_ports = %v, quer true\n%s", name, st["nat_on_mirror_ports"], out)
		}
		if !strings.Contains(out, "aviso: regra de NAT") {
			t.Errorf("%s: sem aviso com a regra\n%s", name, out)
		}
	}
}

// Sem regra de NAT: portas do espelho só em regra de filtro, iptables-save sem -A ou faixa fora do espelho.
func TestNetNATFalseWithoutNATOnMirror(t *testing.T) {
	cases := map[string]netOpts{
		"filtro aceitando 8443": {ruleset: "\t\ttcp dport 8443 accept\n"},
		"iptables-save vazio":   {iptNAT: "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n"},
		"faixa fora":            {ruleset: "\t\ttcp dport 10000-20000 dnat to 10.0.0.1\n"},
		"web em outra porta pelo env": {
			ruleset: "\t\ttcp dport 8443 dnat to 10.0.0.1\n",
			env:     []string{"FS_WEB_TCP_PORTS=8080", "FS_WEB_UDP_PORTS=8080"},
		},
	}
	for name, o := range cases {
		o.features = ethtoolK
		st, _, out := runNetWith(t, o)
		if st["nat_on_mirror_ports"] != false {
			t.Errorf("%s: nat_on_mirror_ports = %v, quer false\n%s", name, st["nat_on_mirror_ports"], out)
		}
	}
}
