#!/bin/sh
# Prepara a rede para a captura (spec 016 RF-01..RF-04, ADRs 0011 e 0038).
# Executado pela unit finger-sniffer-net.service (oneshot) antes de todos os serviços.
# Nunca falha por um offload que o driver não deixa mudar: registra e segue; o estado
# efetivo vai para /run/finger-sniffer/net-status.json, lido pelo health.
# O espelho não cria nem muda regra de firewall: só lê o ruleset para saber se há NAT nas portas dele.
set -u

# ens192 (vmxnet3) no finger-01 (ADR 0038)
IFACE="${FS_CAPTURE_IFACE:-ens192}"
# Os caminhos aceitam override para o teste (deploy/net_test.go); a unit usa os padrões.
SYSCTL_FILE="${FS_NET_SYSCTL_FILE:-/finger-sniffer/deploy/sysctl/90-finger-sniffer.conf}"
STATUS_FILE="${FS_NET_STATUS_FILE:-/run/finger-sniffer/net-status.json}"
STATUS_DIR="$(dirname "$STATUS_FILE")"
# tx-udp-segmentation (GSO de UDP no driver) pela ADR 0019: o QUIC sai datagrama a datagrama, como no fio.
OFFLOADS="gro rx-gro-hw lro tso gso tx-checksumming rx-udp-gro-forwarding tx-udp-segmentation"

# mirror_ports: portas do espelho, uma por linha (web TCP e UDP, raw, dns 53 e API), do env da unit.
mirror_ports() {
	{
		echo "${FS_WEB_TCP_PORTS:-8080,8443}"
		echo "${FS_WEB_UDP_PORTS:-8443}"
		echo "${FS_RAW_PORTS:-7:echo,21:banner,22:banner,25:banner,110:banner,143:banner,587:banner,993:tls-banner}" |
			tr ',' '\n' | cut -d: -f1
		echo 53
		echo "${FS_API_HTTPS_PORT:-9000}"
		echo "${FS_API_HTTP_PORT:-9001}"
	} | tr ', ' '\n\n' | grep -E '^[0-9]+$' | sort -un
}

# nat_rules: regras de NAT/redirecionamento do nft e, se existir, do iptables-save -t nat (uma por linha).
nat_rules() {
	nft list ruleset 2>/dev/null | grep -E '(^|[[:space:]])(dnat|snat|redirect|masquerade|tproxy)([[:space:];]|$)'
	if command -v iptables-save >/dev/null 2>&1; then
		iptables-save -t nat 2>/dev/null | grep -E '^(\[[0-9]+:[0-9]+\] )?-A .*-j (DNAT|SNAT|REDIRECT|MASQUERADE|TPROXY)'
	fi
	if command -v ip6tables-save >/dev/null 2>&1; then
		ip6tables-save -t nat 2>/dev/null | grep -E '^(\[[0-9]+:[0-9]+\] )?-A .*-j (DNAT|SNAT|REDIRECT|MASQUERADE|TPROXY)'
	fi
	return 0
}

# nat_hits <portas separadas por vírgula>: lê regras de NAT na entrada e imprime as que citam porta do espelho.
# Porta citada: valor depois de dport/sport/--dport(s)/--sport(s)/--to-ports/to (número, faixa ou conjunto) ou
# ":<porta>" depois de um endereço; endereços IPv4/IPv6, contadores e textos entre aspas não contam.
nat_hits() {
	awk -v ports="$1" '
	BEGIN { n = split(ports, a, ","); for (i = 1; i <= n; i++) P[a[i] + 0] = 1 }
	function cites(v,   ab, m, k, i) {
		m = split(v, k, ",")
		for (i = 1; i <= m; i++) {
			if (k[i] ~ /^[0-9]+-[0-9]+$/) {
				split(k[i], ab, "-")
				for (p in P) if (p + 0 >= ab[1] + 0 && p + 0 <= ab[2] + 0) return 1
			} else if (k[i] ~ /^[0-9]+$/ && ((k[i] + 0) in P)) return 1
		}
		return 0
	}
	{
		l = $0
		gsub(/"[^"]*"/, "", l)
		gsub(/\[[0-9]+:[0-9]+\]/, "", l)
		gsub(/packets [0-9]+ bytes [0-9]+/, "", l)
		gsub(/\[[0-9a-fA-F:.]+\]/, "IP", l)
		gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/, "IP", l)
		gsub(/\{[ ]*/, "", l); gsub(/[ ]*\}/, "", l); gsub(/,[ ]+/, ",", l); gsub(/;/, " ", l)
		t = split(l, w, /[ \t]+/)
		hit = 0
		for (i = 1; i <= t && !hit; i++) {
			if (w[i] ~ /^(dport|sport|--dport|--dports|--sport|--sports|--to-ports|--to-port|to)$/) {
				j = i + 1
				if (w[j] == "!=" || w[j] == "==" || w[j] == "!") j++
				if (cites(w[j])) hit = 1
			}
			c = gsub(/:/, ":", w[i])
			if (c == 1 && w[i] ~ /^(IP)?:[0-9]+(-[0-9]+)?$/) {
				v = w[i]; sub(/^(IP)?:/, "", v)
				if (cites(v)) hit = 1
			}
		}
		if (hit) print $0
	}'
}

mkdir -p "$STATUS_DIR"

# 1. Offloads: desliga um por um (alguns são [fixed] conforme o driver).
for o in $OFFLOADS; do
	if ! ethtool -K "$IFACE" "$o" off 2>/dev/null; then
		echo "aviso: não foi possível desligar $o em $IFACE"
	fi
done

# 2. sysctl da pilha TCP
if [ -f "$SYSCTL_FILE" ]; then
	sysctl -q -p "$SYSCTL_FILE" || echo "aviso: falha ao aplicar $SYSCTL_FILE"
fi

# 3. Estado efetivo para o health
features=$(ethtool -k "$IFACE" 2>/dev/null)
json_offloads=""
for f in generic-receive-offload rx-gro-hw large-receive-offload tcp-segmentation-offload \
	generic-segmentation-offload tx-checksumming rx-udp-gro-forwarding tx-udp-segmentation; do
	# sub-features (tx-udp-segmentation, por exemplo) podem vir indentadas conforme o driver; recurso que o driver
	# não lista fica unknown, e o fixo ([fixed]) fica com o valor que o ethtool mostra
	v=$(echo "$features" | awk -F': ' -v k="$f" '{sub(/^[ \t]+/, "", $1)} $1==k {split($2,a," "); print a[1]; exit}')
	case "$v" in on | off) ;; *) v=unknown ;; esac
	[ -n "$json_offloads" ] && json_offloads="$json_offloads,"
	json_offloads="$json_offloads\"$f\":\"$v\""
done

aggregating=false
for f in generic-receive-offload rx-gro-hw large-receive-offload; do
	echo "$features" | grep -Eq "^[[:space:]]*$f: on" && aggregating=true
done

# conntrack e nftables são tolerados (ADR 0038 item 7): ficam no estado, informativos; só NAT nas portas do espelho
# conta como problema
nft_rules=$(nft list ruleset 2>/dev/null | grep -c . || true)
conntrack=false
lsmod 2>/dev/null | grep -q '^nf_conntrack ' && conntrack=true
nat_hit_lines=$(nat_rules | nat_hits "$(mirror_ports | paste -sd, -)")
nat_on_mirror=false
[ -n "$nat_hit_lines" ] && nat_on_mirror=true
mtu=$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null || echo 0)

cat >"$STATUS_FILE" <<JSON
{"iface":"$IFACE","mtu":$mtu,"kernel":"$(uname -r)","offloads":{$json_offloads},"aggregating_offload":$aggregating,"nft_ruleset_lines":${nft_rules:-0},"conntrack_loaded":$conntrack,"nat_on_mirror_ports":$nat_on_mirror,"applied_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
chmod 0644 "$STATUS_FILE"

[ "$aggregating" = true ] && echo "aviso: offload de agregação ainda ligado em $IFACE"
if [ "$nat_on_mirror" = true ]; then
	echo "aviso: regra de NAT/redirecionamento cita porta do espelho (ADR 0038 item 7):"
	printf '%s\n' "$nat_hit_lines" | sed 's/^/  /'
fi
cat "$STATUS_FILE"
exit 0
