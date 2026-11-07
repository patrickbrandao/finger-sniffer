#!/bin/sh
# Prepara a rede para a captura (spec 016 RF-01..RF-04, ADR 0011).
# Executado pela unit finger-sniffer-net.service (oneshot) antes de todos os serviços.
# Nunca falha por um offload que o driver não deixa mudar: registra e segue; o estado
# efetivo vai para /run/finger-sniffer/net-status.json, lido pelo health.
set -u

IFACE="${FS_CAPTURE_IFACE:-eth0}"
SYSCTL_FILE="/finger-sniffer/deploy/sysctl/90-finger-sniffer.conf"
STATUS_DIR="/run/finger-sniffer"
STATUS_FILE="$STATUS_DIR/net-status.json"
OFFLOADS="gro rx-gro-hw lro tso gso tx-checksumming rx-udp-gro-forwarding"

mkdir -p "$STATUS_DIR"

# 1. Offloads: desliga um por um (alguns são [fixed] em virtio).
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
	generic-segmentation-offload tx-checksumming rx-udp-gro-forwarding; do
	v=$(echo "$features" | awk -F': ' -v k="$f" '$1==k {split($2,a," "); print a[1]}')
	[ -n "$json_offloads" ] && json_offloads="$json_offloads,"
	json_offloads="$json_offloads\"$f\":\"${v:-unknown}\""
done

aggregating=false
for f in generic-receive-offload rx-gro-hw large-receive-offload; do
	echo "$features" | grep -q "^$f: on" && aggregating=true
done

nft_rules=$(nft list ruleset 2>/dev/null | grep -c . || true)
conntrack=false
lsmod | grep -q '^nf_conntrack ' && conntrack=true
mtu=$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null || echo 0)

cat >"$STATUS_FILE" <<JSON
{"iface":"$IFACE","mtu":$mtu,"kernel":"$(uname -r)","offloads":{$json_offloads},"aggregating_offload":$aggregating,"nft_ruleset_lines":${nft_rules:-0},"conntrack_loaded":$conntrack,"applied_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
chmod 0644 "$STATUS_FILE"

[ "$aggregating" = true ] && echo "aviso: offload de agregação ainda ligado em $IFACE"
[ "${nft_rules:-0}" -gt 0 ] && echo "aviso: nftables tem regras (ADR 0011 pede sem firewall com estado)"
[ "$conntrack" = true ] && echo "aviso: nf_conntrack carregado"
cat "$STATUS_FILE"
exit 0
