#!/usr/bin/env bash
# Gera os golden pcaps (task 013) contra o servidor (finger-01, ADR 0038) e as saídas de referência de cada um.
#
# Roda no Mac (clientes macOS: curl, Go, Chrome, Firefox e sockets especiais) e usa o servidor (finger-01)
# (listener HTTP temporário na porta 7700) e como cliente Linux (curl de saída para um servidor externo,
# porque o tráfego da VPS para ela mesma passa pela loopback e não pela interface capturada). A captura é feita no servidor
# com tcpdump -s0; antes das saídas de referência os IPs públicos da máquina de teste viram endereços de
# documentação (anon.py). Saídas por pcap, geradas no servidor:
#   <nome>.tshark.json  tshark -T json com os campos IP/TCP e tcp.analysis.* (inclui ack_rtt)
#   <nome>.ja4.jsonl    ja4 -j da FoxIO (JA4T)
#   <nome>.p0f.txt      observações syn e syn+ack do p0f -r
# No fim (inclusive em erro) os listeners são removidos e a remoção é conferida.
#
# O caso retransmit-macos troca a qdisc raiz da $IFACE, a NIC única do host, que também leva os sites do humano
# (ADR 0038 item 9; task 357). Por isso ele só roda com FS_GOLDEN_NETEM=1, dado com o aval do humano, e só sobre a
# raiz padrão do kernel (handle 0:); a raiz só é apagada se ainda for a prio 1: que o próprio script pôs.
#
# Uso: test/golden/collect.sh                      (a partir de qualquer diretório; sem o caso de retransmissão)
#      FS_GOLDEN_NETEM=1 test/golden/collect.sh    (com o caso de retransmissão, só com o aval do humano)
set -euo pipefail
cd "$(dirname "$0")"

NETEM="${FS_GOLDEN_NETEM:-0}"
NETEM_TOUCHED=0 # 1 depois que netem_on tentou trocar a raiz (só então netem_off pode apagá-la)
VPS="${VPS_SSH:-root@finger-01.tmsoft.com.br}"
SSH_PORT="${VPS_PORT:-48022}"
IFACE="${FS_CAPTURE_IFACE:-ens192}" # interface capturada do finger-01 (ADR 0038)
HOST=finger-01.badblock.net.br
VPS4=170.247.40.86
VPS6=2804:231c:e500:cafe::86
PORT=7700
EXT=example.com
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
R=/tmp/fs-golden
OUT="${FS_GOLDEN_OUT:-pcaps}"
DOC4=198.51.100.10
DOC6=2001:db8::10
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
FIREFOX="${FIREFOX_BIN:-/Applications/Firefox.app/Contents/MacOS/firefox}"
LOCAL_TMP=$(mktemp -d)

remote() { ssh -p "$SSH_PORT" -o BatchMode=yes "$VPS" "$@" </dev/null; }
log() { echo "[golden] $*"; }

# root_qdisc: a linha da qdisc raiz da $IFACE (só leitura).
root_qdisc() { remote "tc qdisc show dev $IFACE root" | head -1; }

# netem_on: põe a prio 1: com o netem 30: como raiz, só se a raiz atual for a padrão do kernel (handle 0:, ex.: mq ou
# fq_codel); uma raiz configurada no host não é tocada. A perda vale só nos pacotes que saem da porta do listener
# (ssh e serviços não são afetados).
netem_on() {
	local cur
	cur=$(root_qdisc)
	if ! echo "$cur" | grep -qE '^qdisc [a-z_]+ 0: root'; then
		log "AVISO: a raiz da $IFACE não é a padrão do kernel (${cur:-desconhecida}); netem não ligado"
		return 1
	fi
	NETEM_TOUCHED=1
	remote "tc qdisc add dev $IFACE root handle 1: prio && \
		tc qdisc add dev $IFACE parent 1:3 handle 30: netem loss 8% && \
		tc filter add dev $IFACE protocol ip parent 1:0 prio 3 u32 match ip sport $PORT 0xffff flowid 1:3"
}

# netem_off: apaga a raiz só se este script a trocou e ela ainda é a prio 1: de netem_on; nunca "del root" às cegas.
netem_off() {
	[ "$NETEM_TOUCHED" = 1 ] || return 0
	NETEM_TOUCHED=0
	if root_qdisc | grep -q '^qdisc prio 1: root'; then
		remote "tc qdisc del dev $IFACE root"
	else
		log "ATENÇÃO: a raiz da $IFACE não é mais a prio 1: do netem; nada apagado"
	fi
}

cleanup() {
	set +e
	netem_off
	remote "pkill -f '[f]s-golden-srv'; pkill -f '[t]cpdump -i $IFACE -s0 -U -w $R'; true"
	local left s check="pgrep -fc '[f]s-golden-srv'; ss -ltnH 'sport = :$PORT' | wc -l"
	[ "$NETEM" = 1 ] && check="$check; tc qdisc show dev $IFACE | grep -c netem"
	left=$(remote "$check")
	s=$(echo "$left" | tr -d ' \n')
	if [ -n "$s" ] && [ -z "$(echo "$s" | tr -d 0)" ]; then
		log "servidor limpo: sem listener na $PORT$([ "$NETEM" = 1 ] && echo ' e sem netem')"
	else
		log "ATENÇÃO: sobras no servidor (listener, socket$([ "$NETEM" = 1 ] && echo ', netem')): $(echo "$left" | tr '\n' ' ')"
	fi
	remote "rm -rf $R"
	rm -rf "$LOCAL_TMP"
}
trap cleanup EXIT

# IPs públicos do Mac (o ssh por IPv4 e por IPv6 mostra o endereço de origem)
MAC4=$(ssh -4 -p "$SSH_PORT" -o BatchMode=yes "$VPS" 'echo ${SSH_CLIENT%% *}' </dev/null)
MAC6=$(ssh -6 -p "$SSH_PORT" -o BatchMode=yes "$VPS" 'echo ${SSH_CLIENT%% *}' </dev/null 2>/dev/null || true)
log "Mac: $MAC4 ${MAC6:-(sem IPv6)}"
MACF="host $MAC4"
[ -n "$MAC6" ] && MACF="(host $MAC4 or host $MAC6)"
EXT4=$(remote "getent ahostsv4 $EXT | awk 'NR==1{print \$1}'")
EXT6=$(remote "getent ahostsv6 $EXT | awk 'NR==1{print \$1}'")
log "$EXT: $EXT4 $EXT6"

log "preparando o servidor"
remote "rm -rf $R && mkdir -p $R/www && head -c 400000 /dev/urandom > $R/www/big.bin && echo hi > $R/www/small.txt \
	&& printf '<!doctype html><title>golden</title><p>golden</p>' > $R/www/index.html"
scp -q -P "$SSH_PORT" anon.py "$VPS:$R/anon.py"
for ip in "$VPS4" "$VPS6"; do
	# setsid -f: o processo se desliga da sessão ssh na hora (com "&" o ssh ficaria esperando)
	remote "cd $R/www && setsid -f bash -c 'exec -a fs-golden-srv python3 -m http.server $PORT --bind $ip' >/dev/null 2>&1 </dev/null"
done
sleep 1

# capture <nome> <filtro>: inicia o tcpdump do caso; stop <nome> encerra.
capture() {
	remote "setsid -f tcpdump -i $IFACE -s0 -U -w $R/$1.raw.pcap '$2' >/dev/null 2>&1 </dev/null"
	sleep 1.5
}
stop() {
	sleep 1.5
	remote "pkill -INT -f '[t]cpdump -i $IFACE -s0 -U -w $R/$1.raw.pcap'; sleep 0.5"
}

CASES=()
run_case() {
	local name=$1 filter=$2
	shift 2
	log "caso $name"
	capture "$name" "$filter"
	"$@" || log "aviso: o cliente de $name saiu com erro"
	stop "$name"
	CASES+=("$name")
}

mac_curl() { curl -s -o /dev/null --max-time 30 "$@"; }
# limite de tempo para os navegadores (o macOS não tem timeout)
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
chrome() {
	limit 40 "$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
		--user-data-dir="$LOCAL_TMP/chrome" --disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable \
		--dump-dom "http://$VPS4:$PORT/" >/dev/null 2>&1
}
firefox() {
	mkdir -p "$LOCAL_TMP/ff"
	limit 60 "$FIREFOX" --headless --no-remote --profile "$LOCAL_TMP/ff" --screenshot "$LOCAL_TMP/ff.png" \
		"http://$VPS4:$PORT/" >/dev/null 2>&1
}
# Sem netem, nenhum tráfego: o caso sai sem pacotes e é descartado (nunca um "retransmit" sem perda).
retransmit() {
	netem_on || {
		netem_off
		return 1
	}
	mac_curl -4 "http://$HOST:$PORT/big.bin"
	netem_off
}

run_case curl-macos-v4 "tcp port $PORT and $MACF" mac_curl -4 "http://$HOST:$PORT/big.bin"
if [ -n "$MAC6" ]; then
	run_case curl-macos-v6 "tcp port $PORT and $MACF" mac_curl -6 "http://$HOST:$PORT/big.bin"
fi
run_case curl-linux-v4 "tcp port 80 and host $EXT4" remote "curl -4 -s -o /dev/null --max-time 20 http://$EXT/"
run_case curl-linux-v6 "tcp port 80 and host $EXT6" remote "curl -6 -s -o /dev/null --max-time 20 http://$EXT/"
run_case go-macos "tcp port $PORT and $MACF" go run -tags golden ./goclient "http://$VPS4:$PORT/big.bin"
run_case chrome-macos "tcp port $PORT and $MACF" chrome
run_case firefox-macos "tcp port $PORT and $MACF" firefox
run_case keepalive-macos "tcp port $PORT and $MACF" python3 sock.py keepalive "$VPS4" "$PORT"
if [ "$NETEM" = 1 ]; then
	run_case retransmit-macos "tcp port $PORT and $MACF" retransmit
else
	log "caso retransmit-macos pulado: o netem troca a qdisc raiz da $IFACE do host (ADR 0038 item 9); FS_GOLDEN_NETEM=1 só com o aval do humano"
fi
run_case rst-macos "tcp port $PORT and $MACF" python3 sock.py rst "$VPS4" "$PORT"

log "saídas de referência no servidor"
MAP="$MAC4=$DOC4"
[ -n "$MAC6" ] && MAP="$MAP $MAC6=$DOC6"
FIELDS="frame.number frame.time_epoch ip.src ip.dst ipv6.src ipv6.dst ip.ttl ipv6.hlim ip.id ip.flags.df ip.dsfield \
ipv6.tclass ipv6.flow tcp.stream tcp.srcport tcp.dstport tcp.flags tcp.seq_raw tcp.ack_raw tcp.len tcp.window_size_value \
tcp.option_kind tcp.options.mss_val tcp.options.wscale.shift tcp.options.timestamp.tsval tcp.analysis.ack_rtt \
tcp.analysis.retransmission tcp.analysis.out_of_order tcp.analysis.keep_alive tcp.analysis.zero_window"
EFLAGS=""
for f in $FIELDS; do EFLAGS="$EFLAGS -e $f"; done
for name in "${CASES[@]}"; do
	remote "cd $R && python3 anon.py $name.raw.pcap $name.pcap $MAP && \
		tshark -r $name.pcap -T json $EFLAGS > $name.tshark.json 2>/dev/null && \
		$JA4 -j $name.pcap 2>/dev/null | grep '^{' > $name.ja4.jsonl || true; \
		rm -f p.log; p0f -r $name.pcap -o p.log >/dev/null 2>&1; \
		grep -E ' mod=(syn|syn[+]ack)[|]' p.log > $name.p0f.txt || true"
done

mkdir -p "$OUT"
for name in "${CASES[@]}"; do
	for ext in pcap tshark.json ja4.jsonl p0f.txt; do
		scp -q -P "$SSH_PORT" "$VPS:$R/$name.$ext" "$OUT/$name.$ext"
	done
	n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$OUT/$name.tshark.json")
	if [ "$n" = 0 ]; then
		# cliente não conectou (ex.: navegador que não sobe headless): sem pcap vazio no repositório
		log "AVISO: $name sem pacotes; descartado"
		rm -f "$OUT/$name".*
		continue
	fi
	log "$name: $n pacotes, $(wc -l <"$OUT/$name.ja4.jsonl" | tr -d ' ') JA4T, $(wc -l <"$OUT/$name.p0f.txt" | tr -d ' ') p0f"
done

# versões das ferramentas, para o README
remote "tshark --version | head -1; tcpdump --version 2>&1 | head -1; dpkg -s p0f | grep ^Version; \
	echo ja4 \$(cd /root/ja4-rust && grep -m1 '^version' Cargo.toml)" > "$OUT/VERSIONS.txt"
{
	curl --version | head -1
	go version
	"$CHROME" --version 2>/dev/null || true
	"$FIREFOX" --version 2>/dev/null || true
	sw_vers -productVersion | sed 's/^/macOS /'
} >>"$OUT/VERSIONS.txt"
log "pronto: $(find "$OUT" -name '*.pcap' | wc -l | tr -d ' ') pcaps em test/golden/$OUT"
