#!/usr/bin/env bash
# Gera os golden pcaps (task 013) contra a vps602 e as saídas de referência de cada um.
#
# Roda no Mac (clientes macOS: curl, Go, Chrome, Firefox e sockets especiais) e usa a vps602 como servidor
# (listener HTTP temporário na porta 7700) e como cliente Linux (curl de saída para um servidor externo,
# porque o tráfego da VPS para ela mesma passa pela loopback e não pela eth0). A captura é feita na vps602
# com tcpdump -s0; antes das saídas de referência os IPs públicos da máquina de teste viram endereços de
# documentação (anon.py). Saídas por pcap, geradas na vps602:
#   <nome>.tshark.json  tshark -T json com os campos IP/TCP e tcp.analysis.* (inclui ack_rtt)
#   <nome>.ja4.jsonl    ja4 -j da FoxIO (JA4T)
#   <nome>.p0f.txt      observações syn e syn+ack do p0f -r
# No fim (inclusive em erro) o netem e os listeners são removidos e a remoção é conferida.
#
# Uso: test/golden/collect.sh        (a partir de qualquer diretório)
set -euo pipefail
cd "$(dirname "$0")"

VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
SSH_PORT="${VPS_PORT:-48022}"
HOST=vps602.tmsoft.com.br
VPS4=172.233.24.85
VPS6=2600:3c0d::f03c:93ff:fe26:8fd9
PORT=7700
EXT=example.com
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
R=/tmp/fs-golden
OUT=pcaps
DOC4=198.51.100.10
DOC6=2001:db8::10
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FIREFOX="/Applications/Firefox.app/Contents/MacOS/firefox"
LOCAL_TMP=$(mktemp -d)

remote() { ssh -p "$SSH_PORT" -o BatchMode=yes "$VPS" "$@" </dev/null; }
log() { echo "[golden] $*"; }

cleanup() {
	set +e
	remote "pkill -f '[f]s-golden-srv'; pkill -f '[t]cpdump -i eth0 -s0 -U -w $R'; \
		tc qdisc del dev eth0 root 2>/dev/null; true"
	local left
	left=$(remote "pgrep -fc '[f]s-golden-srv'; tc qdisc show dev eth0 | grep -c netem; ss -ltnH 'sport = :$PORT' | wc -l")
	if [ "$(echo "$left" | tr -d ' \n')" = "000" ]; then
		log "vps602 limpa: sem listener na $PORT e sem netem"
	else
		log "ATENÇÃO: sobras na vps602 (listener, netem, socket): $(echo "$left" | tr '\n' ' ')"
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

log "preparando a vps602"
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
	remote "setsid -f tcpdump -i eth0 -s0 -U -w $R/$1.raw.pcap '$2' >/dev/null 2>&1 </dev/null"
	sleep 1.5
}
stop() {
	sleep 1.5
	remote "pkill -INT -f '[t]cpdump -i eth0 -s0 -U -w $R/$1.raw.pcap'; sleep 0.5"
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
netem_on() {
	# perda só nos pacotes que saem da porta do listener (ssh e serviços não são afetados)
	remote "tc qdisc add dev eth0 root handle 1: prio && \
		tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 8% && \
		tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip sport $PORT 0xffff flowid 1:3"
}
netem_off() { remote "tc qdisc del dev eth0 root"; }
retransmit() {
	netem_on
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
run_case retransmit-macos "tcp port $PORT and $MACF" retransmit
run_case rst-macos "tcp port $PORT and $MACF" python3 sock.py rst "$VPS4" "$PORT"

log "saídas de referência na vps602"
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
