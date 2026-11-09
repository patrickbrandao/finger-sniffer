#!/usr/bin/env bash
# Gera os golden de Initials QUIC (task 050) contra a vps602.
#
# Roda no Mac. Sobe na vps602 um servidor HTTP/3 temporário (server/, quic-go, KeyLogWriter) na porta capturada
# 7703, em UDP e TCP (h2 com Alt-Svc, para o Firefox), e captura cada caso com tcpdump -s0 na eth0 (só UDP).
# Clientes do Mac: curl do Homebrew (--http3-only, ngtcp2), Go (goclient/, quic-go/http3), Chrome e Firefox
# headless. O certificado é autoassinado e gerado a cada coleta: curl e Go o recebem como raiz (--cacert/-ca),
# o Chrome o aceita pelo hash da chave (--ignore-certificate-errors-spki-list) e é mandado direto ao QUIC só
# para esta origem (--origin-to-force-quic-on, só na coleta, nunca no e2e); o Firefox recebe uma exceção de
# certificado num perfil descartável e o mapeamento de Alt-Svc de teste (network.http.http3.alt-svc-mapping-
# for-testing). Nenhuma sandbox é desligada.
#
# Antes das saídas de referência o IP do Mac vira endereço de documentação (../anon.py). Saídas por caso, geradas
# na vps602, em pcaps/:
#   <caso>.pcap          captura anonimizada (todos os datagramas UDP da coleta)
#   <caso>.keys          chaves TLS da sessão (NSS SSLKEYLOGFILE) gravadas pelo servidor
#   <caso>.tshark.json   tshark -T json (camadas udp, quic, tls e http3) com as chaves
#   <caso>.ja4.jsonl     ja4 -j -r --keylog-file da FoxIO (JA4 q, JA4_r, JA4S)
#   <caso>.ref.json      resumo (ref.py) só com saídas das ferramentas: Initials, frames, CRYPTO, parâmetros de
#                        transporte na ordem, ClientHello, JA4 do ja4 e do tshark, SETTINGS e HEADERS do h3
#   <caso>.initial.pcap  primeiro voo: só os datagramas com pacote Initial da primeira conexão (cliente e servidor)
#   <caso>.initial.ja4.jsonl  ja4 sobre o primeiro voo (deve dar o mesmo JA4 da captura inteira)
# A cópia mínima para o pkg/quicparse vai para pkg/quicparse/testdata/initials/ (<caso>.initial.pcap e
# <caso>.expected.json, o ref.json só da primeira conexão,
# com os SETTINGS e os HEADERS do h3 decifrados, para os testes de QPACK).
#
# No fim (inclusive em erro) o servidor e o tcpdump são parados, os arquivos temporários apagados e a limpeza é
# conferida ("vps602 limpa").
#
# Uso: test/golden/quic/collect.sh                 (todos os casos)
#      ONLY="curl go" test/golden/quic/collect.sh
#      REF_ONLY=1 test/golden/quic/collect.sh   (só as saídas de referência, sobre os pcaps já gravados)
set -euo pipefail
cd "$(dirname "$0")"

VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
SSH_PORT="${VPS_PORT:-48022}"
HOST=vps602.tmsoft.com.br
VPS4=172.233.24.85
PORT=7703
URL="https://$HOST:$PORT/"
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
R=/tmp/fs-golden-quic
OUT=pcaps
QTD=../../../pkg/quicparse/testdata/initials
DOC4=198.51.100.10
DOC6=2001:db8::10
CURL="${CURL_H3:-/opt/homebrew/opt/curl/bin/curl}"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FIREFOX="/Applications/Firefox.app/Contents/MacOS/firefox"
LOCAL_TMP=$(mktemp -d)

remote() { ssh -p "$SSH_PORT" -o BatchMode=yes "$VPS" "$@" </dev/null; }
log() { echo "[golden-quic] $*"; }

cleanup() {
	set +e
	remote "pkill -f '[f]s-golden-quic-srv'; pkill -f '[t]cpdump -i eth0 -s0 -U -w $R'; rm -rf $R; true"
	local left
	left=$(remote "pgrep -fc '[f]s-golden-quic-srv'; pgrep -fc '[t]cpdump -i eth0 -s0 -U -w $R'; \
		ss -lunH 'sport = :$PORT' | wc -l; ss -ltnH 'sport = :$PORT' | wc -l; test -e $R && echo 1 || echo 0")
	if [ "$(echo "$left" | tr -d ' \n')" = "00000" ]; then
		log "vps602 limpa: sem servidor, sem tcpdump, sem listener UDP/TCP na $PORT e sem $R"
	else
		log "ATENÇÃO: sobras na vps602 (servidor, tcpdump, UDP, TCP, diretório): $(echo "$left" | tr '\n' ' ')"
	fi
	rm -rf "$LOCAL_TMP"
}
trap cleanup EXIT

want() { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }

if ! "$CURL" --version | grep -q HTTP3; then
	echo "collect.sh: $CURL sem HTTP3 (precisa de um curl com ngtcp2 ou quiche; CURL_H3=...)" >&2
	exit 1
fi

# IPs públicos do Mac (o ssh por IPv4 e por IPv6 mostra o endereço de origem)
MAC4=$(ssh -4 -p "$SSH_PORT" -o BatchMode=yes "$VPS" 'echo ${SSH_CLIENT%% *}' </dev/null)
MAC6=$(ssh -6 -p "$SSH_PORT" -o BatchMode=yes "$VPS" 'echo ${SSH_CLIENT%% *}' </dev/null 2>/dev/null || true)
log "Mac: $MAC4 ${MAC6:-(sem IPv6)}"
MACF="host $MAC4"
[ -n "$MAC6" ] && MACF="(host $MAC4 or host $MAC6)"

log "certificado autoassinado e servidor"
/usr/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 2 -subj /CN=fs-golden \
	-addext "subjectAltName=DNS:$HOST,IP:$VPS4" -keyout "$LOCAL_TMP/key.pem" -out "$LOCAL_TMP/cert.pem" 2>/dev/null
SPKI=$(/usr/bin/openssl x509 -in "$LOCAL_TMP/cert.pem" -pubkey -noout | /usr/bin/openssl pkey -pubin -outform der |
	/usr/bin/openssl dgst -sha256 -binary | base64)
FPR=$(/usr/bin/openssl x509 -in "$LOCAL_TMP/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags golden -trimpath -o "$LOCAL_TMP/fs-golden-quic-srv" ./server
remote "rm -rf $R && mkdir -p $R"
scp -q -P "$SSH_PORT" "$LOCAL_TMP/fs-golden-quic-srv" "$LOCAL_TMP/cert.pem" "$LOCAL_TMP/key.pem" ../anon.py ref.py \
	"$VPS:$R/"
GOCLIENT="$LOCAL_TMP/goclient"
go build -tags golden -o "$GOCLIENT" ./goclient

# capture <caso>: servidor novo (keylog só desse caso) e tcpdump; stop <caso> encerra os dois.
capture() {
	remote "cd $R && setsid -f ./fs-golden-quic-srv -addr $VPS4:$PORT -cert cert.pem -key key.pem -keylog $1.keys \
		>$1.srv.log 2>&1 </dev/null; \
		setsid -f tcpdump -i eth0 -s0 -U -w $R/$1.raw.pcap 'udp port $PORT and $MACF' >/dev/null 2>&1 </dev/null"
	sleep 1.5
}
stop() {
	sleep 1.5
	remote "pkill -INT -f '[t]cpdump -i eth0 -s0 -U -w $R/$1.raw.pcap'; pkill -f '[f]s-golden-quic-srv'; sleep 0.5"
}

CASES=()
run_case() {
	local name=$1
	shift
	want "$name" || return 0
	log "caso $name"
	capture "$name"
	"$@" || log "aviso: o cliente de $name saiu com erro"
	stop "$name"
	CASES+=("$name")
}

# limite de tempo para os navegadores (o macOS não tem timeout)
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
curl_case() { "$CURL" -4 -s -o /dev/null --max-time 20 --cacert "$LOCAL_TMP/cert.pem" --http3-only "$URL"; }
go_case() { "$GOCLIENT" -ca "$LOCAL_TMP/cert.pem" "$URL" >/dev/null; }
chrome_case() {
	limit 40 "$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
		--user-data-dir="$LOCAL_TMP/chrome" --host-resolver-rules="MAP $HOST $VPS4" \
		--enable-quic --origin-to-force-quic-on="$HOST:$PORT" --ignore-certificate-errors-spki-list="$SPKI" \
		--dump-dom "$URL" >/dev/null 2>&1
}
firefox_case() {
	local p="$LOCAL_TMP/ff"
	mkdir -p "$p"
	cat >"$p/user.js" <<EOF
user_pref("network.dns.disableIPv6", true);
user_pref("network.http.http3.enable", true);
user_pref("network.http.http3.alt-svc-mapping-for-testing", "$HOST;h3=:$PORT");
EOF
	# exceção só para este certificado neste perfil descartável (o mesmo arquivo que o "aceitar o risco" grava)
	printf '%s:%s:\tOID.2.16.840.1.101.3.4.2.1\t%s\t\n' "$HOST" "$PORT" "$FPR" >"$p/cert_override.txt"
	limit 60 "$FIREFOX" --headless --no-remote --profile "$p" --screenshot "$LOCAL_TMP/ff.png" "$URL" \
		>"$LOCAL_TMP/ff.log" 2>&1
}

# descrição do cliente gravada no ref.json
describe() {
	case $1 in
	curl) "$CURL" --version | head -1 ;;
	go) echo "Go $(go env GOVERSION) $(grep -m1 'github.com/quic-go/quic-go ' ../../../go.mod | xargs)" ;;
	chrome) "$CHROME" --version 2>/dev/null ;;
	firefox) "$FIREFOX" --version 2>/dev/null ;;
	esac
}

if [ -n "${REF_ONLY:-}" ]; then
	# só refaz as saídas de referência a partir dos pcaps (já anonimizados) e chaves do repositório
	for f in "$OUT"/*.initial.pcap; do
		name=$(basename "$f" .initial.pcap)
		want "$name" || continue
		scp -q -P "$SSH_PORT" "$OUT/$name.pcap" "$OUT/$name.keys" "$VPS:$R/"
		CASES+=("$name")
	done
else
	run_case curl curl_case
	run_case go go_case
	run_case chrome chrome_case
	run_case firefox firefox_case
fi

log "saídas de referência na vps602"
MAP="$MAC4=$DOC4"
[ -n "$MAC6" ] && MAP="$MAP $MAC6=$DOC6"
for name in "${CASES[@]}"; do
	anon="python3 anon.py $name.raw.pcap $name.pcap $MAP"
	[ -n "${REF_ONLY:-}" ] && anon=true
	desc=$(describe "$name" | tr -d "'")
	remote "cd $R && $anon && touch $name.keys && \
		tshark -r $name.pcap -o tls.keylog_file:$name.keys -T json --no-duplicate-keys \
			-J 'frame ip ipv6 udp quic tls http3' \
			-Y quic > $name.tshark.json 2>/dev/null && \
		tshark -r $name.pcap -Y 'udp.stream == 0 && quic.long.packet_type == 0' -w $name.initial.pcap -F pcap \
			2>/dev/null && \
		{ $JA4 -j -r --keylog-file $name.keys $name.pcap 2>/dev/null | grep '^{' > $name.ja4.jsonl || true; } && \
		{ $JA4 -j -r $name.initial.pcap 2>/dev/null | grep '^{' > $name.initial.ja4.jsonl || true; } && \
		python3 ref.py $name '$desc'"
done

mkdir -p "$OUT" "$QTD"
for name in "${CASES[@]}"; do
	[ -z "${REF_ONLY:-}" ] && rm -f "$OUT/$name".* "$QTD/$name".*
	for ext in pcap keys tshark.json ja4.jsonl ref.json initial.pcap initial.ja4.jsonl; do
		scp -q -P "$SSH_PORT" "$VPS:$R/$name.$ext" "$OUT/$name.$ext" 2>/dev/null || true
	done
	if ! python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))['connections'] else 1)" \
		"$OUT/$name.ref.json" 2>/dev/null; then
		# cliente não mandou Initial: sem golden vazio no repositório
		log "AVISO: $name sem Initial; descartado"
		[ "$name" = firefox ] && log "log do firefox: $(tr '\n' ' ' <"$LOCAL_TMP/ff.log" 2>/dev/null | cut -c1-400)"
		rm -f "$OUT/$name".*
		continue
	fi
	log "$name: $(python3 -c "import json,sys; c=json.load(open(sys.argv[1]))['connections'][0]; \
print('ja4', c['ja4_tool'], 'datagramas', c['client_hello_datagrams'], 'fora_de_ordem', c['crypto_out_of_order'], \
'tps', len(c['transport_parameters']))" "$OUT/$name.ref.json")"
	# cópia mínima para o pkg/quicparse: primeiro voo e o esperado da primeira conexão
	cp "$OUT/$name.initial.pcap" "$QTD/$name.initial.pcap"
	python3 -c "import json,sys; r=json.load(open(sys.argv[1])); c=r['connections'][0]; \
c['case']=r['case']; c['client']=r['client']; json.dump(c, open(sys.argv[2],'w'), indent=1, sort_keys=True); \
open(sys.argv[2],'a').write('\n')" "$OUT/$name.ref.json" "$QTD/$name.expected.json"
done

# versões das ferramentas, para o README
remote "tshark --version | head -1; tcpdump --version 2>&1 | head -1; \
	echo ja4 \$(cd /root/ja4-rust && grep -m1 '^version' Cargo.toml)" >"$OUT/VERSIONS.txt"
{
	"$CURL" --version | head -1
	go version
	grep -m1 'github.com/quic-go/quic-go ' ../../../go.mod | sed 's/^[[:space:]]*/server e goclient: /'
	"$CHROME" --version 2>/dev/null || true
	"$FIREFOX" --version 2>/dev/null || true
	sw_vers -productVersion | sed 's/^/macOS /'
} >>"$OUT/VERSIONS.txt"
cp "$OUT/VERSIONS.txt" "$QTD/VERSIONS.txt"
log "pronto: $(find "$OUT" -name '*.initial.pcap' | wc -l | tr -d ' ') casos em test/golden/quic/$OUT"
