#!/usr/bin/env bash
# Gera os golden de ClientHello e h2 decifrado (task 036) contra a vps602.
#
# Roda no Mac. Sobe na vps602 um servidor TLS + h2 temporário (server/, Go, KeyLogWriter) na porta capturada
# 7702 e captura cada caso com tcpdump -s0 na eth0. Clientes do Mac: curl do macOS (LibreSSL), curl do Homebrew
# (OpenSSL), Go (goclient/), Chrome e Firefox headless, cada um em h2 e em h1. O certificado é autoassinado e
# gerado a cada coleta: curl e Go o recebem como raiz (--cacert/-ca), o Chrome o aceita pelo hash da chave
# (--ignore-certificate-errors-spki-list, só para essa chave). O Firefox não tem como confiar nele sem mexer no
# sistema; ele recebe uma exceção de certificado (cert_override.txt) num perfil descartável, só para essa chave.
#
# Antes das saídas de referência o IP do Mac vira endereço de documentação (../anon.py). Saídas por caso, geradas
# na vps602, em pcaps/:
#   <caso>.pcap         captura anonimizada
#   <caso>.keys         chaves TLS da sessão (NSS SSLKEYLOGFILE) gravadas pelo servidor
#   <caso>.tshark.json  tshark -T json (camadas tls, http2 e http) com as chaves: JA3/JA4, SETTINGS,
#                       WINDOW_UPDATE, PRIORITY, HEADERS com o HPACK decodificado
#   <caso>.ja4.jsonl    ja4 -j -r --keylog-file da FoxIO (JA4, JA4_r, JA4H)
#   <caso>.ref.json     resumo (ref.py): JA3/JA4 e Akamai calculados das saídas do tshark, JA4H do ja4
#   <caso>.client.h2    bytes h2 decifrados do cliente para o servidor (só h2), para pkg/h2passive
# e, para cada cliente, <cliente>.peet.json: a resposta de https://tls.peet.ws/api/all para o mesmo binário.
# A cópia mínima para os testes do parser passivo vai para pkg/h2passive/testdata/clients/.
#
# No fim (inclusive em erro) o servidor e o tcpdump são parados, os arquivos temporários apagados e a limpeza é
# conferida ("vps602 limpa").
#
# Uso: test/golden/tls/collect.sh            (todos os casos)
#      ONLY="curl-libressl-h2 go-h1" test/golden/tls/collect.sh
set -euo pipefail
cd "$(dirname "$0")"

VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
SSH_PORT="${VPS_PORT:-48022}"
HOST=vps602.tmsoft.com.br
VPS4=172.233.24.85
PORT=7702
URL="https://$HOST:$PORT/"
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
R=/tmp/fs-golden-tls
OUT=pcaps
H2TD=../../../pkg/h2passive/testdata/clients
DOC4=198.51.100.10
DOC6=2001:db8::10
CURL_LIBRESSL=/usr/bin/curl
CURL_OPENSSL="${CURL_OPENSSL:-/opt/homebrew/opt/curl/bin/curl}"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FIREFOX="/Applications/Firefox.app/Contents/MacOS/firefox"
PEET=https://tls.peet.ws/api/all
LOCAL_TMP=$(mktemp -d)

remote() { ssh -p "$SSH_PORT" -o BatchMode=yes "$VPS" "$@" </dev/null; }
log() { echo "[golden-tls] $*"; }

cleanup() {
	set +e
	remote "pkill -f '[f]s-golden-tls-srv'; pkill -f '[t]cpdump -i eth0 -s0 -U -w $R'; rm -rf $R; true"
	local left
	left=$(remote "pgrep -fc '[f]s-golden-tls-srv'; pgrep -fc '[t]cpdump -i eth0 -s0 -U -w $R'; \
		ss -ltnH 'sport = :$PORT' | wc -l; test -e $R && echo 1 || echo 0")
	if [ "$(echo "$left" | tr -d ' \n')" = "0000" ]; then
		log "vps602 limpa: sem servidor, sem tcpdump, sem listener na $PORT e sem $R"
	else
		log "ATENÇÃO: sobras na vps602 (servidor, tcpdump, listener, diretório): $(echo "$left" | tr '\n' ' ')"
	fi
	rm -rf "$LOCAL_TMP"
}
trap cleanup EXIT

want() { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }

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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags golden -trimpath -o "$LOCAL_TMP/fs-golden-tls-srv" ./server
remote "rm -rf $R && mkdir -p $R"
scp -q -P "$SSH_PORT" "$LOCAL_TMP/fs-golden-tls-srv" "$LOCAL_TMP/cert.pem" "$LOCAL_TMP/key.pem" ../anon.py ref.py \
	"$VPS:$R/"
GOCLIENT="$LOCAL_TMP/goclient"
go build -tags golden -o "$GOCLIENT" ./goclient

# capture <caso>: servidor novo (keylog só desse caso) e tcpdump; stop <caso> encerra os dois.
capture() {
	remote "cd $R && setsid -f ./fs-golden-tls-srv -addr $VPS4:$PORT -cert cert.pem -key key.pem -keylog $1.keys \
		>/dev/null 2>&1 </dev/null; \
		setsid -f tcpdump -i eth0 -s0 -U -w $R/$1.raw.pcap 'tcp port $PORT and $MACF' >/dev/null 2>&1 </dev/null"
	sleep 1.5
}
stop() {
	sleep 1.5
	remote "pkill -INT -f '[t]cpdump -i eth0 -s0 -U -w $R/$1.raw.pcap'; pkill -f '[f]s-golden-tls-srv'; sleep 0.5"
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
curl_case() { "$1" -4 -s -o /dev/null --max-time 20 --cacert "$LOCAL_TMP/cert.pem" "$2" "$URL"; }
go_case() { "$GOCLIENT" -ca "$LOCAL_TMP/cert.pem" -proto "$1" "$URL" >/dev/null; }
chrome_run() {
	local dir=$1
	shift
	limit 40 "$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
		--user-data-dir="$LOCAL_TMP/$dir" --host-resolver-rules="MAP $HOST $VPS4" "$@" 2>/dev/null
}
chrome_case() {
	local extra=()
	[ "$1" = h1 ] && extra=(--disable-http2)
	chrome_run "chrome-$1" --ignore-certificate-errors-spki-list="$SPKI" ${extra[@]+"${extra[@]}"} --dump-dom "$URL" >/dev/null
}
firefox_profile() {
	mkdir -p "$LOCAL_TMP/$1"
	{
		echo 'user_pref("network.dns.disableIPv6", true);'
		[ "$2" = h1 ] && echo 'user_pref("network.http.http2.enabled", false);'
		true
	} >"$LOCAL_TMP/$1/user.js"
	# exceção só para este certificado neste perfil descartável (o mesmo arquivo que o "aceitar o risco" grava)
	printf '%s:%s:\tOID.2.16.840.1.101.3.4.2.1\t%s\t\n' "$HOST" "$PORT" "$FPR" >"$LOCAL_TMP/$1/cert_override.txt"
}
firefox_run() {
	limit 60 "$FIREFOX" --headless --no-remote --profile "$LOCAL_TMP/$1" --screenshot "$LOCAL_TMP/$1.png" "$2" \
		>"$LOCAL_TMP/$1.log" 2>&1
}
firefox_case() {
	firefox_profile "ff-$1" "$1"
	firefox_run "ff-$1" "$URL"
}

run_case curl-libressl-h2 curl_case "$CURL_LIBRESSL" --http2
run_case curl-libressl-h1 curl_case "$CURL_LIBRESSL" --http1.1
if [ -x "$CURL_OPENSSL" ]; then
	run_case curl-openssl-h2 curl_case "$CURL_OPENSSL" --http2
	run_case curl-openssl-h1 curl_case "$CURL_OPENSSL" --http1.1
fi
for p in h2 h1; do run_case "go-$p" go_case "$p"; done
for p in h2 h1; do run_case "chrome-$p" chrome_case "$p"; done
for p in h2 h1; do run_case "firefox-$p" firefox_case "$p"; done
if want firefox-h2 || want firefox-h1; then
	if [ -s "$LOCAL_TMP/ff-h2.png" ] || [ -s "$LOCAL_TMP/ff-h1.png" ]; then
		log "firefox headless rodou"
	else
		log "AVISO: firefox headless não gerou a captura de tela; log: $(tr '\n' ' ' <"$LOCAL_TMP/ff-h2.log" 2>/dev/null | cut -c1-300)"
	fi
fi

log "saídas de referência na vps602"
MAP="$MAC4=$DOC4"
[ -n "$MAC6" ] && MAP="$MAP $MAC6=$DOC6"
for name in "${CASES[@]}"; do
	remote "cd $R && python3 anon.py $name.raw.pcap $name.pcap $MAP && touch $name.keys && \
		tshark -r $name.pcap -o tls.keylog_file:$name.keys -T json --no-duplicate-keys -J 'tcp tls http2 http' \
			-Y 'tls.handshake.type == 1 || http2 || http' > $name.tshark.json 2>/dev/null && \
		{ $JA4 -j -r --keylog-file $name.keys $name.pcap 2>/dev/null | grep '^{' > $name.ja4.jsonl || true; } && \
		python3 ref.py $name"
done

mkdir -p "$OUT" "$H2TD"
for name in "${CASES[@]}"; do
	rm -f "$OUT/$name".*
	for ext in pcap keys tshark.json ja4.jsonl ref.json client.h2; do
		scp -q -P "$SSH_PORT" "$VPS:$R/$name.$ext" "$OUT/$name.$ext" 2>/dev/null || true
	done
	if ! python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))['client_hellos'] else 1)" \
		"$OUT/$name.ref.json"; then
		# cliente não conectou: sem golden vazio no repositório
		log "AVISO: $name sem ClientHello; descartado"
		rm -f "$OUT/$name".*
		continue
	fi
	log "$name: $(python3 -c "import json,sys; r=json.load(open(sys.argv[1])); \
print('ja4', r['ja4'], 'alpn', r['client_hellos'][0]['alpn'], 'akamai', r.get('akamai'), \
'ja4h', r.get('ja4h'))" "$OUT/$name.ref.json")"
	# cópia mínima para o parser passivo: bytes decifrados do cliente e o esperado
	if [ -s "$OUT/$name.client.h2" ]; then
		cp "$OUT/$name.client.h2" "$H2TD/$name.client.h2"
		python3 -c "import json,sys; r=json.load(open(sys.argv[1])); r.pop('client_hellos'); \
json.dump(r, open(sys.argv[2],'w'), indent=1, sort_keys=True); open(sys.argv[2],'a').write('\n')" \
			"$OUT/$name.ref.json" "$H2TD/$name.expected.json"
	fi
done

if [ -z "${ONLY:-}" ] || [ -n "${PEET_ONLY:-}" ]; then
	log "referência externa: $PEET"
	"$CURL_LIBRESSL" -4 -s --max-time 20 --http2 "$PEET" -o "$OUT/curl-libressl.peet.json" || true
	[ -x "$CURL_OPENSSL" ] && { "$CURL_OPENSSL" -4 -s --max-time 20 --http2 "$PEET" -o "$OUT/curl-openssl.peet.json" || true; }
	"$GOCLIENT" -proto h2 -out "$OUT/go.peet.json" "$PEET" >/dev/null || true
	# o Chrome entrega o JSON dentro de um <pre>
	chrome_run chrome-peet --dump-dom "$PEET" |
		python3 -c "import sys,re,html; m=re.search(r'<pre[^>]*>(.*)</pre>', sys.stdin.read(), re.S); \
sys.stdout.write(html.unescape(m.group(1)) if m else '')" >"$OUT/chrome.peet.json" || true
	for f in "$OUT"/*.peet.json; do
		# JSON válido e sem o IP público do Mac (o tls.peet.ws devolve o IP de origem em vários campos)
		python3 -c "import json,sys; t=open(sys.argv[1]).read(); \
t=t.replace(sys.argv[2], sys.argv[3]) if sys.argv[2] else t; t=t.replace(sys.argv[4], sys.argv[5]) if sys.argv[4] else t; \
json.loads(t); open(sys.argv[1],'w').write(t)" "$f" "$MAC4" "$DOC4" "${MAC6:-}" "$DOC6" 2>/dev/null || {
			log "AVISO: $f inválido; descartado"
			rm -f "$f"
		}
	done
	date -u +%Y-%m-%dT%H:%MZ >"$OUT/peet.date"
fi

# versões das ferramentas, para o README
remote "tshark --version | head -1; tcpdump --version 2>&1 | head -1; \
	echo ja4 \$(cd /root/ja4-rust && grep -m1 '^version' Cargo.toml)" >"$OUT/VERSIONS.txt"
{
	"$CURL_LIBRESSL" --version | head -1
	[ -x "$CURL_OPENSSL" ] && "$CURL_OPENSSL" --version | head -1
	go version
	"$CHROME" --version 2>/dev/null || true
	"$FIREFOX" --version 2>/dev/null || true
	sw_vers -productVersion | sed 's/^/macOS /'
} >>"$OUT/VERSIONS.txt"
log "pronto: $(find "$OUT" -name '*.pcap' | wc -l | tr -d ' ') pcaps em test/golden/tls/$OUT"
