#!/usr/bin/env bash
# Smoke test do deploy (spec 016 RF-10), executado na vps602 pelo remote-install.sh depois dos reinícios.
#
#   SVC=""      todos os passos
#   SVC=<svc>   só os passos daquele serviço + health (capture, store e nats só têm o health)
#
# Passos: health :9001 com os 5 serviços ok/degraded; web GET :80/ e GET :443/ (TLS estrito, salvo quando o
# health do web aponta cert_self_signed: aí aceita com aviso); dns A de <probe>.<zona> com o IP do espelho e
# example.com → REFUSED; raw eco na 7 e banner 220 na 25; store GET https://:9000/api/v1/health.
# Roda todos os passos selecionados e sai com 1 se algum falhar.
#
# Variáveis (os padrões vêm do env instalado; os testes de deploy/smoke_test.go apontam para servidores falsos):
#   FS_ENV_FILE, SMOKE_HOST (IPv4), SMOKE_NAME (nome do certificado), SMOKE_ZONE, SMOKE_DNS_EXPECT,
#   SMOKE_*_PORT, SMOKE_HEALTH_WAIT (segundos), SMOKE_TIMEOUT (segundos por passo), SMOKE_LIST=1 (só lista os
#   passos selecionados, sem executar).
set -uo pipefail

SVC="${SVC:-}"
ENV_FILE="${FS_ENV_FILE:-/finger-sniffer/etc/finger-sniffer.env}"

# env_get <chave>: valor da última ocorrência no env instalado ("" se ausente).
env_get() {
	[ -r "$ENV_FILE" ] || return 0
	grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2-
}

HOST="${SMOKE_HOST:-$(env_get FS_LISTEN_IPV4)}"
NAME="${SMOKE_NAME:-vps602.tmsoft.com.br}"
ZONE="${SMOKE_ZONE:-$(env_get FS_DNS_ZONE)}"
ZONE="${ZONE:-dns-monitor.tmsoft.com.br}"
DNS_EXPECT="${SMOKE_DNS_EXPECT:-$HOST}"
API_HTTP_PORT="${SMOKE_API_HTTP_PORT:-9001}"
API_HTTPS_PORT="${SMOKE_API_HTTPS_PORT:-9000}"
HTTP_PORT="${SMOKE_HTTP_PORT:-80}"
HTTPS_PORT="${SMOKE_HTTPS_PORT:-443}"
DNS_PORT="${SMOKE_DNS_PORT:-53}"
ECHO_PORT="${SMOKE_ECHO_PORT:-7}"
BANNER_PORT="${SMOKE_BANNER_PORT:-25}"
HEALTH_WAIT="${SMOKE_HEALTH_WAIT:-30}"
TIMEOUT="${SMOKE_TIMEOUT:-5}"

case "$SVC" in
"" | capture | web | raw | dns | store | nats) ;;
*)
	echo "SVC inválido: $SVC" >&2
	exit 2
	;;
esac
if [ -z "$HOST" ]; then
	echo "smoke: sem IP (SMOKE_HOST ou FS_LISTEN_IPV4 em $ENV_FILE)" >&2
	exit 2
fi

fail=0
HEALTH=""

pass() { printf "  %-28s ok %s\n" "$1" "${2:-}"; }
warn() { printf "  %-28s AVISO %s\n" "$1" "$2"; }
bad() {
	printf "  %-28s FALHOU %s\n" "$1" "$2"
	fail=1
}

# selected <svc>: o passo do serviço roda nesta seleção?
selected() { [ -z "$SVC" ] || [ "$SVC" = "$1" ]; }

# health_compact: o JSON do health sem espaços nem quebras de linha ("" se não respondeu).
health_compact() {
	curl -fsS -m "$TIMEOUT" "http://$HOST:$API_HTTP_PORT/api/v1/health" 2>/dev/null | tr -d ' \t\r\n'
}

# svc_block <svc>: trecho do objeto do serviço até o primeiro "}" (status e reasons vêm antes de metrics).
svc_block() { printf '%s' "$HEALTH" | grep -o "\"$1\":{\"status\":\"[a-z]*\"[^}]*" | head -n1; }

svc_status() { svc_block "$1" | sed -E 's/^"[a-z]+":\{"status":"([a-z]*)".*/\1/'; }

# self_signed <svc>: o health do serviço aponta certificado autoassinado?
self_signed() { svc_block "$1" | grep -q '"cert_self_signed"'; }

step_health() {
	local deadline=$((SECONDS + HEALTH_WAIT)) s st bad_list
	while :; do
		HEALTH=$(health_compact)
		bad_list=""
		for s in capture web raw dns store; do
			st=$(svc_status "$s")
			case "$st" in
			ok | degraded) ;;
			*) bad_list="$bad_list $s=${st:-ausente}" ;;
			esac
		done
		[ -n "$HEALTH" ] && [ -z "$bad_list" ] && break
		if [ "$SECONDS" -ge "$deadline" ]; then
			[ -n "$HEALTH" ] || bad_list=" sem resposta"
			bad "health :$API_HTTP_PORT" "$bad_list"
			return
		fi
		sleep 1
	done
	local summary=""
	for s in capture web raw dns store; do summary="$summary $s=$(svc_status "$s")"; done
	pass "health :$API_HTTP_PORT" "$summary"
}

# https_get <rótulo> <porta> <caminho> <svc dono do certificado>
https_get() {
	local label="$1" port="$2" path="$3" owner="$4" code
	if self_signed "$owner"; then
		code=$(curl -ksS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" \
			--resolve "$NAME:$port:$HOST" "https://$NAME:$port$path" 2>&1) || true
		if [ "$code" = 200 ]; then
			warn "$label" "HTTP 200 com certificado autoassinado (sem validação)"
		else
			bad "$label" "HTTP $code"
		fi
		return
	fi
	code=$(curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" \
		--resolve "$NAME:$port:$HOST" "https://$NAME:$port$path" 2>&1) || true
	if [ "$code" = 200 ]; then
		pass "$label" "HTTP 200, TLS validado ($NAME)"
	else
		bad "$label" "$code"
	fi
}

step_web() {
	local code
	code=$(curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" "http://$HOST:$HTTP_PORT/" 2>&1) || true
	if [ "$code" = 200 ]; then pass "web GET :$HTTP_PORT/" "HTTP 200"; else bad "web GET :$HTTP_PORT/" "HTTP $code"; fi
	https_get "web GET https :$HTTPS_PORT/" "$HTTPS_PORT" / web
}

step_dns() {
	local id qname got status
	# probe ID válido ([a-z0-9]{8,32}) e único por execução
	id="smoke$(date +%s)$RANDOM"
	qname="$id.$ZONE"
	got=$(dig +short +time="$TIMEOUT" +tries=1 -p "$DNS_PORT" @"$HOST" "$qname" A 2>&1)
	if printf '%s\n' "$got" | grep -qxF "$DNS_EXPECT"; then
		pass "dns A <probe>.$ZONE" "$DNS_EXPECT"
	else
		bad "dns A <probe>.$ZONE" "esperado $DNS_EXPECT, veio: $(printf '%s' "$got" | tr '\n' ' ')"
	fi
	status=$(dig +time="$TIMEOUT" +tries=1 -p "$DNS_PORT" @"$HOST" example.com A 2>&1 |
		sed -nE 's/.*status: ([A-Z]+).*/\1/p' | head -n1)
	if [ "$status" = REFUSED ]; then
		pass "dns example.com" "REFUSED"
	else
		bad "dns example.com" "esperado REFUSED, veio ${status:-sem resposta}"
	fi
}

# tcp_line <porta> <linha a enviar ("" = nada)>: devolve a primeira linha recebida, sem \r.
tcp_line() {
	local port="$1" send="$2" line=""
	(
		exec 3<>"/dev/tcp/$HOST/$port" || exit 1
		[ -n "$send" ] && printf '%s\r\n' "$send" >&3
		IFS= read -r -t "$TIMEOUT" line <&3 || true
		printf '%s' "${line%$'\r'}"
		exec 3<&-
	) 2>/dev/null
}

step_raw() {
	local token got
	token="fs-smoke-$RANDOM$RANDOM"
	got=$(tcp_line "$ECHO_PORT" "$token")
	if [ "$got" = "$token" ]; then pass "raw eco :$ECHO_PORT"; else bad "raw eco :$ECHO_PORT" "veio '${got}'"; fi
	got=$(tcp_line "$BANNER_PORT" "")
	case "$got" in
	220*) pass "raw banner :$BANNER_PORT" "$got" ;;
	*) bad "raw banner :$BANNER_PORT" "veio '${got}'" ;;
	esac
}

step_store() {
	https_get "store GET https :$API_HTTPS_PORT/health" "$API_HTTPS_PORT" /api/v1/health store
}

steps="health"
selected web && steps="$steps web"
selected dns && steps="$steps dns"
selected raw && steps="$steps raw"
selected store && steps="$steps store"

if [ "${SMOKE_LIST:-0}" = 1 ]; then
	echo "$steps"
	exit 0
fi

echo "[smoke] passos: $steps (host $HOST)"
for st in $steps; do "step_$st"; done
if [ "$fail" = 1 ]; then
	echo "[smoke] FALHOU"
	exit 1
fi
echo "[smoke] ok"
