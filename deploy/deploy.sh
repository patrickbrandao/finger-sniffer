#!/usr/bin/env bash
# Deploy no finger-01 a partir do Mac (spec 016 RF-10..RF-12, ADR 0038). Sem aprovação: servidor de testes; o
# destino padrão é root@finger-01.tmsoft.com.br:48022 (FS_VPS_SSH/FS_VPS_PORT mudam).
#
#   make deploy            # todos os serviços (reinicia só o que mudou)
#   make deploy SVC=web    # reinicia só o web
#   FORCE=1 make deploy    # reinicia todos mesmo sem mudança
#
# Fluxo: build local → rsync para uma área de staging própria → instalação remota sob trava
# (flock /run/finger-sniffer/deploy.lock) → smoke test (units, rede e deploy/smoke.sh; com SVC, só o serviço + health).
#
# Com uma carga em andamento no servidor (/tmp/fs-load-running, gravada por test/load/*.sh) o deploy é recusado, antes
# do build e de novo sob a trava, porque reiniciar as units invalida a medida (spec 017 RF-13, task 361).
# FORCE_DURING_LOAD=1 passa por cima, de caso pensado.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}"
PORT="${FS_VPS_PORT:-48022}"
SVC="${SVC:-}"
FORCE="${FORCE:-0}"
STAGING="/var/tmp/finger-sniffer-deploy/$(whoami)-$(hostname -s)-$$"
SSH=(ssh -p "$PORT" -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

case "$SVC" in
"" | capture | web | raw | dns | store | bot | nats) ;;
*)
	echo "SVC inválido: $SVC (capture|web|raw|dns|store|bot|nats)" >&2
	exit 2
	;;
esac

# GET por h3 do Mac (fim do script): nome do certificado B e UDP 8443, porque a 443 é do traefik (ADR 0038)
H3_NAME="${FS_SMOKE_NAME:-finger-01.badblock.net.br}"
H3_PORT="${FS_SMOKE_H3_PORT:-8443}"
if [ "${FS_DEPLOY_PRINT_TARGETS:-0}" = 1 ]; then
	# só para os testes (deploy/deploy_test.go): alvos resolvidos, sem build nem ssh
	echo "host=$HOST port=$PORT h3=$H3_NAME:$H3_PORT"
	exit 0
fi

LOAD_LOCK="${FS_LOAD_LOCK:-/tmp/fs-load-running}"
FORCE_DURING_LOAD="${FORCE_DURING_LOAD:-0}"
if [ "$FORCE_DURING_LOAD" != 1 ]; then
	echo "== carga em andamento?"
	rc=0
	"${SSH[@]}" "if [ -e '$LOAD_LOCK' ]; then echo \"carga em andamento no servidor ($LOAD_LOCK: \$(cat '$LOAD_LOCK' 2>/dev/null)); deploy recusado (FORCE_DURING_LOAD=1 passa por cima)\" >&2; exit 3; fi" || rc=$?
	[ "$rc" = 0 ] || exit "$rc"
fi

echo "== build"
make -s build

echo "== rsync → $HOST:$STAGING"
"${SSH[@]}" "mkdir -p '$STAGING'"
rsync -a --delete -e "ssh -p $PORT -o BatchMode=yes" \
	--exclude='/.git' --exclude='/tasks/' --exclude='/tmp/' --exclude='/var/' --exclude='/.grill/' \
	--exclude='/etc/' --exclude='.DS_Store' --exclude='/.env' --exclude='/.claude/' \
	./ "$HOST:$STAGING/"

echo "== instalação remota (com trava)"
"${SSH[@]}" "mkdir -p /run/finger-sniffer && flock -w 300 /run/finger-sniffer/deploy.lock \
	env SVC='$SVC' FORCE='$FORCE' FORCE_DURING_LOAD='$FORCE_DURING_LOAD' FS_LOAD_LOCK='$LOAD_LOCK' \
	bash '$STAGING/deploy/remote-install.sh' '$STAGING'; rc=\$?; rm -rf '$STAGING'; exit \$rc"

# GET por h3 a partir do Mac (spec 016 RF-10): só com o web anunciando h3 e um curl local com HTTP3.
# O smoke remoto já confere Alt-Svc, o listener UDP e um GET por h3 de dentro do servidor.
if [ -z "$SVC" ] || [ "$SVC" = web ]; then
	if ! curl -fsS -m 5 "http://$H3_NAME:9001/api/v1/health" 2>/dev/null | tr -d ' \t\r\n' |
		grep -Eq '"(web_)?h3_listening":1([,}]|$)'; then
		echo "== h3 do Mac: AVISO web sem h3_listening no heartbeat: pulado"
	elif ! curl --version 2>/dev/null | grep -i '^features:' | grep -qw HTTP3; then
		echo "== h3 do Mac: AVISO curl local sem HTTP3: pulado"
	else
		out=$(curl --http3-only -sS -o /dev/null -w '%{http_code} %{http_version}' -m 10 "https://$H3_NAME:$H3_PORT/" 2>&1) || true
		if [ "$out" = "200 3" ]; then
			echo "== h3 do Mac: ok HTTP/3 200"
		else
			echo "== h3 do Mac: FALHOU $out"
			exit 1
		fi
	fi
fi
