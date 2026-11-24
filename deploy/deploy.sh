#!/usr/bin/env bash
# Deploy no finger-01 a partir do Mac (spec 016 RF-10..RF-12, ADR 0038). Sem aprovação: servidor de testes; o
# destino padrão é root@finger-01.tmsoft.com.br:48022 (FS_VPS_SSH/FS_VPS_PORT mudam).
#
#   make deploy            # todos os serviços (reinicia só o que mudou)
#   make deploy SVC=web    # reinicia só o web
#   FORCE=1 make deploy    # reinicia todos mesmo sem mudança
#
# Fluxo: build local → rsync (com delta) para o staging estável desta máquina, sob a trava dele → instalação remota sob
# trava (flock /run/finger-sniffer/deploy.lock) → smoke test (units, rede e deploy/smoke.sh; com SVC, só o serviço +
# health).
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
# Staging estável por máquina (task 393): <base>/<usuário>-<host>, mantido entre deploys para o rsync mandar só o
# delta. A base fica em /var/lib (só o root escreve lá), criada 0700 e conferida (diretório do próprio usuário remoto,
# sem link, sem acesso de grupo/outros), nunca em /var/tmp, onde outro usuário local poderia criá-la antes ou
# trocá-la por link (task 354); nem dentro de /finger-sniffer, que o rsync --delete do remote-install.sh limparia.
# Dois deploys da mesma máquina (worktrees diferentes) se excluem pela trava <base>/<nome>.lock, mantida por uma
# sessão ssh aberta do rsync até o fim da instalação. FS_DEPLOY_STAGING_BASE só para os testes.
STAGING_BASE="${FS_DEPLOY_STAGING_BASE:-/var/lib/finger-sniffer-deploy}"
STAGING_NAME="$(printf '%s-%s' "$(whoami)" "$(hostname -s)" | tr -c 'A-Za-z0-9._-' '_')"
STAGING=""
if ! [[ "$STAGING_BASE" =~ ^/[A-Za-z0-9._/-]+$ ]] || ! [[ "$STAGING_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
	echo "staging inválido: '$STAGING_BASE/$STAGING_NAME'" >&2
	exit 2
fi
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

# Script remoto da trava do staging: cria e confere a base (0700) e o staging, pega a trava (fd 8, solta quando a
# sessão termina) e segura a sessão até o stdin fechar. Saída 4: base ou staging inseguro.
# shellcheck disable=SC2016 # expandido no servidor
STAGING_LOCK_SCRIPT='set -eu
umask 077
b="$1"
s="$1/$2"
# safe_dir <dir> <máscara proibida>: diretório (não link) do usuário remoto sem os bits da máscara
safe_dir() {
	[ -d "$1" ] && [ ! -L "$1" ] || return 1
	om=$(stat -c "%u %a" "$1" 2>/dev/null || stat -f "%u %Lp" "$1")
	[ "${om%% *}" = "$(id -u)" ] && [ $((0${om##* } & $2)) -eq 0 ]
}
[ -e "$b" ] || [ -L "$b" ] || mkdir -m 0700 -p "$b"
safe_dir "$b" 077 || { echo "staging recusado: base $b precisa ser diretório 0700 do $(id -un), sem link" >&2; exit 4; }
exec 8>"$b/$2.lock"
flock -w 600 8 || { echo "trava do staging $s ocupada há 600 s" >&2; exit 5; }
[ -e "$s" ] || [ -L "$s" ] || mkdir -m 0700 "$s"
safe_dir "$s" 022 || { echo "staging recusado: $s precisa ser diretório do $(id -un) sem escrita para outros, sem link" >&2; exit 4; }
chmod 0700 "$s"
echo "locked $s"
exec cat >/dev/null'

LOCAL_TMP="$(mktemp -d "${TMPDIR:-/tmp}/fs-deploy.XXXXXX")"
LOCK_PID=""
# Solta a trava do staging ao sair (fecha o stdin da sessão e a encerra); o staging fica para o próximo delta.
release_staging_lock() {
	exec 9>&- 2>/dev/null || true
	if [ -n "$LOCK_PID" ]; then
		kill "$LOCK_PID" 2>/dev/null || true
		wait "$LOCK_PID" 2>/dev/null || true
	fi
	rm -rf "$LOCAL_TMP"
}
trap release_staging_lock EXIT

echo "== trava do staging $STAGING_BASE/$STAGING_NAME"
mkfifo "$LOCAL_TMP/lock.in"
"${SSH[@]}" "bash -c $(printf '%q' "$STAGING_LOCK_SCRIPT") staging-lock '$STAGING_BASE' '$STAGING_NAME'" \
	<"$LOCAL_TMP/lock.in" >"$LOCAL_TMP/lock.out" 2>&1 &
LOCK_PID=$!
exec 9>"$LOCAL_TMP/lock.in"
while ! grep -q '^locked ' "$LOCAL_TMP/lock.out" 2>/dev/null; do
	if ! kill -0 "$LOCK_PID" 2>/dev/null; then
		cat "$LOCAL_TMP/lock.out" >&2
		echo "trava do staging não obtida" >&2
		exit 1
	fi
	sleep 0.2
done
STAGING=$(sed -n 's/^locked //p' "$LOCAL_TMP/lock.out" | head -1)
if [ "$STAGING" != "$STAGING_BASE/$STAGING_NAME" ]; then
	echo "staging remoto inesperado: '$STAGING'" >&2
	exit 1
fi

echo "== rsync → $HOST:$STAGING"
# -rlptD é o -a sem dono nem grupo: o receptor (root) fica dono de tudo, e não o uid do Mac, que no servidor pode
# ser de outro usuário; go-w para nada no staging ter escrita de outros (task 354). -z e o staging estável dão o
# delta (task 393). Fora do staging, além do que é só local: node_modules das ferramentas de contrato, dist/ da
# release e binários de teste/cobertura soltos, que nada usa no servidor (task 393).
rsync -rlptDz --chmod=go-w --delete --stats -e "ssh -p $PORT -o BatchMode=yes" \
	--exclude='/.git' --exclude='/tasks/' --exclude='/tmp/' --exclude='/var/' --exclude='/.grill/' \
	--exclude='/etc/' --exclude='.DS_Store' --exclude='/.env' --exclude='/.claude/' \
	--exclude='node_modules/' --exclude='/dist/' --exclude='*.test' --exclude='*.out' --exclude='coverage.*' \
	./ "$HOST:$STAGING/" >"$LOCAL_TMP/rsync.out" 2>&1 || {
	cat "$LOCAL_TMP/rsync.out" >&2
	exit 1
}
# o que foi transferido (sem delta, ~600 MB a cada deploy antes da task 393)
grep -E '^(sent |total size|Total bytes)' "$LOCAL_TMP/rsync.out" | sed 's/^/   /' || true

echo "== instalação remota (com trava)"
"${SSH[@]}" "mkdir -p /run/finger-sniffer && flock -w 300 /run/finger-sniffer/deploy.lock \
	env SVC='$SVC' FORCE='$FORCE' FORCE_DURING_LOAD='$FORCE_DURING_LOAD' FS_LOAD_LOCK='$LOAD_LOCK' \
	bash '$STAGING/deploy/remote-install.sh' '$STAGING'"

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
