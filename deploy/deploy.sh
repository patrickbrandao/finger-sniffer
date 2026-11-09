#!/usr/bin/env bash
# Deploy na vps602 a partir do Mac (spec 016 RF-10..RF-12). Sem aprovação: servidor de testes.
#
#   make deploy            # todos os serviços (reinicia só o que mudou)
#   make deploy SVC=web    # reinicia só o web
#   FORCE=1 make deploy    # reinicia todos mesmo sem mudança
#
# Fluxo: build local → rsync para uma área de staging própria → instalação remota sob trava
# (flock /run/finger-sniffer/deploy.lock) → smoke test (units, rede e deploy/smoke.sh; com SVC, só o serviço + health).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${FS_VPS_SSH:-root@vps602.tmsoft.com.br}"
PORT="${FS_VPS_PORT:-48022}"
SVC="${SVC:-}"
FORCE="${FORCE:-0}"
STAGING="/var/tmp/finger-sniffer-deploy/$(whoami)-$(hostname -s)-$$"
SSH=(ssh -p "$PORT" -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

case "$SVC" in
"" | capture | web | raw | dns | store | nats) ;;
*)
	echo "SVC inválido: $SVC (capture|web|raw|dns|store|nats)" >&2
	exit 2
	;;
esac

echo "== build"
make -s build

echo "== rsync → $HOST:$STAGING"
"${SSH[@]}" "mkdir -p '$STAGING'"
rsync -a --delete -e "ssh -p $PORT -o BatchMode=yes" \
	--exclude='/.git' --exclude='/tasks/' --exclude='/tmp/' --exclude='/var/' --exclude='/.grill/' \
	--exclude='/etc/' --exclude='.DS_Store' --exclude='/.env' \
	./ "$HOST:$STAGING/"

echo "== instalação remota (com trava)"
"${SSH[@]}" "mkdir -p /run/finger-sniffer && flock -w 300 /run/finger-sniffer/deploy.lock \
	env SVC='$SVC' FORCE='$FORCE' bash '$STAGING/deploy/remote-install.sh' '$STAGING'; rc=\$?; rm -rf '$STAGING'; exit \$rc"
