#!/usr/bin/env bash
# Desfaz o traefix de teste do up.sh no finger-01 (task 406) e confere que a limpeza foi completa. Roda do Mac, por
# ssh, e só mexe no que é do teste (o container fs-traefix-test, a imagem que o up.sh baixou, as chaves
# fs-traefix-test-*, /finger-sniffer/var/traefix-test/ e a trava tomada pelo up.sh). Pode rodar de novo a qualquer
# momento (idempotente), inclusive depois de um up.sh interrompido.
#
# Passos: para o container e o gravador; traz os lotes gravados para tmp/traefix-test/<data>-<digest>/ deste
# repositório (fora do Git; FS_TRAEFIX_FETCH=0 pula); revoga as chaves (as do keys.ids e qualquer fs-traefix-test-*
# ativa); apaga a imagem se ela não existia antes do up.sh; apaga a pasta; solta a trava se o token for o nosso. No
# fim confere: nenhum container, nenhuma porta 18xxx do teste em escuta, nenhuma chave de teste ativa, pasta
# apagada, trava não é nossa e traefik-app com o mesmo StartedAt e RestartCount de antes. Sai ≠ 0 se algo ficou.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
VPS_SSH="${VPS_SSH:-${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}}"
VPS_PORT="${VPS_PORT:-48022}"
IMAGE="${FS_TRAEFIX_IMAGE:-tmsoftbrasil/traefix:latest}"
LOCK="${FS_LOAD_LOCK:-/tmp/fs-load-running}"
DIR=/finger-sniffer/var/traefix-test
NAME=fs-traefix-test

say() { echo "down.sh: $*" >&2; }
ssh_vps() { ssh -4 -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=15 "$VPS_SSH" "$@"; }

case "$VPS_SSH" in *vps602*)
	say "vps602 abandonado: recusado"
	exit 2
	;;
esac
ssh_vps true || {
	say "$VPS_SSH:$VPS_PORT inacessível"
	exit 1
}

# 1. container e gravador (os lotes param de chegar)
ssh_vps bash -s -- "$DIR" "$NAME" <<'EOF'
dir=$1 name=$2
if docker container inspect "$name" >/dev/null 2>&1; then
	docker rm -f "$name" >/dev/null && echo "container $name removido" >&2
fi
if [ -f "$dir/recorder.pid" ]; then
	kill "$(cat "$dir/recorder.pid")" 2>/dev/null || true
fi
# o gravador roda com o caminho absoluto: só ele casa
pkill -f "^$dir/recorder " 2>/dev/null || true
sleep 0.5
EOF

# 2. lotes gravados → tmp/ deste repositório
if [ "${FS_TRAEFIX_FETCH:-1}" = 1 ] && ssh_vps "[ -d $DIR/batches ] && [ -n \"\$(ls -A $DIR/batches)\" ]"; then
	dig=$(ssh_vps "cat $DIR/image.digest 2>/dev/null" | sed 's/.*sha256://' | cut -c1-12)
	out="$repo/tmp/traefix-test/$(date -u +%Y%m%dT%H%M%SZ)-${dig:-sem-digest}"
	mkdir -p "$out"
	if ssh_vps "cd $DIR && tar -czf - batches recorder.log image.digest sender traefik-app.before 2>/dev/null" | tar -xzf - -C "$out"; then
		say "lotes gravados em $out ($(find "$out/batches" -name '*.body' | wc -l | tr -d ' ') lotes)"
	else
		say "AVISO: não consegui trazer os lotes para $out"
	fi
fi

# 3. chaves, imagem, pasta e trava; imprime o estado de antes do traefik-app e o token para as conferências
state=$(ssh_vps bash -s -- "$DIR" "$IMAGE" "$LOCK" <<'EOF'
dir=$1 image=$2 lock=$3
cli="runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot"
ids=$(cat "$dir/keys.ids" 2>/dev/null)
# qualquer fs-traefix-test-* ainda ativa (de um up.sh interrompido antes de gravar o keys.ids)
ids="$ids $($cli key list 2>/dev/null | awk '$3 ~ /^fs-traefix-test-/ && $NF == "-" {print $1}')"
for id in $ids; do
	if out=$($cli key revoke "$id" 2>&1) || printf '%s' "$out" | grep -qi revoked; then
		echo "chave $id revogada" >&2
	else
		echo "AVISO: revogar $id: $out" >&2
	fi
done
if [ "$(cat "$dir/image.existed" 2>/dev/null)" = no ] && docker image inspect "$image" >/dev/null 2>&1; then
	docker image rm "$image" >/dev/null && echo "imagem $image apagada (não existia antes)" >&2
fi
before=$(cat "$dir/traefik-app.before" 2>/dev/null)
token=$(cat "$dir/lock.token" 2>/dev/null)
if [ -n "$token" ] && [ "$(cat "$lock" 2>/dev/null)" = "$token" ]; then
	rm -f "$lock" && echo "trava $lock solta" >&2
fi
rm -rf "$dir"
printf 'before=%s\ntoken=%s\n' "$before" "$token"
EOF
)
before=$(printf '%s\n' "$state" | sed -n 's/^before=//p')
token=$(printf '%s\n' "$state" | sed -n 's/^token=//p')

# 4. conferências
fail=0
check() {
	if [ "$2" = ok ]; then
		say "ok: $1"
	else
		say "FALHA: $1 ($2)"
		fail=1
	fi
}
r=$(ssh_vps "docker container inspect $NAME >/dev/null 2>&1 && echo existe || echo ok")
check "nenhum container $NAME" "$r"
r=$(ssh_vps "ss -Hltnup | grep -E ':(18443|18444|18446|18447|18082|18090)\b' || echo ok")
check "nenhuma porta do teste em escuta" "$r"
r=$(ssh_vps "runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot key list | awk '\$3 ~ /^fs-traefix-test-/ && \$NF == \"-\" {print \$1}'")
check "nenhuma chave fs-traefix-test-* ativa" "${r:-ok}"
r=$(ssh_vps "[ -e $DIR ] && echo existe || echo ok")
check "$DIR apagada" "$r"
r=$(ssh_vps "pgrep -f '^$DIR/recorder ' || echo ok")
check "gravador parado" "$r"
if [ -n "$token" ]; then
	r=$(ssh_vps "[ \"\$(cat '$LOCK' 2>/dev/null)\" = '$token' ] && echo nossa || echo ok")
	check "trava $LOCK não é mais nossa" "$r"
fi
now=$(ssh_vps "docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' traefik-app 2>/dev/null || echo absent")
if [ -n "$before" ]; then
	[ "$now" = "$before" ] && r=ok || r="antes $before, agora $now"
	check "traefik-app intacto ($now)" "$r"
else
	say "traefik-app agora: $now (sem registro de antes)"
fi
exit "$fail"
