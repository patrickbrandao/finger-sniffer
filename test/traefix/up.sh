#!/usr/bin/env bash
# Sobe o traefix de teste no finger-01 (task 406; tasks 273 e 313, spec 019, ADRs 0038 item 9, 0054 e 0062 itens 7
# e 8). Roda do Mac, por ssh, e só mexe no que é do teste:
#   - /finger-sniffer/var/traefix-test/ (fora do rsync --delete do deploy): configurações, gravador, lotes, estado;
#   - o container fs-traefix-test (tmsoftbrasil/traefix:latest, --network host, portas 18443/18444/18446/18447 e
#     127.0.0.1:18082) e a imagem dele (apagada pelo down.sh se não existia antes);
#   - duas chaves de teste do bot (fs-traefix-test-block-*, fs-traefix-test-revoked-*), criadas e revogadas pela CLI;
#   - a trava /tmp/fs-load-running (spec 017 RF-13): espera ela sumir e a segura até o down.sh, para nenhuma carga
#     ou deploy correr junto (e o e2e do verify-full recusa enquanto ela existir).
# Nunca toca o traefik-app, outros containers nem a rede do Docker; o down.sh confere que o traefik-app segue com o
# mesmo StartedAt.
#
# Uso (a saída padrão só tem os export das variáveis do e2e; o resto vai ao stderr):
#   eval "$(test/traefix/up.sh)"
#   go test -tags e2e -count=1 -v -run TestF8TraefixReal ./test/e2e/
#   test/traefix/down.sh
#
# Variáveis: VPS_SSH (root@finger-01.tmsoft.com.br), VPS_PORT (48022), FS_TRAEFIX_IMAGE
# (tmsoftbrasil/traefix:latest), FS_LOAD_LOCK (/tmp/fs-load-running), FS_TRAEFIX_LOCK_WAIT (segundos de espera pela
# trava, 3600), FS_TRAEFIX_STOP_BOT=1 (exporta FS_E2E_TRAEFIX_STOP_BOT=1: o e2e para o bot por alguns segundos),
# FS_TRAEFIX_SOCKS (host:porta de um ssh -D já aberto, exportado como FS_E2E_TRAEFIX_SOCKS para o caso do relay).
# Se algo falhar no meio, o up.sh chama o down.sh e nada fica no servidor.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
VPS_SSH="${VPS_SSH:-${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}}"
VPS_PORT="${VPS_PORT:-48022}"
IMAGE="${FS_TRAEFIX_IMAGE:-tmsoftbrasil/traefix:latest}"
LOCK="${FS_LOAD_LOCK:-/tmp/fs-load-running}"
WAIT="${FS_TRAEFIX_LOCK_WAIT:-3600}"
DIR=/finger-sniffer/var/traefix-test
NAME=fs-traefix-test
PUBLIC=https://finger-01.badblock.net.br

say() { echo "up.sh: $*" >&2; }
die() {
	say "$*"
	exit 1
}
ssh_vps() { ssh -4 -p "$VPS_PORT" -o BatchMode=yes -o ConnectTimeout=15 "$VPS_SSH" "$@"; }

# o servidor anterior nunca recebe nada (AGENTS.md)
case "$VPS_SSH" in *vps602*) die "vps602 abandonado: recusado" ;; esac

ssh_vps true || die "$VPS_SSH:$VPS_PORT inacessível"
if ssh_vps "docker container inspect $NAME >/dev/null 2>&1 || [ -e $DIR ]"; then
	die "já existe o container $NAME ou $DIR no servidor: rode test/traefix/down.sh antes"
fi

# daqui em diante, qualquer falha desfaz tudo
cleanup_on_error() {
	rc=$?
	trap - EXIT
	if [ "$rc" -ne 0 ]; then
		say "falhou (código $rc): desfazendo com o down.sh"
		FS_TRAEFIX_FETCH=0 "$here/down.sh" >&2 || true
	fi
	exit "$rc"
}
trap cleanup_on_error EXIT
trap 'exit 130' INT TERM

# trava da carga: espera sumir e toma com um token próprio (set -C: atômico); o down.sh só apaga se o token for o nosso
token="traefix-test $(whoami)@$(hostname -s):$$ $(date -u +%FT%TZ)"
deadline=$(($(date +%s) + WAIT))
while :; do
	rc=0
	ssh_vps "set -C; echo '$token' > '$LOCK'" 2>/dev/null || rc=$?
	if [ "$rc" -eq 0 ]; then
		# a pasta só nasce com a trava na mão: uma espera interrompida não deixa nada no servidor
		ssh_vps "umask 077 && mkdir -p $DIR/run $DIR/batches && echo '$token' > $DIR/lock.token"
		break
	fi
	[ "$rc" -ne 255 ] || die "servidor inacessível ao tomar $LOCK"
	[ "$(date +%s)" -lt "$deadline" ] || die "$LOCK ainda existe depois de ${WAIT}s: $(ssh_vps "cat '$LOCK'" 2>/dev/null)"
	say "carga em andamento ($LOCK: $(ssh_vps "cat '$LOCK'" 2>/dev/null)); nova tentativa em 60 s"
	sleep 60
done
say "trava $LOCK tomada"

# estado do traefik-app antes (o down.sh confere que não mudou)
ssh_vps "docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' traefik-app 2>/dev/null || echo absent" |
	ssh_vps "cat > $DIR/traefik-app.before"
say "traefik-app antes: $(ssh_vps "cat $DIR/traefik-app.before")"

# gravador (linux/amd64, estático) e configurações
tmpbin="$(mktemp -d)"
(cd "$repo" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$tmpbin/recorder" ./test/traefix/recorder)
ssh_vps "cat > $DIR/recorder && chmod 700 $DIR/recorder" <"$tmpbin/recorder"
rm -rf "$tmpbin"
ssh_vps "cat > $DIR/static.yml" <"$here/static.yml"
ssh_vps "cat > $DIR/dynamic.yml.tmpl" <"$here/dynamic.yml"

# imagem: anota se já existia (o down.sh só apaga a que este teste baixou), pull da latest, digest e sender
ssh_vps "if docker image inspect $IMAGE >/dev/null 2>&1; then echo yes; else echo no; fi > $DIR/image.existed"
say "docker pull $IMAGE"
ssh_vps "docker pull -q $IMAGE" >&2

# chaves de teste: criadas e postas no dynamic.yml no próprio servidor (nunca passam pelo Mac nem vão ao log)
ssh_vps bash -s -- "$DIR" <<'EOF'
set -euo pipefail
dir=$1
cli="runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot"
ts=$(date -u +%Y%m%d%H%M%S)
umask 077
mk() {
	local name=$1
	shift
	local out id key
	out=$($cli key create --name "$name" --domains finger-01.badblock.net.br "$@")
	id=$(printf '%s\n' "$out" | awk '$1 == "id:" {print $2}')
	key=$(printf '%s\n' "$out" | awk '$1 == "key:" {print $2}')
	[ -n "$id" ] && echo "$id" >>"$dir/keys.ids"
	if ! printf '%s' "$key" | grep -Eq '^fsk_[A-Za-z0-9_-]+$'; then
		echo "key create $name sem chave válida" >&2
		return 1
	fi
	printf '%s %s\n' "$id" "$key"
}
read -r _ block < <(mk "fs-traefix-test-block-$ts" --mode block)
read -r rid revoked < <(mk "fs-traefix-test-revoked-$ts")
if [ -z "${block:-}" ] || [ -z "${revoked:-}" ] || [ -z "${rid:-}" ]; then
	echo "chaves de teste não criadas" >&2
	exit 1
fi
$cli key revoke "$rid" >/dev/null
sed -e "s|__FS_BLOCK_KEY__|$block|" -e "s|__FS_REVOKED_KEY__|$revoked|" "$dir/dynamic.yml.tmpl" >"$dir/run/dynamic.yml"
if grep -q '__FS_' "$dir/run/dynamic.yml"; then
	echo "dynamic.yml com marcador não trocado" >&2
	exit 1
fi
echo "chaves de teste: $(tr '\n' ' ' <"$dir/keys.ids")(a revoked já revogada)" >&2
EOF
# a chave vale em até 2 s (keyReload do bot)
sleep 3

# gravador em 127.0.0.1:18090 → ingest do bot na 9003 (origem 10.249.255.254, dentro de 10.249.0.0/16)
# o "cd" fica fora da lista em segundo plano: em "cd && setsid ... &" o "&" vale para a lista inteira, e o
# subshell que sobra segura os pipes do ssh (a chamada não volta) e o $! aponta para ele, não para o gravador
ssh_vps "cd $DIR || exit 1; setsid nohup $DIR/recorder -listen 127.0.0.1:18090 -upstream http://10.249.255.254:9003 \
	-dir $DIR/batches >$DIR/recorder.log 2>&1 </dev/null & echo \$! > $DIR/recorder.pid"
for _ in $(seq 20); do
	ssh_vps "ss -Hltn 'sport = :18090' | grep -q ." && break
	sleep 0.5
done
ssh_vps "ss -Hltn 'sport = :18090' | grep -q ." || die "gravador não abriu 127.0.0.1:18090: $(ssh_vps "tail -5 $DIR/recorder.log")"

# container: rede do host (o Docker do host tem iptables: false; o SYN e a origem são os do cliente), certificado B
# do espelho só leitura
ssh_vps "docker run -d --name $NAME --network host --restart no --label fs.task=406 \
	-v $DIR/static.yml:/etc/traefik/traefik.yml:ro -v $DIR/run:/etc/traefix:ro \
	-v /finger-sniffer/var/certs/http01.crt:/certs/tls.crt:ro -v /finger-sniffer/var/certs/http01.key:/certs/tls.key:ro \
	$IMAGE" >/dev/null
ok=0
for _ in $(seq 60); do
	if ssh_vps "curl -sf -o /dev/null http://127.0.0.1:18082/ping"; then
		ok=1
		break
	fi
	sleep 0.5
done
[ "$ok" = 1 ] || die "traefix sem /ping em 30 s: $(ssh_vps "docker logs --tail 20 $NAME 2>&1")"
# erro de carga de router/middleware não derruba o /ping: confere os routers pela entrada
code=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 10 "$PUBLIC:18443/ping" || true)
[ "$code" = 200 ] || die "$PUBLIC:18443/ping deu $code: $(ssh_vps "docker logs --tail 20 $NAME 2>&1")"
if errs=$(ssh_vps "docker logs $NAME 2>&1 | grep -Ei 'level=error|\"level\":\"error\"| ERR '"); then
	say "AVISO: erros na carga do traefix:"
	echo "$errs" >&2
fi

digest=$(ssh_vps "docker image inspect --format '{{index .RepoDigests 0}}' $IMAGE")
version=$(ssh_vps "docker exec $NAME /traefik version" | sed -n 's/^Version: *//p')
labels=$(ssh_vps "docker image inspect --format '{{index .Config.Labels \"org.opencontainers.image.version\"}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}' $IMAGE" || true)
printf '%s\n' "$digest" | ssh_vps "cat > $DIR/image.digest"
printf 'traefix/%s\n' "$version" | ssh_vps "cat > $DIR/sender"
say "imagem $digest"
say "traefik version $version (sender traefix/$version), rótulos OCI version/revision: $labels"

trap - EXIT
# variáveis do e2e (TestF8TraefixReal)
cat <<EOV
export FS_E2E_TRAEFIX_URL=$PUBLIC:18443/observe
export FS_E2E_TRAEFIX_BLOCK_URL=$PUBLIC:18443/block
export FS_E2E_TRAEFIX_REVOKED_URL=$PUBLIC:18443/revoked
export FS_E2E_TRAEFIX_PLAIN_URL=$PUBLIC:18444
export FS_E2E_TRAEFIX_CONTAINER=$NAME
EOV
[ "${FS_TRAEFIX_STOP_BOT:-0}" != 1 ] || echo "export FS_E2E_TRAEFIX_STOP_BOT=1"
[ -z "${FS_TRAEFIX_SOCKS:-}" ] || echo "export FS_E2E_TRAEFIX_SOCKS=$FS_TRAEFIX_SOCKS"
say "no ar; rode o e2e e depois test/traefix/down.sh (a trava $LOCK fica até lá)"
