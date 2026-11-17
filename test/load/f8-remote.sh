#!/usr/bin/env bash
# Lado servidor da carga da F8 (task 285; spec 018 RNF-01/RNF-02, ADR 0057 item 2), roda no finger-01 em
# /tmp/fs-load-f8 (copiado para lá com o botload linux/amd64 e o f8-side.sh; passos em RESULTS.md, seção F8):
#
#   f8-remote.sh image                         importa a imagem fs-load-f8:285 (só o botload estático, sem download)
#   f8-remote.sh start NAME MODE [flags...]    cria uma chave de teste pela CLI do bot, sobe o container NAME na
#                                              bridge br-net-public (rede network_public, 1 CPU) com o botload MODE e
#                                              a chave pela entrada padrão; saída em /tmp/fs-load-f8/out-NAME
#   f8-remote.sh start-nokey NAME MODE [flags]  igual ao start, sem chave (modo feed)
#   f8-remote.sh stop NAME                     docker stop (o botload termina limpo com SIGTERM)
#   f8-remote.sh cleanup                       para e remove os containers fs-load-f8-*, revoga as chaves load-f8-*
#                                              e remove a imagem
#
# A chave só existe na variável KEY deste shell e na entrada do container: nunca em argumento, arquivo ou log (a
# saída do key create não é gravada; o id, que não é segredo, vai para keys.txt para a revogação).
set -euo pipefail
DIR=/tmp/fs-load-f8
IMAGE=fs-load-f8:285
NET=network_public
CLI="runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot"
DOMAINS=fs-load.example,*.hostile.fs-load.example

case "${1:-}" in
image)
	tmp=$(mktemp -d)
	cp "$DIR/botload" "$tmp/botload"
	tar -C "$tmp" -c botload | docker import --change 'ENTRYPOINT ["/botload"]' - "$IMAGE" >/dev/null
	rm -rf "$tmp"
	docker image inspect "$IMAGE" --format '{{.Id}} {{.Size}}'
	;;
start)
	name=$2 mode=$3
	shift 3
	out="$DIR/out-$name"
	mkdir -p "$out"
	created=$($CLI key create --name "load-f8-$name-$(date -u +%s)" --domains "$DOMAINS" --rate 5000 --burst 10000 --daily 100000000)
	id=$(printf '%s\n' "$created" | awk '/^id: /{print $2}')
	KEY=$(printf '%s\n' "$created" | awk '/^key: /{print $2}')
	unset created
	[ -n "$id" ] && [ "${KEY#fsk_}" != "$KEY" ] || { echo "key create falhou (id '$id')" >&2; exit 1; }
	echo "$id $name" >>"$DIR/keys.txt"
	echo "chave $id criada para $name; esperando 3 s (keyReload)"
	sleep 3
	# o docker run fica em segundo plano com a chave na entrada; --rm remove o container no fim
	(printf '%s\n' "$KEY" | setsid docker run -i --rm --name "fs-load-f8-$name" --network "$NET" --cpus 1 --memory 1g \
		-v "$out:/out" "$IMAGE" "$mode" -out /out "$@" >"$out/run.log" 2>&1 &)
	unset KEY
	sleep 2
	docker ps --filter "name=fs-load-f8-$name" --format '{{.Names}} {{.Status}}'
	;;
start-nokey)
	# modo sem chave (feed): mesmo container, sem criar chave
	name=$2 mode=$3
	shift 3
	out="$DIR/out-$name"
	mkdir -p "$out"
	(setsid docker run --rm --name "fs-load-f8-$name" --network "$NET" --cpus 1 --memory 1g \
		-v "$out:/out" "$IMAGE" "$mode" -out /out "$@" >"$out/run.log" 2>&1 </dev/null &)
	sleep 2
	docker ps --filter "name=fs-load-f8-$name" --format '{{.Names}} {{.Status}}'
	;;
stop)
	docker stop -t 20 "fs-load-f8-$2" >/dev/null 2>&1 || true
	;;
cleanup)
	for c in $(docker ps -a --filter name=fs-load-f8- --format '{{.Names}}'); do docker stop -t 20 "$c" >/dev/null 2>&1 || true; docker rm -f "$c" >/dev/null 2>&1 || true; done
	# revoga as chaves desta carga (keys.txt) e as load-f8-* que tenham sobrado de uma execução interrompida
	ids=$( { [ -f "$DIR/keys.txt" ] && awk '{print $1}' "$DIR/keys.txt"; $CLI key list | awk '$3 ~ /^load-f8-/ && $NF == "-" {print $1}'; } | sort -u)
	for id in $ids; do $CLI key revoke "$id" >/dev/null 2>&1 && echo "chave $id revogada" || echo "chave $id: revogação falhou ou já revogada"; done
	docker image rm "$IMAGE" >/dev/null 2>&1 || true
	docker ps -a --filter name=fs-load-f8- --format '{{.Names}}'
	;;
*)
	echo "uso: $0 image|start NAME MODE [flags]|stop NAME|cleanup" >&2
	exit 2
	;;
esac
