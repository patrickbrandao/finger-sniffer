#!/usr/bin/env bash
# Lado servidor da carga da F8 (tasks 285 e 396; spec 017 RF-17, spec 018 RNF-01/RNF-02, ADR 0071), roda no
# finger-01 em /tmp/fs-load-f8 (copiado para lá com o botload linux/amd64 e o f8-side.sh; passos em RESULTS.md,
# seção F8). O botload roda como unit transitória do systemd, sem Docker (ADR 0071):
#
#   f8-remote.sh install                       copia o botload para /finger-sniffer/tmp/fs-load-f8-botload
#   f8-remote.sh start NAME MODE [flags...]    cria uma chave de teste pela CLI do bot e sobe a unit transitória
#                                              finger-sniffer-load-f8-NAME (fora de finger-sniffer.slice, 1 CPU,
#                                              1G, sem swap) com o botload MODE e a chave pela entrada padrão; o
#                                              alvo padrão do botload é http://10.249.255.254:9003 (origem
#                                              10.249.255.254, dentro de 10.249.0.0/16); saída em
#                                              /tmp/fs-load-f8/out-NAME
#   f8-remote.sh start-nokey NAME MODE [flags]  igual ao start, sem chave (modo feed)
#   f8-remote.sh stop NAME                     para a unit (o botload termina limpo com SIGTERM)
#   f8-remote.sh status                        lista as units finger-sniffer-load-f8-*
#   f8-remote.sh cleanup                       para as units finger-sniffer-load-f8-*, revoga as chaves load-f8-*
#                                              e apaga o binário
#
# A chave só existe na variável KEY deste shell e num FIFO sem conteúdo em disco, lido pela unit como entrada
# padrão: nunca em argumento, propriedade da unit, arquivo ou log (a saída do key create não é gravada; o id, que
# não é segredo, vai para keys.txt para a revogação).
set -euo pipefail
# variáveis FS_LOAD_F8_* só para o teste com stubs (f8remote_test.go)
DIR=${FS_LOAD_F8_DIR:-/tmp/fs-load-f8}
BIN=${FS_LOAD_F8_BIN:-/finger-sniffer/tmp/fs-load-f8-botload}
UNIT_PREFIX=finger-sniffer-load-f8-
# teto de vida da unit: se o cleanup não rodar, o systemd a para sozinho
MAX_RUNTIME=${FS_LOAD_F8_MAX_RUNTIME:-3h}
CLI="runuser -u finger-sniffer -- /finger-sniffer/bin/finger-sniffer-bot"
DOMAINS="fs-load.example,*.hostile.fs-load.example"

# units da carga ainda carregadas (ativas ou falhas)
load_units() {
	systemctl list-units --all --plain --no-legend "${UNIT_PREFIX}*.service" | awk '{print $1}'
}

stop_unit() {
	systemctl stop "$1" >/dev/null 2>&1 || true
	systemctl reset-failed "$1" >/dev/null 2>&1 || true
}

# launch NAME MODE STDIN [flags...]: sobe a unit transitória; STDIN é o caminho do FIFO da chave ou "null"
launch() {
	local name=$1 mode=$2 stdin=$3 input
	local out="$DIR/out-$name"
	shift 3
	if [ "$stdin" = null ]; then input=null; else input="file:$stdin"; fi
	systemd-run --unit="$UNIT_PREFIX$name" --collect --quiet \
		-p CPUQuota=100% -p MemoryMax=1G -p MemorySwapMax=0 -p RuntimeMaxSec="$MAX_RUNTIME" \
		-p KillSignal=SIGTERM -p TimeoutStopSec=20 \
		-p StandardInput="$input" -p StandardOutput="append:$out/run.log" -p StandardError="append:$out/run.log" \
		"$BIN" "$mode" -out "$out" "$@"
}

case "${1:-}" in
install)
	mkdir -p "$(dirname "$BIN")"
	cp "$DIR/botload" "$BIN"
	chmod 0755 "$BIN"
	ls -l "$BIN"
	;;
start)
	name=$2 mode=$3
	shift 3
	[ -x "$BIN" ] || { echo "binário $BIN ausente: rode install" >&2; exit 1; }
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
	# FIFO num diretório 0700: o fd 3 o abre para leitura e escrita (não bloqueia), guarda a linha da chave no
	# buffer do pipe até a unit abrir o FIFO; fechar o fd depois dá EOF ao botload
	fifo_dir=$(mktemp -d "$DIR/key.XXXXXX")
	chmod 0700 "$fifo_dir"
	mkfifo -m 0600 "$fifo_dir/key"
	# se algo falhar ou chegar sinal no meio, a unit para e o FIFO some
	trap 'exec 3>&- 2>/dev/null || true; rm -rf "$fifo_dir"; stop_unit "$UNIT_PREFIX$name"' ERR INT TERM
	exec 3<>"$fifo_dir/key"
	printf '%s\n' "$KEY" >&3
	unset KEY
	launch "$name" "$mode" "$fifo_dir/key" "$@"
	sleep 2
	exec 3>&-
	rm -rf "$fifo_dir"
	trap - ERR INT TERM
	systemctl is-active "$UNIT_PREFIX$name" || true
	;;
start-nokey)
	name=$2 mode=$3
	shift 3
	[ -x "$BIN" ] || { echo "binário $BIN ausente: rode install" >&2; exit 1; }
	mkdir -p "$DIR/out-$name"
	trap 'stop_unit "$UNIT_PREFIX$name"' ERR INT TERM
	launch "$name" "$mode" null "$@"
	trap - ERR INT TERM
	sleep 2
	systemctl is-active "$UNIT_PREFIX$name" || true
	;;
stop)
	stop_unit "$UNIT_PREFIX$2"
	;;
status)
	load_units
	;;
cleanup)
	# o trap garante o binário apagado mesmo se a revogação falhar ou chegar sinal
	trap 'rm -f "$BIN"' EXIT
	for u in $(load_units); do stop_unit "$u"; done
	# revoga as chaves desta carga (keys.txt) e as load-f8-* que tenham sobrado de uma execução interrompida
	ids=$( { [ -f "$DIR/keys.txt" ] && awk '{print $1}' "$DIR/keys.txt"; $CLI key list | awk '$3 ~ /^load-f8-/ && $NF == "-" {print $1}'; } | sort -u)
	for id in $ids; do $CLI key revoke "$id" >/dev/null 2>&1 && echo "chave $id revogada" || echo "chave $id: revogação falhou ou já revogada"; done
	rm -rf "$DIR"/key.*
	load_units
	;;
*)
	echo "uso: $0 install|start NAME MODE [flags]|start-nokey NAME MODE [flags]|stop NAME|status|cleanup" >&2
	exit 2
	;;
esac
