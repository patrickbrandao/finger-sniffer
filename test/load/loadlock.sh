# shellcheck shell=bash
# Trava da carga no servidor (/tmp/fs-load-running; spec 017 RF-13, task 361), comum a run.sh e budget.sh.
# Carregue com ". test/load/loadlock.sh" depois de definir ssh_vps (ssh para o servidor) e REMOTE (diretório remoto
# da carga). Enquanto a trava existe, make deploy e o e2e do verify-full recusam rodar.
#
#   load_lock_take     cria a trava com um token próprio, de forma atômica (set -C); se ela já existir, recusa
#                      mostrando o dono e não toca em nada da outra carga (nem a trava, nem o loadmon, nem REMOTE).
#   load_lock_release  no fim (trap EXIT): para o loadmon e apaga REMOTE só se esta execução tomou a trava, e apaga a
#                      trava só se o token nela ainda for o nosso.
#
# FS_LOAD_LOCK_HELD=1: a trava já é segurada por um vigia desta mesma carga (ex.: test/load/f8-side.sh, que a
# mantém entre as rodadas da F8). load_lock_take exige que ela exista e não a cria; load_lock_release para o loadmon e
# apaga REMOTE, mas deixa a trava para o vigia.
LOAD_LOCK="${FS_LOAD_LOCK:-/tmp/fs-load-running}"
LOAD_TOKEN="$(whoami)@$(hostname -s):$$ $(date -u +%FT%TZ)"
LOAD_MINE=0

load_lock_take() {
	local rc=0
	if [ "${FS_LOAD_LOCK_HELD:-0}" = 1 ]; then
		ssh_vps "[ -e '$LOAD_LOCK' ]" || {
			echo "FS_LOAD_LOCK_HELD=1, mas $LOAD_LOCK não existe no servidor (o vigia está rodando?)" >&2
			return 1
		}
		LOAD_MINE=held
		return 0
	fi
	ssh_vps "set -C; echo '$LOAD_TOKEN' > '$LOAD_LOCK'" 2>/dev/null || rc=$?
	case "$rc" in
	0) LOAD_MINE=1 ;;
	255)
		echo "servidor inacessível ao tomar $LOAD_LOCK" >&2
		return 1
		;;
	*)
		echo "outra carga em andamento: $LOAD_LOCK = $(ssh_vps "cat '$LOAD_LOCK'" 2>/dev/null)" >&2
		return 1
		;;
	esac
}

load_lock_release() {
	case "$LOAD_MINE" in
	1)
		ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 1; rm -rf '$REMOTE'; \
			if [ \"\$(cat '$LOAD_LOCK' 2>/dev/null)\" = '$LOAD_TOKEN' ]; then rm -f '$LOAD_LOCK'; fi" >/dev/null 2>&1 || true
		;;
	held)
		ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 1; rm -rf '$REMOTE'" >/dev/null 2>&1 || true
		;;
	esac
	LOAD_MINE=0
}
