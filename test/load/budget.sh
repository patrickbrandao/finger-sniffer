#!/usr/bin/env bash
# Carga do orçamento de memória de entrada do web contra a vps602 (task 214; spec 005 RF-12, ADR 0033).
# Roda na máquina cliente.
#
#   test/load/budget.sh [flags do budgetload]
#
# Variáveis: OUT (padrão tmp/load/raw/budget-<data UTC>), FS_VPS_SSH, FS_VPS_PORT, RESTART_WEB=1 (reinicia o web
# antes e espera o health ok: o memory.peak passa a ser só desta janela; task 215).
#
# Segura /tmp/fs-load-running na vps602 (ninguém implanta nem roda e2e), anota NRestarts, memory.peak e o PID do
# web, sobe o loadmon (memória por unit a cada 1 s), roda o budgetload, traz o cgroup.csv e grava em
# $OUT/web.txt o estado do web depois (NRestarts, memory.peak, PID, OOM no journal) e o pico do memory.current.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VPS_SSH="${FS_VPS_SSH:-root@vps602.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"
OUT="${OUT:-tmp/load/raw/budget-$(date -u +%Y%m%dT%H%M%SZ)}"
BIN="tmp/load"
REMOTE=/tmp/fs-load
LOCK=/tmp/fs-load-running
CG=/sys/fs/cgroup/system.slice/finger-sniffer-web.service

ssh_vps() { ssh -p "$VPS_PORT" -o BatchMode=yes "$VPS_SSH" "$@"; }
cleanup() {
	ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 1; rm -rf $REMOTE $LOCK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

web_state() {
	ssh_vps "systemctl show finger-sniffer-web -p NRestarts -p MainPID -p ActiveEnterTimestamp -p MemoryMax; \
		echo memory.peak=\$(cat $CG/memory.peak); echo memory.current=\$(cat $CG/memory.current); \
		grep -E '^(oom|oom_kill|max) ' $CG/memory.events | sed 's/ /=/'"
}

mkdir -p "$BIN" "$OUT"
go build -tags load -o "$BIN/budgetload" ./test/load/cmd/budgetload
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags load -o "$BIN/loadmon" ./test/load/cmd/loadmon

ssh_vps "if [ -e $LOCK ]; then echo 'outra carga em andamento' >&2; exit 1; fi; mkdir -p $REMOTE; date -u +%FT%TZ > $LOCK"
scp -q -P "$VPS_PORT" "$BIN/loadmon" "$VPS_SSH:$REMOTE/loadmon"
if [ "${RESTART_WEB:-0}" = 1 ]; then
	ssh_vps "systemctl restart finger-sniffer-web"
	for _ in $(seq 60); do
		st=$(curl -fsS --max-time 3 "http://${VPS_SSH#*@}:9001/api/v1/health" 2>/dev/null |
			python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["web"]["status"])' 2>/dev/null || true)
		[ "$st" = ok ] && break
		sleep 1
	done
	[ "$st" = ok ] || { echo "web não voltou ok depois do restart" >&2; exit 1; }
	sleep 5
fi
{
	echo "# antes ($(date -u +%FT%TZ))"
	web_state
} >"$OUT/web.txt"
START=$(date -u +'%F %T')
ssh_vps "setsid -f $REMOTE/loadmon sample -out $REMOTE/cgroup.csv -interval 1s >/dev/null 2>&1 </dev/null"

"$BIN/budgetload" -out "$OUT" "$@" 2>&1 | tee "$OUT/run.txt"

ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 2"
scp -q -P "$VPS_PORT" "$VPS_SSH:$REMOTE/cgroup.csv" "$OUT/cgroup.csv"
{
	echo "# depois ($(date -u +%FT%TZ))"
	web_state
	echo "# pico do memory.current do web nas amostras de 1 s (bytes)"
	awk -F, '$2=="web" && $4>m {m=$4} END {print "mem_current_max=" m}' "$OUT/cgroup.csv"
	awk -F, '$2=="web" && $5>m {m=$5} END {print "anon_max=" m}' "$OUT/cgroup.csv"
	echo "# memória do web por janela de 30 s (kernel = memory.current − anon − file)"
	"$BIN/budgetload" -analyze "$OUT/cgroup.csv"
	echo "# journal do web durante a carga (OOM, reinício, pânico)"
	ssh_vps "journalctl -u finger-sniffer-web --since '$START UTC' --no-pager -o short-iso |
		grep -iE 'oom|killed|panic|started|stopped' | tail -20" || true
} >>"$OUT/web.txt"
cat "$OUT/web.txt"
echo "resultados em $OUT"
