#!/usr/bin/env bash
# Carga de 10 min contra o finger-01 (task 068, spec 017 RF-13, ADRs 0022 e 0039). Roda na máquina cliente.
#
#   test/load/run.sh [flags do loadgen run]
#
# Variáveis:
#   OUT          pasta dos resultados (padrão: test/load/results/<data UTC>)
#   FS_VPS_SSH   destino ssh (padrão root@finger-01.tmsoft.com.br)
#   FS_VPS_PORT  porta ssh (padrão 48022)
#   QUIC_TARGET  meta p95 do registro QUIC no relatório (padrão 500ms, ADR 0026, que substituiu a 0024)
#   FS_LOAD_LOCK_HELD=1  a trava /tmp/fs-load-running já é segurada por um vigia desta carga (ex.: f8-side.sh na F8);
#                o run.sh exige que ela exista e não a cria nem a apaga (test/load/loadlock.sh)
#
# Com outra carga em andamento (trava presente) o run.sh recusa antes de compilar e não toca na outra (task 361).
#
# Passos: compila o loadgen (local) e o loadmon (linux/amd64), grava o conntrack -S (antes), sobe o loadmon no
# servidor (CPU/RAM/nr_throttled por unit a cada 1 s, em finger.slice/finger-sniffer.slice), roda a carga, para o
# loadmon, grava o conntrack -S (depois) e o "table full" do dmesg, traz o cgroup.csv, gera o relatório e limpa o
# servidor.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VPS_SSH="${FS_VPS_SSH:-root@finger-01.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"
OUT="${OUT:-test/load/results/$(date -u +%Y%m%dT%H%M%SZ)}"
QUIC_TARGET="${QUIC_TARGET:-500ms}"
BIN="tmp/load"
REMOTE=/tmp/fs-load

ssh_vps() { ssh -p "$VPS_PORT" -o BatchMode=yes "$VPS_SSH" "$@"; }

# /tmp/fs-load-running no servidor: enquanto existir, make deploy e o e2e do verify-full recusam (task 361).
# shellcheck source=test/load/loadlock.sh
. "$ROOT/test/load/loadlock.sh"
trap load_lock_release EXIT
load_lock_take || exit 1

mkdir -p "$BIN" "$OUT"
go build -tags load -o "$BIN/loadgen" ./test/load/cmd/loadgen
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags load -o "$BIN/loadmon" ./test/load/cmd/loadmon

# com a trava nossa, um loadmon que sobrou de uma carga interrompida pode ser parado
ssh_vps "pkill -INT -f '[l]oadmon sample' || true; mkdir -p $REMOTE"
scp -q -P "$VPS_PORT" "$BIN/loadmon" "$VPS_SSH:$REMOTE/loadmon"
ssh_vps "conntrack -S 2>&1 || true" >"$OUT/conntrack-antes.txt"
ssh_vps "setsid -f $REMOTE/loadmon sample -out $REMOTE/cgroup.csv -interval 1s >/dev/null 2>&1 </dev/null"

"$BIN/loadgen" run -out "$OUT" \
	-clock-cmd "ssh -p $VPS_PORT -o BatchMode=yes $VPS_SSH $REMOTE/loadmon clock" "$@" 2>&1 | tee "$OUT/run.log"

ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 2"
ssh_vps "conntrack -S 2>&1 || true" >"$OUT/conntrack-depois.txt"
ssh_vps "dmesg -T 2>/dev/null | grep -i 'table full' | tail -20 || true" >"$OUT/conntrack-dmesg.txt"
scp -q -P "$VPS_PORT" "$VPS_SSH:$REMOTE/cgroup.csv" "$OUT/cgroup.csv"
"$BIN/loadgen" report -dir "$OUT" -quic-target "$QUIC_TARGET"
echo "resultados em $OUT"
