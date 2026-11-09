#!/usr/bin/env bash
# Carga de 10 min contra a vps602 (task 068, spec 017 RF-13, ADR 0022). Roda na máquina cliente.
#
#   test/load/run.sh [flags do loadgen run]
#
# Variáveis:
#   OUT          pasta dos resultados (padrão: test/load/results/<data UTC>)
#   FS_VPS_SSH   destino ssh (padrão root@vps602.tmsoft.com.br)
#   FS_VPS_PORT  porta ssh (padrão 48022)
#   QUIC_TARGET  meta p95 do registro QUIC no relatório (padrão 3s, ADR 0024; 500ms depois da task 090)
#
# Passos: compila o loadgen (local) e o loadmon (linux/amd64), sobe o loadmon na vps602 (CPU/RAM por unit a
# cada 1 s), roda a carga, para o loadmon, traz o cgroup.csv, gera o relatório e limpa a vps602.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VPS_SSH="${FS_VPS_SSH:-root@vps602.tmsoft.com.br}"
VPS_PORT="${FS_VPS_PORT:-48022}"
OUT="${OUT:-test/load/results/$(date -u +%Y%m%dT%H%M%SZ)}"
QUIC_TARGET="${QUIC_TARGET:-3s}"
BIN="tmp/load"
REMOTE=/tmp/fs-load

ssh_vps() { ssh -p "$VPS_PORT" -o BatchMode=yes "$VPS_SSH" "$@"; }

# /tmp/fs-load-running na vps602: enquanto existir, os outros agentes não implantam nem rodam e2e.
LOCK=/tmp/fs-load-running
cleanup() {
	ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 1; rm -rf $REMOTE $LOCK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$BIN" "$OUT"
go build -tags load -o "$BIN/loadgen" ./test/load/cmd/loadgen
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags load -o "$BIN/loadmon" ./test/load/cmd/loadmon

# nada de outra carga em andamento
ssh_vps "pkill -INT -f '[l]oadmon sample' || true; mkdir -p $REMOTE; date -u +%FT%TZ > $LOCK"
scp -q -P "$VPS_PORT" "$BIN/loadmon" "$VPS_SSH:$REMOTE/loadmon"
ssh_vps "setsid -f $REMOTE/loadmon sample -out $REMOTE/cgroup.csv -interval 1s >/dev/null 2>&1 </dev/null"

"$BIN/loadgen" run -out "$OUT" \
	-clock-cmd "ssh -p $VPS_PORT -o BatchMode=yes $VPS_SSH $REMOTE/loadmon clock" "$@" 2>&1 | tee "$OUT/run.log"

ssh_vps "pkill -INT -f '[l]oadmon sample' || true; sleep 2"
scp -q -P "$VPS_PORT" "$VPS_SSH:$REMOTE/cgroup.csv" "$OUT/cgroup.csv"
"$BIN/loadgen" report -dir "$OUT" -quic-target "$QUIC_TARGET"
echo "resultados em $OUT"
