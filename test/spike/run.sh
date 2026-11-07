#!/usr/bin/env bash
# Roda o spike de carga (task 006) a partir do Mac.
#
#   test/spike/run.sh [duração] [conexões_novas_por_s]     # padrão: 10m 50
#
# Na vps602 cada programa roda numa unit transitória (systemd-run) com o mesmo MemoryMax/GOMEMLIMIT das
# units reais (spec 016 RF-07). O NATS é o da unit finger-sniffer-nats. Resultados em tmp/spike-results/.
set -euo pipefail

DUR="${1:-10m}"
RATE="${2:-50}"
HOST="${FS_VPS_SSH:-root@vps602.tmsoft.com.br}"
PORT="${FS_VPS_PORT:-48022}"
TARGET_IP="${FS_SPIKE_TARGET_IP:-172.233.24.85}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/tmp/spike-results/$(date -u +%Y%m%dT%H%M%SZ)-${DUR}-${RATE}${FS_SPIKE_LABEL:+-$FS_SPIKE_LABEL}"
BIN="$ROOT/tmp/spike-bin"
R=/root/spike
ssh_() { ssh -p "$PORT" -o BatchMode=yes "$HOST" "$@"; }

mkdir -p "$OUT" "$BIN"
cd "$ROOT"
echo "== build"
for c in spikecap spikestore spikeweb spikemon; do
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags spike -trimpath -o "$BIN/$c" "./test/spike/cmd/$c"
done
go build -tags spike -o "$BIN/spikeload" ./test/spike/cmd/spikeload

echo "== envio"
ssh_ "systemctl stop spike-cap spike-store spike-web spike-mon spike-vmstat 2>/dev/null || true; rm -rf $R; mkdir -p $R"
scp -q -P "$PORT" "$BIN"/spikecap "$BIN"/spikestore "$BIN"/spikeweb "$BIN"/spikemon "$HOST:$R/"

echo "== início na vps602"
ssh_ "set -e
systemctl reset-failed spike-cap spike-store spike-web spike-mon spike-vmstat 2>/dev/null || true
run() { name=\$1; mem=\$2; gomem=\$3; shift 3
  systemd-run --quiet --unit=\$name -p MemoryMax=\$mem -E GOMEMLIMIT=\$gomem \
    -p StandardOutput=file:$R/\$name.jsonl -p StandardError=file:$R/\$name.err \"\$@\"; }
run spike-web   96M  80MiB  $R/spikeweb -addr $TARGET_IP:8080
run spike-store 384M 320MiB $R/spikestore -db $R/spike.sqlite ${STORE_ARGS:--retention 2m}
sleep 2
run spike-cap   96M  80MiB  $R/spikecap -iface eth0
run spike-mon   32M  24MiB  $R/spikemon -procs spikecap,nats-server,spikestore,spikeweb
systemd-run --quiet --unit=spike-vmstat -p StandardOutput=file:$R/vmstat.txt vmstat -t 1
sleep 2
systemctl is-active spike-web spike-store spike-cap spike-mon"

echo "== carga: $RATE conexões/s por $DUR"
"$BIN/spikeload" -target "http://$TARGET_IP:8080" -rate "$RATE" -duration "$DUR" | tee "$OUT/load.jsonl"

echo "== drenagem e parada"
sleep 15
ssh_ "systemctl stop spike-cap; sleep 5; systemctl stop spike-store spike-mon spike-web spike-vmstat; sleep 1
ls -la $R/spike.sqlite* | awk '{print \$5, \$9}' > $R/db-size.txt
cat /proc/loadavg > $R/loadavg.txt
$R/spikestore -delete-stream || true"
scp -q -P "$PORT" "$HOST:$R/*.jsonl" "$HOST:$R/*.err" "$HOST:$R/*.txt" "$OUT/" || true
ssh_ "rm -rf $R"
echo "== resultados em $OUT"
for f in spike-store spike-cap spike-mon; do echo "-- $f"; tail -1 "$OUT/$f.jsonl" 2>/dev/null; done
echo "-- load"; tail -1 "$OUT/load.jsonl"
