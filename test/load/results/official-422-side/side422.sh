#!/usr/bin/env bash
# Vigia lateral da task 422 (side247 da task 247 mais io.stat, CPU e o escritor do store), roda no finger-01: a cada
# 5 s, health (jsonl), /metrics do store e memória/pressões/IO/CPU do cgroup do store e da fatia. Segura
# /tmp/fs-load-running entre as rodadas com o token dado em $2 (o run.sh roda com FS_LOAD_LOCK_HELD=1). Para com
# SIGTERM (pkill -f side422).
OUT=${1:-/tmp/fs-load-422/side}
TOKEN=${2:-side422}
mkdir -p "$OUT"
CG=/sys/fs/cgroup/finger.slice/finger-sniffer.slice
ST=$CG/finger-sniffer-store.service
kv() { awk -v k="$2" '$1==k{print $2}' "$1"; }
while :; do
	[ -e /tmp/fs-load-running ] || echo "$TOKEN" >/tmp/fs-load-running
	t=$(date -u +%FT%TZ)
	h=$(curl -s -m 4 http://127.0.0.1:9001/api/v1/health)
	printf '{"t":"%s","health":%s}\n' "$t" "${h:-null}" >>"$OUT/health_watch.jsonl"
	{
		echo "# $t"
		curl -s -m 4 http://127.0.0.1:9001/metrics | grep -E '^fs_store_(ingest_backlog_seconds|ingest_pending_messages|stream_lost_total|db_bytes|db_fs_bytes|db_full_total|db_full_dropped_total|purged_total|wal_frames|flows_dropped_total|stray_packets_total|stray_midflow_total|connections_degraded_total|live_dropped_total|writer_seconds_(sum|count)|record_ready_seconds_(sum|count))'
	} >>"$OUT/metrics.txt"
	{
		echo "# $t"
		for c in store:$ST slice:$CG; do
			n=${c%%:*} d=${c#*:}
			echo "$n memory.current $(cat $d/memory.current)"
			for k in anon file shmem workingset_refault_file pgscan pgsteal; do echo "$n $k $(kv $d/memory.stat $k)"; done
			for k in high max oom oom_kill; do echo "$n events_$k $(kv $d/memory.events $k)"; done
			echo "$n mem_some $(sed -n 1p $d/memory.pressure)"
			echo "$n io_some $(sed -n 1p $d/io.pressure)"
			echo "$n io_full $(sed -n 2p $d/io.pressure)"
			echo "$n io_stat $(tr '\n' ' ' <$d/io.stat 2>/dev/null)"
			echo "$n cpu_usage_usec $(kv $d/cpu.stat usage_usec) nr_throttled $(kv $d/cpu.stat nr_throttled)"
		done
		echo "db $(stat -c '%n %s' /finger-sniffer/var/store/finger-sniffer.sqlite* | tr '\n' ' ')"
		echo "df $(df -B1 --output=size,used,avail /finger-sniffer/var/store | tail -1)"
	} >>"$OUT/store_mem.txt"
	since=$(date -u -d '-5 sec' +%FT%TZ)
	echo "# $t $(curl -s -m 4 "http://127.0.0.1:9001/api/v1/connections?since=$since&limit=1000" | jq -r '[.[].src.ip] | group_by(.) | map("\(.[0])=\(length)") | join(" ")')" >>"$OUT/foreign_watch.txt"
	sleep 5
done
