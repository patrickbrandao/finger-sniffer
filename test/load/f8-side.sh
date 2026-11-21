#!/usr/bin/env bash
# Vigia lateral da carga da F8 (task 285), roda no finger-01: a cada 5 s, o health do store (com as métricas bot_*
# do heartbeat), o health do bot, o /metrics do store e memória/CPU/pressões do cgroup do bot, do store e da fatia.
# Segura /tmp/fs-load-running entre as rodadas: rode o run.sh com FS_LOAD_LOCK_HELD=1 (ele não a cria nem a apaga;
# test/load/loadlock.sh, task 361). Para com SIGTERM (pkill -f f8-side).
OUT=${1:-/tmp/fs-load-f8/side}
mkdir -p "$OUT"
CG=/sys/fs/cgroup/finger.slice/finger-sniffer.slice
kv() { awk -v k="$2" '$1==k{print $2}' "$1"; }
while :; do
	[ -e /tmp/fs-load-running ] || date -u +%FT%TZ >/tmp/fs-load-running
	t=$(date -u +%FT%TZ)
	h=$(curl -s -m 4 http://127.0.0.1:9001/api/v1/health)
	printf '{"t":"%s","health":%s}\n' "$t" "${h:-null}" >>"$OUT/health_watch.jsonl"
	b=$(curl -s -m 4 http://127.0.0.1:9003/bot/v1/health)
	printf '{"t":"%s","bot":%s}\n' "$t" "${b:-null}" >>"$OUT/bot_health.jsonl"
	{
		echo "# $t"
		curl -s -m 4 http://127.0.0.1:9001/metrics | grep -E '^fs_store_(ingest_backlog_seconds|ingest_pending_messages|stream_lost_total|db_bytes|db_fs_bytes|db_full_total|db_full_dropped_total|purged_total|wal_frames|flows_dropped_total|live_dropped_total)'
	} >>"$OUT/metrics.txt"
	{
		echo "# $t"
		for c in bot:$CG/finger-sniffer-bot.service store:$CG/finger-sniffer-store.service slice:$CG; do
			n=${c%%:*} d=${c#*:}
			echo "$n memory.current $(cat "$d/memory.current" 2>/dev/null)"
			for k in anon file shmem; do echo "$n $k $(kv "$d/memory.stat" $k)"; done
			for k in high max oom oom_kill; do echo "$n events_$k $(kv "$d/memory.events" $k)"; done
			echo "$n mem_some $(sed -n 1p "$d/memory.pressure" 2>/dev/null)"
			echo "$n cpu_usage_usec $(kv "$d/cpu.stat" usage_usec) nr_throttled $(kv "$d/cpu.stat" nr_throttled)"
		done
		echo "botdb $(stat -c '%n %s' /finger-sniffer/var/bot/bot.db* 2>/dev/null | tr '\n' ' ')"
	} >>"$OUT/cgroup.txt"
	sleep 5
done
