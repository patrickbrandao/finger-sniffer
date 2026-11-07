#!/usr/bin/env bash
# Parte remota do regen.sh: roda na vps602 dentro do diretório com os pcaps.
# Entrada: JA4 (binário do ja4 da FoxIO) e FP (p0f.fp). Saída: ja4t.json e p0f.log no diretório atual.
set -euo pipefail
: "${JA4:?}" "${FP:?}"
first=1
printf '{' > ja4t.json
for f in *.pcap *.pcapng; do
	[ -f "$f" ] || continue
	# o ja4 -j emite um objeto JSON por linha e também escreve logs no stdout: só as linhas JSON contam
	out=$("$JA4" -j "$f" </dev/null 2>/dev/null | grep '^{' | paste -sd, - || true)
	[ "$first" = 1 ] || printf ',' >> ja4t.json
	first=0
	printf '"%s":[%s]' "$f" "$out" >> ja4t.json
done
printf '}\n' >> ja4t.json
: > p0f.log
for f in *.pcap *.pcapng; do
	[ -f "$f" ] || continue
	rm -f one.log
	p0f -f "$FP" -r "$f" -o one.log </dev/null >/dev/null 2>&1 || true
	[ -f one.log ] || continue
	grep -E ' mod=(syn|syn[+]ack)[|]' one.log | sed "s|^|$f |" >> p0f.log || true
done
rm -f one.log
