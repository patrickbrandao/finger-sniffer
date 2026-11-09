#!/usr/bin/env bash
# Parte remota do regen.sh: roda na vps602.
#   syn: no diretório com os pcaps de SYN; entrada JA4 e FP; saída ja4t.json e p0f.log.
#   tls: no diretório com src/ (pcaps completos da FoxIO) e bin/ (ClientHellos crus); entrada JA4;
#        saída em out/: pcaps reduzidos, ja4.golden.json e ja3.golden.json.
set -euo pipefail
MODE="${1:-syn}"
: "${JA4:?}"

# ja4_json <pcap> [flags]: o ja4 -j emite um objeto JSON por linha e também escreve logs no stdout
ja4_json() {
	"$JA4" -j "$@" </dev/null 2>/dev/null | grep '^{' | paste -sd, - || true
}

if [ "$MODE" = syn ]; then
	: "${FP:?}"
	first=1
	printf '{' > ja4t.json
	for f in *.pcap *.pcapng; do
		[ -f "$f" ] || continue
		out=$(ja4_json "$f")
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
	exit 0
fi

mkdir -p out
# 1) FoxIO: só os fluxos TCP com ClientHello, até o frame que fecha o ClientHello (o que vem antes, como
#    CONNECT ou SOCKS, fica para o tshark reconhecer o TLS)
for f in src/*; do
	b=$(basename "$f")
	filter=$(tshark -r "$f" -Y 'tls.handshake.type == 1 && tcp' -T fields -e tcp.stream -e frame.number 2>/dev/null |
		awk '!seen[$1]++ { printf "%s(tcp.stream == %s && frame.number <= %s)", sep, $1, $2; sep=" || " }')
	[ -n "$filter" ] || continue
	tshark -r "$f" -Y "$filter" -w "out/foxio-${b%.*}.pcapng" 2>/dev/null
done
# 2) clientes reais: o ClientHello cru vira um pcap TCP
for f in bin/*.bin; do
	b=$(basename "$f" .bin)
	od -Ax -tx1 -v "$f" > "out/$b.txt"
	text2pcap -q -T 50000,443 "out/$b.txt" "out/client-$b.pcap" >/dev/null 2>&1
	rm -f "out/$b.txt"
done
# 3) gabaritos
cd out
first=1
printf '{' > ja4.golden.json
for f in *.pcap *.pcapng; do
	sorted=$(ja4_json -r "$f")
	orig=$(ja4_json -r -O "$f")
	[ "$first" = 1 ] || printf ',' >> ja4.golden.json
	first=0
	printf '"%s":{"sorted":[%s],"original":[%s]}' "$f" "$sorted" "$orig" >> ja4.golden.json
done
printf '}\n' >> ja4.golden.json
first=1
printf '{' > ja3.golden.json
for f in *.pcap *.pcapng; do
	out=$(tshark -r "$f" -Y 'tls.handshake.type == 1 && tcp' -T fields -E separator=';' \
		-e tcp.stream -e ip.src -e ipv6.src -e tcp.srcport -e ip.dst -e ipv6.dst -e tcp.dstport \
		-e tls.handshake.ja3_full -e tls.handshake.ja3 -e tls.handshake.ja4 2>/dev/null |
		awk -F';' '{ src = ($2 != "") ? $2 : $3; dst = ($5 != "") ? $5 : $6;
			printf "%s{\"stream\":%s,\"src\":\"%s\",\"src_port\":%s,\"dst\":\"%s\",\"dst_port\":%s,\"ja3\":\"%s\",\"ja3_md5\":\"%s\",\"tshark_ja4\":\"%s\"}", sep, $1, src, $4, dst, $7, $8, $9, $10; sep="," }')
	[ "$first" = 1 ] || printf ',' >> ja3.golden.json
	first=0
	printf '"%s":[%s]' "$f" "$out" >> ja3.golden.json
done
printf '}\n' >> ja3.golden.json
tshark -v | head -1 > VERSIONS.txt
"$JA4" --version >> VERSIONS.txt 2>/dev/null || true
