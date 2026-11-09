#!/usr/bin/env bash
# Gera o golden pcap de cliente Windows (task 088) a partir de um pcap público da FoxIO, porque o projeto não
# tem máquina Windows para capturar contra a vps602.
#
# Fonte: https://github.com/FoxIO-LLC/ja4, pasta pcap/, commit c6469a7b0dbf8fe963810162429fbfd9d1acc4d5,
# arquivo latest.pcapng (licença BSD 3-Clause, cópia em
# pkg/fingerprint/internal/pcaptest/testdata/syn/LICENSE-FoxIO-BSD3). É uma captura feita no próprio cliente
# Windows (janela 64240, MSS 1460, wscale 8, sem timestamps; p0f -r: "Windows NT kernel").
#
# O pcap fica só com os fluxos TCP que têm SYN do cliente, convertido de pcapng para pcap (o ingest de teste
# lê pcap). Os IPs são privados (172.16.225.48) ou de servidores públicos da captura original: nada a
# anonimizar. As saídas de referência são geradas na vps602 com as mesmas ferramentas e campos do collect.sh:
#   windows-foxio.tshark.json, windows-foxio.ja4.jsonl, windows-foxio.p0f.txt
#
# Uso: test/golden/foxio-windows.sh   (FOXIO_PCAP_DIR aponta para a pasta pcap/ do clone; senão clona)
set -euo pipefail
cd "$(dirname "$0")"

VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
SSH_PORT="${VPS_PORT:-48022}"
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
FP="${P0F_FP:-/finger-sniffer/etc/p0f.fp}"
FOXIO_COMMIT=c6469a7b0dbf8fe963810162429fbfd9d1acc4d5
NAME=windows-foxio
R=/tmp/fs-golden-windows
OUT=pcaps
LOCAL_TMP=$(mktemp -d)

remote() { ssh -p "$SSH_PORT" -o BatchMode=yes "$VPS" "$@" </dev/null; }
cleanup() {
	set +e
	remote "rm -rf $R"
	rm -rf "$LOCAL_TMP"
}
trap cleanup EXIT

SRC="${FOXIO_PCAP_DIR:-$(git rev-parse --show-toplevel)/tmp/ref/ja4/pcap}"
if [ ! -f "$SRC/latest.pcapng" ]; then
	git clone -q https://github.com/FoxIO-LLC/ja4 "$LOCAL_TMP/ja4"
	git -C "$LOCAL_TMP/ja4" checkout -q "$FOXIO_COMMIT"
	SRC="$LOCAL_TMP/ja4/pcap"
fi

remote "rm -rf $R && mkdir -p $R"
scp -q -P "$SSH_PORT" "$SRC/latest.pcapng" "$VPS:$R/latest.pcapng"

FIELDS="frame.number frame.time_epoch ip.src ip.dst ipv6.src ipv6.dst ip.ttl ipv6.hlim ip.id ip.flags.df ip.dsfield \
ipv6.tclass ipv6.flow tcp.stream tcp.srcport tcp.dstport tcp.flags tcp.seq_raw tcp.ack_raw tcp.len tcp.window_size_value \
tcp.option_kind tcp.options.mss_val tcp.options.wscale.shift tcp.options.timestamp.tsval tcp.analysis.ack_rtt \
tcp.analysis.retransmission tcp.analysis.out_of_order tcp.analysis.keep_alive tcp.analysis.zero_window"
EFLAGS=""
for f in $FIELDS; do EFLAGS="$EFLAGS -e $f"; done

# fluxos com SYN do cliente → filtro tcp.stream in {...} → pcap; depois as três saídas de referência
remote "cd $R && \
	S=\$(tshark -r latest.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.stream | sort -un | paste -sd, -) && \
	tshark -r latest.pcapng -Y \"tcp.stream in {\$S}\" -F pcap -w $NAME.pcap && \
	tshark -r $NAME.pcap -T json $EFLAGS > $NAME.tshark.json 2>/dev/null && \
	$JA4 -j $NAME.pcap 2>/dev/null | grep '^{' > $NAME.ja4.jsonl || true; \
	rm -f p.log; p0f -f $FP -r $NAME.pcap -o p.log >/dev/null 2>&1; \
	grep -E ' mod=(syn|syn[+]ack)[|]' p.log > $NAME.p0f.txt || true"

mkdir -p "$OUT"
for ext in pcap tshark.json ja4.jsonl p0f.txt; do
	scp -q -P "$SSH_PORT" "$VPS:$R/$NAME.$ext" "$OUT/$NAME.$ext"
done
n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$OUT/$NAME.tshark.json")
echo "[golden] $NAME: $n pacotes, $(wc -l <"$OUT/$NAME.ja4.jsonl" | tr -d ' ') JA4T, $(wc -l <"$OUT/$NAME.p0f.txt" | tr -d ' ') p0f"
