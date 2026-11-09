#!/usr/bin/env bash
# Regenera os gabaritos a partir das ferramentas oficiais, executadas na vps602.
#
#   syn: ja4 (FoxIO, Rust, compilado em /root/ja4-rust) → ja4t.golden.json
#        p0f 3.09b (Debian, `p0f -r`) com o mesmo p0f.fp do deploy → p0f.golden.log
#   tls: pcaps completos da FoxIO reduzidos aos fluxos com ClientHello TCP → tls/foxio-*.pcapng,
#        ClientHellos de clientes reais de pkg/tlsparse/testdata (text2pcap) → tls/client-*.pcap,
#        ja4 -j -r (e -O) → tls/ja4.golden.json, tshark 4.4 (ja3) → tls/ja3.golden.json
#   quic: pcaps da FoxIO com QUIC reduzidos aos Initials do cliente → quic/*.pcapng,
#        ja4 -j -r (e -O) → quic/ja4.golden.json, tshark 4.4 (cabeçalho, frames, transport params, ja3)
#        → quic/tshark.golden.json
#
# Uso: pkg/fingerprint/internal/pcaptest/testdata/regen.sh [all|syn|tls|quic]
# Os pcaps completos da FoxIO vêm de FOXIO_PCAP_DIR ou de um clone do repositório no commit fixado.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-all}"
VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
PORT="${VPS_PORT:-48022}"
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
FP="${P0F_FP:-/finger-sniffer/etc/p0f.fp}"
FOXIO_COMMIT=c6469a7b0dbf8fe963810162429fbfd9d1acc4d5
R=/tmp/fs-fingerprint-regen
export COPYFILE_DISABLE=1

ssh -p "$PORT" "$VPS" "rm -rf $R && mkdir -p $R"
trap 'ssh -p "$PORT" "$VPS" "rm -rf $R"' EXIT

if [ "$MODE" = all ] || [ "$MODE" = syn ]; then
	ssh -p "$PORT" "$VPS" "mkdir -p $R/syn"
	rsync -a -e "ssh -p $PORT" syn/ regen-remote.sh "$VPS:$R/syn/"
	ssh -p "$PORT" "$VPS" "cd $R/syn && JA4=$JA4 FP=$FP bash ./regen-remote.sh syn"
	scp -q -P "$PORT" "$VPS:$R/syn/ja4t.json" ja4t.golden.json
	scp -q -P "$PORT" "$VPS:$R/syn/p0f.log" p0f.golden.log
	python3 -m json.tool ja4t.golden.json > ja4t.golden.json.tmp && mv ja4t.golden.json.tmp ja4t.golden.json
	echo "ja4t: $(grep -c '"ja4t"' ja4t.golden.json)  p0f: $(wc -l < p0f.golden.log | tr -d ' ')"
fi

foxio_src() {
	SRC="${FOXIO_PCAP_DIR:-$(git rev-parse --show-toplevel)/tmp/ref/ja4/pcap}"
	if [ ! -d "$SRC" ]; then
		TMPC=$(mktemp -d)
		git clone -q https://github.com/FoxIO-LLC/ja4 "$TMPC/ja4"
		git -C "$TMPC/ja4" checkout -q "$FOXIO_COMMIT"
		SRC="$TMPC/ja4/pcap"
	fi
}

if [ "$MODE" = all ] || [ "$MODE" = quic ]; then
	foxio_src
	ssh -p "$PORT" "$VPS" "mkdir -p $R/quic/src"
	rsync -a -e "ssh -p $PORT" "$SRC/"*quic* "$VPS:$R/quic/src/"
	rsync -a -e "ssh -p $PORT" regen-remote.sh "$VPS:$R/quic/"
	ssh -p "$PORT" "$VPS" "cd $R/quic && JA4=$JA4 bash ./regen-remote.sh quic"
	rm -f quic/*.pcapng
	mkdir -p quic
	rsync -a -e "ssh -p $PORT" "$VPS:$R/quic/out/" quic/
	python3 -m json.tool quic/ja4.golden.json > quic/ja4.golden.json.tmp && mv quic/ja4.golden.json.tmp quic/ja4.golden.json
	python3 -m json.tool quic/tshark.json > quic/tshark.golden.json && rm -f quic/tshark.json
	echo "quic: $(ls quic/*.pcapng | wc -l | tr -d ' ') pcaps, $(grep -c '"ja4"' quic/ja4.golden.json) JA4"
fi

if [ "$MODE" = all ] || [ "$MODE" = tls ]; then
	SRC="${FOXIO_PCAP_DIR:-$(git rev-parse --show-toplevel)/tmp/ref/ja4/pcap}"
	if [ ! -d "$SRC" ]; then
		TMPC=$(mktemp -d)
		git clone -q https://github.com/FoxIO-LLC/ja4 "$TMPC/ja4"
		git -C "$TMPC/ja4" checkout -q "$FOXIO_COMMIT"
		SRC="$TMPC/ja4/pcap"
	fi
	ssh -p "$PORT" "$VPS" "mkdir -p $R/tls/src $R/tls/bin"
	rsync -a -e "ssh -p $PORT" "$SRC/" "$VPS:$R/tls/src/"
	rsync -a -e "ssh -p $PORT" ../../../../tlsparse/testdata/*.bin "$VPS:$R/tls/bin/"
	rsync -a -e "ssh -p $PORT" regen-remote.sh "$VPS:$R/tls/"
	ssh -p "$PORT" "$VPS" "cd $R/tls && JA4=$JA4 bash ./regen-remote.sh tls"
	rm -f tls/*.pcap tls/*.pcapng
	mkdir -p tls
	rsync -a -e "ssh -p $PORT" "$VPS:$R/tls/out/" tls/
	for f in tls/ja4.golden.json tls/ja3.golden.json; do
		python3 -m json.tool "$f" > "$f.tmp" && mv "$f.tmp" "$f"
	done
	echo "tls: $(ls tls/*.pcap* | wc -l | tr -d ' ') pcaps, $(grep -c '"ja4"' tls/ja4.golden.json) JA4, $(grep -c '"ja3"' tls/ja3.golden.json) JA3"
fi
