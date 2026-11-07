#!/usr/bin/env bash
# Regenera os gabaritos a partir das ferramentas oficiais, executadas na vps602:
#   - ja4 (FoxIO, Rust, compilado em /root/ja4-rust) → ja4t.golden.json
#   - p0f 3.09b (Debian, `p0f -r`) com o mesmo p0f.fp do deploy → p0f.golden.log
# Uso: pkg/fingerprint/testdata/regen.sh
set -euo pipefail
cd "$(dirname "$0")"
VPS="${VPS_SSH:-root@vps602.tmsoft.com.br}"
PORT="${VPS_PORT:-48022}"
JA4="${JA4_BIN:-/root/ja4-rust/target/release/ja4}"
FP="${P0F_FP:-/finger-sniffer/etc/p0f.fp}"
R=/tmp/fs-fingerprint-regen

ssh -p "$PORT" "$VPS" "rm -rf $R && mkdir -p $R"
rsync -a -e "ssh -p $PORT" syn/ regen-remote.sh "$VPS:$R/"
ssh -p "$PORT" "$VPS" "cd $R && JA4=$JA4 FP=$FP bash ./regen-remote.sh"
scp -q -P "$PORT" "$VPS:$R/ja4t.json" ja4t.golden.json
scp -q -P "$PORT" "$VPS:$R/p0f.log" p0f.golden.log
ssh -p "$PORT" "$VPS" "rm -rf $R"
python3 -m json.tool ja4t.golden.json > ja4t.golden.json.tmp && mv ja4t.golden.json.tmp ja4t.golden.json
echo "ja4t: $(grep -c '"ja4t"' ja4t.golden.json)  p0f: $(wc -l < p0f.golden.log | tr -d ' ')"
