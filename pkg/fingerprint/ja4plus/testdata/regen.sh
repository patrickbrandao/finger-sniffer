#!/usr/bin/env bash
# Regenera ja4h.golden.json e os dados derivados do h2 (pkg/h2passive/testdata) na vps602.
set -euo pipefail
cd "$(dirname "$0")"
H2=../../../h2passive/testdata
SSH=(ssh -p 48022 root@vps602.tmsoft.com.br)
JA4=/root/ja4-rust/target/release/ja4
"${SSH[@]}" 'rm -rf /root/regen-ja4h && mkdir -p /root/regen-ja4h'
scp -q -P 48022 http1-with-cookies.pcapng http2-with-cookies.pcapng root@vps602.tmsoft.com.br:/root/regen-ja4h/
"${SSH[@]}" "cd /root/regen-ja4h && JA4=$JA4 python3 -" <<'PY' >ja4h.golden.json
import json, os, subprocess
out = {}
for f in ["http1-with-cookies.pcapng", "http2-with-cookies.pcapng"]:
    r = {}
    for flags in (["-j"], ["-j", "-r"], ["-j", "-O"], ["-j", "-r", "-O"]):
        o = subprocess.run([os.environ["JA4"]] + flags + [f], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL).stdout
        for line in o.splitlines():
            if line.startswith("{"):
                for i, h in enumerate(json.loads(line).get("http", [])):
                    r.setdefault(i, {}).update(h)
    out[f] = [r[i] for i in sorted(r)]
print(json.dumps(out, indent=1))
PY
# sentido do cliente decifrado (o follow do tshark põe o servidor sem recuo neste pcap: o cliente é o recuado)
"${SSH[@]}" 'cd /root/regen-ja4h && tshark -r http2-with-cookies.pcapng -q -z follow,tls,raw,0 2>/dev/null' |
	awk '/^\t/ {gsub(/\t/, ""); print}' | xxd -r -p >"$H2/chrome-foxio-in.bin"
"${SSH[@]}" 'cd /root/regen-ja4h && tshark -r http2-with-cookies.pcapng -Y "http2.type==1 && tcp.srcport==58847" \
	-T fields -E separator=/t -E aggregator="|" -e http2.streamid -e http2.header.name -e http2.header.repr \
	-e http2.exclusive -e http2.stream_dependency -e http2.headers.weight_real 2>/dev/null' >"$H2/chrome-foxio-in.tshark.tsv"
"${SSH[@]}" 'rm -rf /root/regen-ja4h'
