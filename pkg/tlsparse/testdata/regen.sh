#!/usr/bin/env bash
# Regenera os gabaritos *.tshark.json dos ClientHellos de testdata/ com o tshark 4.4 da vps602:
# cada .bin vira um pcap TCP (text2pcap) e o tshark extrai os campos TLS do ClientHello.
#
# Origem dos .bin (bytes do(s) registro(s) TLS do ClientHello, nada além):
#   - curl-macos, curl-brew, openssl3, openssl3-tls10, libressl-tls10, go, chrome, firefox: clientes reais
#     num macOS, gravados por um listener local que guarda os primeiros bytes da conexão;
#   - curl-linux: curl 8.14.1/OpenSSL 3.5 da vps602 pelo mesmo listener (túnel ssh -R);
#   - foxio-*: ClientHellos dos pcaps de teste da FoxIO (github.com/FoxIO-LLC/ja4, pasta pcap/, commit
#     c6469a7b0dbf8fe963810162429fbfd9d1acc4d5; BSD-3, ver LICENSE-FoxIO-BSD3);
#   - chrome-2records: o chrome.bin partido em 2 registros (o corte é no byte 600 da mensagem).
set -euo pipefail
cd "$(dirname "$0")"
HOST=${FS_VPS:-root@vps602.tmsoft.com.br}
SSH=(ssh -p 48022 "$HOST")
REMOTE=$("${SSH[@]}" mktemp -d /tmp/tlsparse-regen.XXXXXX)
trap '"${SSH[@]}" rm -rf "$REMOTE"' EXIT
COPYFILE_DISABLE=1 tar cf - ./*.bin | "${SSH[@]}" "tar xf - -C $REMOTE"
"${SSH[@]}" "cd $REMOTE && for f in *.bin; do
  b=\${f%.bin}
  od -Ax -tx1 -v \$f > \$b.txt
  text2pcap -q -T 50000,443 \$b.txt \$b.pcap >/dev/null
  tshark -r \$b.pcap -2 -Y 'tls.handshake.type == 1' -T json \
    -e tls.record.version -e tls.handshake.version -e tls.handshake.random -e tls.handshake.session_id_length \
    -e tls.handshake.ciphersuite -e tls.handshake.comp_method -e tls.handshake.extension.type \
    -e tls.handshake.extension.len -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str \
    -e tls.handshake.extensions_supported_group -e tls.handshake.extensions_ec_point_format \
    -e tls.handshake.sig_hash_alg -e tls.handshake.extensions.supported_version \
    -e tls.handshake.extensions_key_share_group -e tls.handshake.extensions_key_share_key_exchange_length \
    -e tls.extension.psk_ke_mode -e tls.compress_certificate.algorithm -e tls.record_size_limit \
    -e tls.handshake.extensions_alps_alpn_str -e tls.handshake.ja3_full -e tls.handshake.ja3 \
    -e tls.handshake.ja4 -e tls.handshake.ja4_r > \$b.tshark.json 2>/dev/null
done; tshark -v | head -1 > TSHARK_VERSION"
"${SSH[@]}" "cd $REMOTE && tar cf - ./*.tshark.json TSHARK_VERSION" | tar xf -
echo "gabaritos regenerados com $(cat TSHARK_VERSION)"
