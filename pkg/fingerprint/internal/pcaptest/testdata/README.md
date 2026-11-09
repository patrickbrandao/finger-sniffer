# Dados de teste dos fingerprints (JA4T, p0f, JA3 e JA4)

## Pcaps (`syn/`)
Só os pacotes SYN e SYN+ACK de cada captura, para manter o repositório pequeno; JA4T e p0f olham apenas
esses pacotes.

- Pcaps de teste da FoxIO (`https://github.com/FoxIO-LLC/ja4`, pasta `pcap/`, commit
  `c6469a7b0dbf8fe963810162429fbfd9d1acc4d5`), os mesmos usados pelo fingerproxy em `pkg/ja4pcap`.
  Licença BSD 3-Clause, em `syn/LICENSE-FoxIO-BSD3`. `chrome-cloudflare-quic.pcap` é o
  `chrome-cloudflare-quic-with-secrets.pcapng` sem o bloco de segredos TLS.
- `vps602-mixed.pcap`: SYNs recebidos e enviados pela vps602 (Linux, macOS e scanners da internet), com os
  IPs dos clientes trocados por endereços de documentação (198.51.100.0/24).
- `edge-cases.pcap`: SYNs sintéticos com opções TCP e campos IP malformados ou raros, gerados por
  `mkedge.py`.

## Pcaps de TLS (`tls/`)
Fluxos TCP com ClientHello, para JA3/JA3N e JA4 (task 018):

- `foxio-*.pcapng`: os pcaps completos da FoxIO (mesmo commit acima) reduzidos aos fluxos TCP que têm
  ClientHello, até o frame que fecha o ClientHello. O que vem antes no fluxo (CONNECT, SOCKS) fica, para o
  tshark reconhecer o TLS. ClientHellos de QUIC ficam para a F4 (spec 011).
- `client-*.pcap`: os ClientHellos de clientes reais de `pkg/tlsparse/testdata` (curl macOS/Linux/Homebrew,
  OpenSSL 3, LibreSSL e OpenSSL em TLS 1.0, Go, Chrome, Firefox e o Chrome em 2 registros), convertidos em
  pcap TCP pelo `text2pcap`.

## Gabaritos
Gerados pelas ferramentas oficiais na vps602 com `regen.sh [all|syn|tls]` (a parte remota está em
`regen-remote.sh`):

- `ja4t.golden.json`: saída `ja4 -j` da ferramenta oficial da FoxIO (Rust, `rust/ja4`, compilada em
  `/root/ja4-rust`), um array de fluxos por pcap.
- `tls/ja4.golden.json`: saída `ja4 -j -r` (`sorted`: JA4 e JA4_r) e `ja4 -j -r -O` (`original`: JA4_o e
  JA4_ro) de cada pcap de `tls/`.
- `tls/ja3.golden.json`: `tls.handshake.ja3_full` e `tls.handshake.ja3` do tshark 4.4 para cada ClientHello
  (e o `tls.handshake.ja4` do tshark, só como referência: ele não tira o GREASE dos algoritmos de assinatura).
- `tls/VERSIONS.txt`: versões do tshark e do ja4 usadas.
- `p0f.golden.log`: observações `syn` e `syn+ack` do `p0f -r` 3.09b (pacote Debian) com o mesmo `p0f.fp`
  do deploy (`/finger-sniffer/etc/p0f.fp`), prefixadas com o nome do pcap.

O `p0f.fp` (LGPL-2.1) não fica no repositório: o teste de comparação do p0f usa `FS_P0F_DB` ou o arquivo
instalado pelo deploy e roda obrigatoriamente na vps602 (testes `linux_priv` do `make verify-full`).
