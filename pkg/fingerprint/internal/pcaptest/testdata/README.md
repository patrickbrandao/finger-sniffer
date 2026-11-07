# Dados de teste dos fingerprints TCP (JA4T e p0f)

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

## Gabaritos
Gerados pelas ferramentas oficiais na vps602 com `regen.sh` (a parte remota está em `regen-remote.sh`):

- `ja4t.golden.json`: saída `ja4 -j` da ferramenta oficial da FoxIO (Rust, `rust/ja4`, compilada em
  `/root/ja4-rust`), um array de fluxos por pcap.
- `p0f.golden.log`: observações `syn` e `syn+ack` do `p0f -r` 3.09b (pacote Debian) com o mesmo `p0f.fp`
  do deploy (`/finger-sniffer/etc/p0f.fp`), prefixadas com o nome do pcap.

O `p0f.fp` (LGPL-2.1) não fica no repositório: o teste de comparação do p0f usa `FS_P0F_DB` ou o arquivo
instalado pelo deploy e roda obrigatoriamente na vps602 (testes `linux_priv` do `make verify-full`).
