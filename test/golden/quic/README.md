# Golden de Initials QUIC (task 050)

Capturas reais do primeiro voo QUIC (Initials do cliente e a resposta do servidor) de curl, quic-go, Chrome e
Firefox contra um servidor HTTP/3 temporário na vps602, com as chaves TLS da sessão e as saídas das
ferramentas de referência sobre o mesmo arquivo. Servem de gabarito para `pkg/quicparse` (task 049: cabeçalho
longo, frames do Initial, remontagem do CRYPTO, parâmetros de transporte, JA4 `q`, SETTINGS e QPACK do h3) e
para o ingest h3 do store. O `golden_test.go` confere a coerência dos arquivos entre si, sem usar código do
projeto.

## Casos

Coleta de 2026-11-09 (versões em `pcaps/VERSIONS.txt`: curl 8.23.0 do Homebrew com ngtcp2 1.26.0, nghttp3
1.19.0 e OpenSSL 4.1.0; Go 1.27.3 com quic-go v0.65.0; Chrome 156.0.8078.80; Firefox 159.0; macOS 27.0.1;
tshark 4.4.19 e ja4 0.18.6 na vps602). Servidor: quic-go v0.65.0 (`server/`), QUIC v1, sem Retry.

| Caso | JA4 (ja4 = tshark) | JA3 (tshark) | Datagramas do ClientHello (bytes UDP) | Frames CRYPTO | ClientHello (bytes) | DCID/SCID (bytes) | Parâmetros de transporte | HEADERS h3 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `curl` | q13d0311h3_55b375c5d22e_df5ee7f3ca36 | 39d562ecba1bc787c4c3419d5080b14e | 2 (1200 + 1200) | 22 | 1550 | 20 / 20 | 8 | 1 |
| `go` | q13d0313h3_55b375c5d22e_4156cdf64688 | aeb4a42cd7925b343b143434a712dd00 | 2 (1280 + 1280) | 4 | 1521 | 17 / 0 | 12 (1 GREASE) | 1 |
| `chrome` | q13d0312h3_55b375c5d22e_178839b6cec1 | 8b53f11720d060000fc2c4d855ff6f38 | 2 (1250 + 1250) | 11 | 1982 | 8 / 0 | 13 (1 GREASE) | 3 |
| `firefox` | q13d0315h3_55b375c5d22e_dc5437974b47 | 7572bae5e642212ed36a93ce73a630e3 | 2 (1252 + 1252) | 3 | 1898 | 8 / 3 | 14 (1 GREASE) | 0 |

Os quatro mandam o ClientHello em **2 datagramas** (todos oferecem X25519MLKEM768, o que passa de 1200 bytes) e
com **CRYPTO fora de ordem**:
- Chrome: 11 frames CRYPTO embaralhados entre PING e PADDING, nos 2 datagramas (o "chaos protection" do Chrome);
- curl (ngtcp2): 22 frames CRYPTO pequenos em ordem aleatória;
- Go (quic-go): o primeiro frame começa no offset 80, o trecho 0–80 vem depois em 2 frames;
- Firefox (neqo): o fim do ClientHello (offset 1492) chega antes do começo, e o datagrama é completado com
  bytes aleatórios depois do último pacote (`coalesced_padding` no `ref.json`), em vez de frames PADDING.

Nenhum tem frames CRYPTO sobrepostos (`crypto_overlap` falso) nem token.

Arquivos por caso em `pcaps/`:
- `<caso>.pcap`: captura `tcpdump -s0` na eth0 (só UDP da porta 7703), com o IP do Mac trocado por
  `198.51.100.10` (`../anon.py`) antes de qualquer saída de referência.
- `<caso>.initial.pcap`: o primeiro voo, só os datagramas com pacote Initial da primeira conexão (cliente e
  servidor), recortado pelo tshark (`udp.stream == 0 && quic.long.packet_type == 0`).
- `<caso>.keys`: chaves TLS da sessão (NSS SSLKEYLOGFILE) gravadas pelo `KeyLogWriter` do servidor, para o
  tshark decifrar Handshake e 1-RTT. O Initial não precisa delas (chaves derivadas do DCID, RFC 9001 5.2). São
  de sessões descartáveis com um certificado autoassinado de 2 dias.
- `<caso>.tshark.json`: `tshark -T json --no-duplicate-keys -J 'frame ip ipv6 udp quic tls http3'` com as
  chaves: cabeçalhos QUIC, frames, o ClientHello remontado (`tls.handshake.ja3`, `ja4`, parâmetros de
  transporte em `tls.quic.parameter.*`) e o h3 decifrado (SETTINGS, HEADERS com o QPACK decodificado).
- `<caso>.ja4.jsonl` e `<caso>.initial.ja4.jsonl`: `ja4 -j -r` da FoxIO sobre a captura inteira (com as chaves) e
  sobre o primeiro voo sozinho; o JA4 é o mesmo nos dois.
- `<caso>.ref.json`: resumo gerado por `ref.py` só com saídas das ferramentas, por conexão QUIC do cliente:
  versão, DCID/SCID, tamanhos dos datagramas, `client_hello_datagrams`, frames CRYPTO na ordem de chegada
  (`[offset, length]`), `crypto_out_of_order`, `crypto_overlap`, ClientHello (JA3, JA3 completo, JA4 e JA4_r do
  tshark, SNI, ALPN, extensões na ordem), `transport_parameters` na ordem (`[id, nome do tshark, valor hex]`),
  JA4/JA4_r/JA4S do ja4, os datagramas Initial do cliente e do servidor (pacotes coalescidos com tipo, versão,
  DCID, SCID, token, Length, número e frames na ordem) e o h3 (`client_settings`, `server_settings` na ordem e
  `client_headers` com o bloco QPACK cru em `qpack_block` e os campos decodificados pelo tshark).

Cópia mínima para o parser em `initials/`: `<caso>.initial.pcap` e `<caso>.expected.json` (a primeira conexão
do `ref.json`, com `case` e `client`). Quando o `pkg/quicparse` (task 049) já tem código, o `collect.sh` grava a
mesma cópia em `pkg/quicparse/testdata/initials/` e o `golden_test.go` confere que as duas são idênticas. Ela
não vai para lá antes disso porque uma pasta `pkg/quicparse` só com `testdata` falha a cobertura mínima do
`verify-full` ("sem dado para pkg/quicparse").

## Conferências e achados

- **JA4**: o do ja4 da FoxIO e o do tshark 4.4.19 são iguais nos quatro casos (`TestConnections`); no QUIC o
  tshark não tropeça no GREASE como no TCP (task 036), porque nenhum dos quatro manda GREASE nos algoritmos de
  assinatura. O ja4 dá o mesmo JA4 sobre o primeiro voo sozinho, então a cópia mínima basta para o golden do
  task 049.
- **Nomes dos parâmetros de transporte**: os do tshark. O Firefox manda o id `0x1d` (29), que o tshark 4.4 chama
  de `Unknown 0x001d`; os GREASE aparecem como `GREASE` (Go `7591`, Chrome `2145526269292744097`, Firefox
  `4278378010`, todos `31*N+27`).
- **Chrome**: precisou de `--origin-to-force-quic-on` (só nesta coleta, nunca no e2e), porque a porta 7703 não
  é anunciada por Alt-Svc nem HTTPS RR. Com o hash da chave em `--ignore-certificate-errors-spki-list` o
  handshake completa e as 3 requisições (`/`, `/i.png`, `/favicon.ico`) vão por h3.
- **Firefox**: tentado uma vez, headless e sem desligar a sandbox. Com `network.http.http3.alt-svc-mapping-for-testing`
  ele abre a conexão QUIC (Initial completo e resposta do servidor), mas fecha no espaço Handshake com
  `CONNECTION_CLOSE` código `0x0c` (APPLICATION_ERROR, a forma que um erro de aplicação toma antes do 1-RTT):
  a exceção de certificado do perfil vale para o TLS sobre TCP, não para a validação do Alt-Svc em h3. Por isso
  não há HEADERS h3 do Firefox; o Initial, que é o objeto deste golden, está completo.
- **curl**: os SETTINGS do h3 do curl (nghttp3) são `[6, 4611686018427387903]` (max_field_section_size no
  máximo de varint), `[1, 0]` e `[7, 0]`; o do Go manda só `[6, 10485760]`; o do Chrome traz um GREASE
  (`0x15931400a`). O servidor (quic-go) manda `[6, 1048576]` e `[8, 1]`.
- O `golden_test.go` confere também que o pcap do primeiro voo tem os mesmos datagramas do cliente (tamanho,
  versão, DCID e SCID lidos do cabeçalho longo) que o tshark dissecou e que nenhum endereço fora de
  `172.233.24.85`, `198.51.100.10` e `2001:db8::10` aparece nos pcaps.

## Como regenerar

```bash
test/golden/quic/collect.sh                  # todos os casos
ONLY="chrome firefox" test/golden/quic/collect.sh
REF_ONLY=1 test/golden/quic/collect.sh       # só as saídas de referência, sobre os pcaps já gravados
```

O script roda no Mac e usa a vps602 sem aprovação, por ser o servidor de testes. Passos:
- gera um certificado autoassinado ECDSA P-256 para `vps602.tmsoft.com.br` (2 dias);
- compila `server/` (quic-go/http3, tag `golden`) para linux/amd64 e o copia para `/tmp/fs-golden-quic` na
  vps602;
- para cada caso, sobe o servidor na porta capturada 7703 (UDP para h3; TCP com h2 e `Alt-Svc` para o Firefox)
  com um keylog só desse caso e um `tcpdump -s0` na eth0 filtrando UDP 7703 e o IP do Mac; roda o cliente; para
  os dois;
- confiança no certificado, sempre restrita a ele: `--cacert` no curl, `-ca` no Go (`goclient/`), o hash da
  chave em `--ignore-certificate-errors-spki-list` no Chrome e uma exceção em `cert_override.txt` num perfil
  descartável do Firefox. Nada no sistema muda e nenhuma sandbox é desligada;
- na vps602: `anon.py`, tshark (captura inteira e recorte do primeiro voo), ja4 e `ref.py`; copia tudo para
  `pcaps/` e a cópia mínima para `initials/` (e `pkg/quicparse/testdata/initials/`, se o pacote existir).

No fim, mesmo em erro, o script para o servidor e o tcpdump, apaga `/tmp/fs-golden-quic` e confere a limpeza. O
log mostra "vps602 limpa: sem servidor, sem tcpdump, sem listener UDP/TCP na 7703 e sem /tmp/fs-golden-quic".

Pré-requisitos: na vps602, `tshark` 4.4 e `tcpdump` (apt) e o ja4 da FoxIO em `/root/ja4-rust` (ver
`../README.md`); no Mac, Go, um curl com HTTP/3 (o do Homebrew, ngtcp2; outro por `CURL_H3=...`), Chrome e
Firefox.
