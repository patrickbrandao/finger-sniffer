# Primeiro voo QUIC de clientes reais (task 050)

Cópia mínima dos golden de `test/golden/quic/` para os testes do `pkg/quicparse` (task 049). Origem, versões,
achados e como regenerar: `test/golden/quic/README.md` (`collect.sh` grava estes arquivos também).

- `<caso>.initial.pcap`: pcap libpcap (Ethernet) só com os datagramas que têm pacote Initial na primeira conexão
  QUIC do caso, do cliente (porta de destino 7703) e do servidor. Os primeiros `client_hello_datagrams`
  datagramas do cliente carregam o ClientHello inteiro.
- `<caso>.expected.json`: o esperado, só de ferramentas de referência (tshark 4.4.19 e ja4 0.18.6 da FoxIO):
  `version`, `dcid`, `scid`, `datagram_sizes`, `client_hello_datagrams`, `crypto_frames` (`[offset, length]` na
  ordem de chegada), `crypto_out_of_order`, `crypto_length`, `client_hello` (JA3, JA4 do tshark, SNI, ALPN,
  extensões na ordem), `transport_parameters` (`[id, nome do tshark, valor hex]` na ordem), `ja4_tool`,
  `ja4_r_tool`, os datagramas Initial do cliente e do servidor com os frames na ordem e, decifrado com as chaves
  da sessão, `http3` (SETTINGS do cliente e do servidor, HEADERS do cliente com o bloco QPACK cru em
  `qpack_block` e os campos decodificados).

| Caso | Cliente | JA4 |
| --- | --- | --- |
| `curl` | curl 8.23.0 (ngtcp2 1.26.0, OpenSSL 4.1.0) | q13d0311h3_55b375c5d22e_df5ee7f3ca36 |
| `go` | Go 1.27.3, quic-go v0.65.0 | q13d0313h3_55b375c5d22e_4156cdf64688 |
| `chrome` | Chrome 156.0.8078.80 | q13d0312h3_55b375c5d22e_178839b6cec1 |
| `firefox` | Firefox 159.0 | q13d0315h3_55b375c5d22e_dc5437974b47 |

Todos com ClientHello em 2 datagramas e CRYPTO fora de ordem. O IP do cliente é `198.51.100.10` (documentação);
o servidor é a vps602 (`172.233.24.85`). O Firefox não tem HEADERS h3 (fecha no Handshake, ver o README de
origem).
