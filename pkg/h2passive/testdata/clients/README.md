# Clientes h2 reais (task 036)

Bytes h2 decifrados do cliente para o servidor, do prefácio em diante, de curl (LibreSSL e OpenSSL), Go,
Chrome 156 e Firefox 159, e o esperado de cada um:

- `<caso>.client.h2`: o que o parser passivo recebe no sentido `in` de uma conexão h2.
- `<caso>.expected.json`: saídas do tshark 4.4 sobre o mesmo pcap (`frames` da conexão com SETTINGS na ordem,
  WINDOW_UPDATE, prioridade do HEADERS e HPACK decodificado com `repr` e `index`), `akamai` (montado com os
  campos do tshark e conferido com o tls.peet.ws, exceto o Firefox) e `ja4h` do ja4 da FoxIO.
  `client_h2_tcp_stream` diz qual conexão de `http2` corresponde aos bytes.

Origem, pcaps completos, chaves e como regenerar: `test/golden/tls/README.md` (`test/golden/tls/collect.sh`).

Capturas do servidor anterior: o `:authority` e o `referer` com `vps602.tmsoft.com.br:7702` dos esperados são
os bytes gravados então (listener de coleta na 7702) e ficam como estão; o parser não depende do host. Uma
recaptura no finger-01 (ADR 0038) troca os arquivos inteiros pelo `collect.sh`.
