# 0019 — HTTP/3: eventos por requisição, fim da conexão QUIC pelo web e UDP sem otimizações

Status: aceita (meta de registro do QUIC: ver 0024)
Data: 2026-11-09

## Contexto
Fatos novos, achados ao preparar a F4:
- O contrato v0 tinha um único evento `fs.v1.web.http3.connection` com as requisições dentro. Navegadores mantêm a
  conexão QUIC aberta por muito tempo (Chrome: dezenas de segundos ou mais), então as requisições h3 só
  apareceriam no feed e no registro no fim da conexão, contra o critério da F4 (feed < 1 s após cada requisição).
- QUIC não tem FIN: o store só fecharia o fluxo UDP por ociosidade (30 s para UDP), o que atrasa o long-poll
  `wait` e corta conexões h3 ociosas com o `FS_IDLE_DEFAULT` de 120 s em dois registros.
- O `http3.Server` do quic-go entrega `http.Request` com `Header` em mapa: perde ordem, caixa e representação
  QPACK, que a spec 011 RF-03 exige. O registro precisa dos bytes do stream de requisição.
- Com GSO/GRO de UDP, a captura (AF_PACKET) e o wrapper do web podem ver datagramas agregados, diferentes do fio
  (mesmo problema que a ADR 0011 resolveu para TCP).

## Decisão
- **Eventos**: `fs.v1.web.http3.connection` passa a ser só o nível de conexão (Initial analisado, SETTINGS, fim),
  publicado até três vezes (handshake terminado/falho, SETTINGS do cliente, fim com `close`); cada requisição vai
  em **`fs.v1.web.http3.request`** (novo, schema `HTTP3Request`), publicado quando a resposta termina — o mesmo
  desenho de `http2.connection` + `http2.stream`. O stream `FS_EVENTS` já cobre `fs.v1.web.>`.
- **Fim da conexão QUIC**: o web é a fonte da verdade. O `http3.connection` final (`close` preenchido) faz o
  store fechar o fluxo UDP 2 s depois (folga para os últimos pacotes do capture), com `close.how = quic_close`
  (ou `timeout` quando `close.how` do web for `idle_timeout`). Enquanto houver evento h3 sem `close`, a
  ociosidade do fluxo no store é `FS_IDLE_DEFAULT` + 30 s, como no TCP. O `MaxIdleTimeout` do QUIC é
  `FS_IDLE_DEFAULT` (spec 005 RF-08: o servidor não fecha antes).
- **Bytes do h3**: o web usa o quic-go para QUIC e o `http3` do quic-go para servir, mas lê os frames do stream de
  requisição e do stream de controle do cliente (HEADERS, DATA, SETTINGS) com um parser passivo próprio
  (`pkg/quicparse`, QPACK com tabela estática e Huffman de `x/net/http2/hpack`). O servidor anuncia
  `QPACK_MAX_TABLE_CAPACITY = 0`, então o cliente não usa tabela dinâmica; referência dinâmica vira
  `static: false` sem valor resolvido. Se a API do `http3` não permitir ver os bytes do stream (por exemplo via
  `RawServerConn`/conexão aceita pelo próprio web), o web implementa o h3 mínimo sobre `quic.Conn` (RFC 9114 sem
  push, QPACK sem tabela dinâmica), sem dependência nova.
- **UDP sem otimizações de agregação**: o web passa ao `quic.Transport` um wrapper de `net.PacketConn` que lê
  cada datagrama antes do quic-go (spec 011 RF-02) e não implementa `OOBCapablePacketConn` — o quic-go roda sem
  GSO, sem GRO e sem ECN; a unit do web ainda fixa `QUIC_GO_DISABLE_GSO=true` e `QUIC_GO_DISABLE_ECN=true`. A
  unit de rede desliga também `tx-udp-segmentation` na eth0. `net.core.rmem_max`/`wmem_max` sobem para 7 MiB
  (buffer pedido pelo quic-go; teto, não reserva).
- **HTTPS RR**: o dns anuncia `alpn="h3,h2"` só quando `FS_WEB_UDP_PORTS` contém 443 (mesmo env compartilhado);
  senão `alpn="h2"`. Alt-Svc nas respostas h1/h2 só com o listener UDP 443 do web de pé (spec 005 RF-04).

## Alternativas consideradas
- Um só evento por conexão no fim: simples, mas quebra o feed ao vivo e o long-poll.
- O store inferir o fim do QUIC pelos pacotes: os pacotes são cifrados; só o web sabe do CONNECTION_CLOSE.
- `http.Request.Header` do `http3`: perde ordem e representação; inaceitável para um espelho (ADR 0009 pede
  controle de cada byte).
- Importar `github.com/quic-go/qpack` diretamente: dependência fora da lista da ADR 0009 (só transitiva); o QPACK
  sem tabela dinâmica é pequeno.
- Manter GSO/ECN do quic-go: mais desempenho, mas a captura passa a depender do driver; a carga do MVP é pequena.

## Consequências
- Contrato 0.3.0 (aditivo): `fs.v1.web.http3.request`, `HTTP3Request`, `QPACKField`, campos novos em `HTTP3Info`
  e `close.how = quic_close` no registro.
- O web mantém mais um parser passivo com fuzz (`pkg/quicparse`: Initial, CRYPTO, transport params, frames h3,
  QPACK).
- Desempenho do QUIC menor (sem GSO/ECN); aceitável para o espelho e medido na carga da F5.
- Conexões QUIC sucessivas na mesma 5-tupla: um Initial com DCID novo depois de um `close` abre conexão nova no
  store (spec 004).
