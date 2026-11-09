# 011 — HTTP/3 e QUIC (UDP 443)

Status: aprovada
Depende de: 005, 008

## Contexto
Navegadores reais usam h3 quando o servidor anuncia (Alt-Svc ou HTTPS RR). O MVP serve HTTP/3 funcional e analisa
o Initial.

## Requisitos
- RF-01: servidor QUIC/HTTP/3 com `quic-go` + `http3` em UDP 443, mesmo certificado.
- RF-02: análise do Initial a partir dos datagramas crus (lidos antes do quic-go por um `net.PacketConn` wrapper
  e também presentes na captura): versão, tamanhos e valores de DCID/SCID, token, comprimento,
  **parâmetros de transporte na ordem** (com valores), ClientHello interno (decifrado com as chaves Initial
  derivadas do DCID) e seus fingerprints (JA4 com prefixo `q`), coalescência de pacotes, tamanho do datagrama
  (padding a 1200).
- RF-03: por requisição h3: pseudo-cabeçalhos e campos na ordem, QPACK (representação), SETTINGS do h3, e os
  instantes absolutos `request_started_at` (HEADERS lido), `request_ended_at` (FIN do stream do cliente),
  `response_started_at` (primeiro HEADERS escrito) e `response_ended_at` (FIN ou reset do stream pelo servidor),
  com a semântica da spec 009 RF-06 (ADR 0029).
- RF-04: controles de resposta compatíveis (status, size, delay_*, h=).
- RF-05: anúncio: `Alt-Svc` nas respostas h1/h2 (spec 005) e HTTPS RR no DNS (spec 007).
- RF-06: `MaxIdleTimeout` = `FS_IDLE_DEFAULT`; o servidor nunca encerra a conexão antes disso (spec 005 RF-08);
  sem 0-RTT, sem migração, sem Retry; `QPACK_MAX_TABLE_CAPACITY = 0` e SETTINGS do servidor fixos e documentados
  no código.
- RF-07: `conn_id` no corpo de `GET /p/<id>/` também em h3, pelo `fs.v1.store.conn_id` com `l4=udp` (ADR 0017),
  pedido no primeiro datagrama da 5-tupla.

## Comportamento (ADR 0019)
- Leitura: um wrapper de `net.PacketConn` entrega ao `quic.Transport` cada datagrama e, antes, guarda os
  datagramas Initial (long header tipo 0) de cada 5-tupla até o ClientHello completar (no máximo 8 datagramas ou
  2 s). Sem `OOBCapablePacketConn`: quic-go sem GSO/GRO/ECN.
- `pkg/quicparse`: cabeçalho longo (versão, DCID/SCID, token, Length, número do pacote), remoção da proteção de
  cabeçalho e decifragem com as chaves Initial derivadas do DCID (QUIC v1 RFC 9001 e v2 RFC 9369), frames na
  ordem, remontagem do CRYPTO por offset (fora de ordem, em vários pacotes e datagramas, como o Chrome faz),
  parâmetros de transporte na ordem (GREASE incluído), coalescência e padding. O ClientHello remontado vai para
  `pkg/tlsparse` e `pkg/fingerprint` (JA3/JA4 com `q`). Versão desconhecida: registra só o cabeçalho
  (`client_hello` nulo) e o quic-go responde Version Negotiation.
- Frames h3: o web lê os bytes do stream de controle do cliente (tipo, SETTINGS na ordem; `h3_control_stream_seen`
  distingue "o cliente não abriu o stream de controle", comum no curl/nghttp3, de "SETTINGS vazio";
  entra no contrato junto com o produtor, task 073) e de cada stream de
  requisição (HEADERS com a representação QPACK de cada linha, DATA contado em `body_len`), sem normalizar.
- Eventos: `fs.v1.web.http3.connection` até 3 vezes (handshake terminado/falho, SETTINGS do cliente, fim com
  `close`); `fs.v1.web.http3.request` quando cada resposta termina. Tetos da ADR 0018 (`fields_truncated`,
  `values_truncated`, `initial_frames_truncated`).
- Controles (RF-04): `status`, `size`, `delay_head`, `delay_body`, `h=`, `alt_svc` e `date` iguais aos do h2 (`Date` em toda resposta final, spec 005 RF-07a); os demais
  (`ver`, `frame`, `conn`, `ka`, `close`, `rst`, `idle`, `hsize`, `continue`, `upgrade`) não se aplicam e
  respondem 400 com explicação, registrado.

## Interfaces e contratos
- Eventos `fs.v1.web.http3.connection` e `fs.v1.web.http3.request`; campo `http3` do registro (`HTTP3Info`,
  `HTTP3Request`, `QPACKField` no openapi). Correlação no store pela 5-tupla UDP; DCID novo depois de um `close`
  abre conexão nova (spec 004).

## Critérios de aceite
- [ ] `curl --http3-only https://<id>.dns-monitor.tmsoft.com.br/p/<id>/` funciona e o registro traz os parâmetros
      de transporte na ordem.
- [ ] Chrome, abrindo a página, passa a usar h3 (visto no registro) a partir da segunda requisição ou de imediato
      via HTTPS RR.
- [ ] JA4 `q...` bate com FoxIO `ja4` sobre o pcap do Initial (FoxIO `chrome-cloudflare-quic` e capturas próprias
      de curl, Chrome, Firefox e quic-go).
- [ ] Parâmetros de transporte e frames do Initial batem com o tshark 4.4 nos mesmos pcaps.
- [ ] Conexão encerrada pelo cliente aparece fechada no store em ≤ 500 ms (p95) do CONNECTION_CLOSE
      (`close.how = quic_close`; ADR 0026).
- [ ] `pkg/quicparse` com fuzz e cobertura ≥ 80% (spec 017).

## Fora de escopo
- 0-RTT do lado servidor, migração de conexão, datagramas QUIC.

## Decisões relacionadas
- specs/decisions/0001-decisoes-iniciais.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0019-http3-eventos-e-fim-quic.md
- specs/decisions/0026-fechamento-rapido-e-ajustes-da-release.md
- specs/decisions/0021-date-nas-respostas.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
