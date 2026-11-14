# 0032 — Campos e limites de contrato da auditoria de 2026-11 (agrupados)

Status: aceita
Data: 2026-11-14

## Contexto
A auditoria de código de 2026-11-10 (tasks 128–192, resumos `RESUMO-AUDITORIA-20261111-0055` e `-0120`) achou
cortes silenciosos e respostas sem teto que pedem campo novo ou forma nova no contrato. Como na ADR 0029, uma ADR
e uma única subida de versão cobrem todos, em vez de vários incrementos seguidos:
- **153**: `GET /api/v1/probes/{id}` devolve todas as conexões e consultas DNS do probe, completas e serializadas
  de uma vez: um probe com dezenas de milhares de conexões leva o store perto do `MemoryMax=384M`.
- **152**: cada `?wait` consulta o SQLite em laço; dezenas de esperas simultâneas sobre um probe grande ocupam a
  única vCPU. Não há teto de esperas.
- **129**: `/pcap` e `/raw` carregam o BLOB inteiro (até 16 MiB) por requisição, sem teto de downloads
  simultâneos nem prazo de escrita.
- **160**: um alvo HTTP/1 longo (até 1 MiB de cabeçalho) não cabe em 900 KiB e o evento é descartado inteiro;
  nada no contrato diz que `request_line.target` pode ser cortado.
- **165**: um ClientHello com listas enormes estoura os 900 KiB e o evento é descartado; o contrato não tem marca
  de corte das listas.
- **171**: `transport_params` (1024) e `h3_settings` (256) já são cortados no parser sem marca.
- **185**: um Upgrade WebSocket aceito sem nenhum frame (o cliente fecha o TCP logo depois do 101) não gera
  evento, e o registro fica sem `websocket`.
- Descrições que não batem com o código: `stream_id` 0 no h2 (145), `status: 0` de stream recusado (146),
  `src_ip` de `/packets` (177), `stream.dropped` fora do filtro `kind` (178), `probe_line` com ou sem terminador
  (181), `head_too_large` (131/155), `chunks_truncated` (133), `rate_limited` só em UDP (147), `DELETE` de probe com
  conexões abertas (150).

O teto do item 1 muda o comportamento acordado na spec 004 ("todas as conexões e consultas DNS do probe,
completas") e foi escalado ao humano (specs/002, "Escalonamento", item 2). **Decisão do humano em 2026-11-14:
teto aceito, 1000 conexões e 1000 consultas DNS, com `truncated`.**

## Decisão
Contratos sobem para **openapi 0.6.0** e **asyncapi 0.5.0**, só com campos e respostas aditivos (ADR 0001); nada
é removido nem renomeado. Todo booleano novo é opcional: ausente equivale a `false` (registros e eventos
anteriores ao 0.6.0/0.5.0 não o têm).

1. **Probe com teto (153, decisão do humano).** `GET /api/v1/probes/{id}` devolve no máximo **1000 conexões e 1000
   consultas DNS**, na ordem atual (conexões pelo início, consultas pelo instante). `Probe.truncated: true` quando
   qualquer uma das listas foi cortada. O restante continua em `GET /api/v1/connections?probe=` e
   `GET /api/v1/dns?probe=`. O critério do `wait` (`all_closed`, `min_conns`, `settle`, ADR 0029) é avaliado
   sobre o conjunto inteiro, não sobre o cortado; `all_closed` também.
2. **Teto de esperas (152).** No máximo **64** `?wait` simultâneos no store (constante, sem variável). Acima disso
   a requisição responde na hora `503` com `Retry-After: 1` e corpo `Error`. Sem `wait` a rota não tem teto
   próprio. A volta do laço consulta só o estado das conexões; o registro completo é lido uma vez, ao sair.
   Complementa a ADR 0029 (A5) sem mudar o critério.
3. **Downloads de BLOB (129).** No máximo **4** respostas de `/pcap` e `/raw` em andamento ao mesmo tempo (as duas
   rotas somadas); acima, `503` com `Retry-After: 1`. Cada resposta tem prazo de escrita de **60 s**
   (`http.ResponseController.SetWriteDeadline`, por resposta; sem `WriteTimeout` global, que quebraria SSE, WS e
   long-poll); o cliente que não lê nesse prazo tem a conexão encerrada.
4. **`request_line.target_truncated` (160).** Booleano em `HTTP1Request.request_line`. `target` é cortado em
   `FS_EVENT_INLINE_MAX` bytes, numa fronteira de runa, e reduzido mais se o evento ainda não couber nos 900 KiB
   (o último recurso de `fitHTTP1`). O alvo completo segue em `raw_head_b64` (quando não cortado) e no fluxo
   `in` (`/raw?dir=in`). Complementa a ADR 0018.
5. **`lists_truncated` no `TLSInfo` (165).** Booleano. Para o evento caber em 900 KiB, o produtor (web e raw)
   reduz as listas analisadas (cipher suites, extensões, grupos, algoritmos, etc.) e corta as strings longas
   `ja3`, `ja3n`, `ja4_r` e `ja4_o`; `lists_truncated: true` marca o corte. Os fingerprints são **sempre
   calculados sobre o ClientHello completo**, antes do corte; o ClientHello cru segue em `client_hello_b64`
   (com `client_hello_truncated` da ADR 0018) e no fluxo `in`. O evento nunca é descartado por tamanho.
6. **`transport_params_truncated` e `h3_settings_truncated` no `HTTP3Info` (171).** Booleanos: `true` quando o
   parser parou em **1024** parâmetros de transporte ou em **256** pares de SETTINGS do h3, ou quando a lista foi
   reduzida para caber no evento.
7. **Upgrade WebSocket sem frames (185): `upgrade_only` em `WebSocketFramePayload`.** Quando a sessão termina sem
   que nenhum frame tenha levado o `upgrade`, o web publica um `fs.v1.web.websocket.frame` com
   `upgrade_only: true`, `upgrade` preenchido e os campos de frame zerados (`dir: in`, `opcode: 0`, `length: 0`,
   `close: null`). O store, ao ver `upgrade_only`, preenche `over/path/extensions/subprotocol` do `websocket` e
   **não acrescenta frame**: o registro fica com `frames: []` e `close: null`. Escolhido em vez de um subject
   novo (`fs.v1.web.websocket.upgrade`), que mexeria na lista do stream (ADR 0017), no `nats.conf` e em
   `pkg/event/subjects.go`. Um WebSocket recusado por falta de vaga (ADR 0033) não gera o evento.
   **Ordem de implantação**: store antes do web, ou os dois no mesmo deploy; um store antigo trataria o evento
   como um frame de opcode 0.
8. **Só descrição (sem mudar forma):**
   - `HTTP2Stream.stream_id` (145): `0` = o web não conseguiu ligar o handler a um stream (stream não
     identificado); o store **sempre acrescenta** os eventos com `stream_id` 0 em `http2.streams[]`, nunca
     substitui. A ligação handler × stream é heurística (pseudo-cabeçalhos e, no empate, campos regulares do
     primeiro bloco contra o `r.Header`); duas requisições idênticas em todos os campos podem trocar de stream.
     `streams_truncated` fica fora (o teto de 1000 streams continua sem marca).
   - `HTTP2Stream.status` (146): `0` com RST_STREAM, 400 ou 431 do servidor em `http2.frames` = stream recusado
     pela biblioteca `x/net/http2` antes de chegar ao handler; sem campo novo.
   - `src_ip` de `GET /api/v1/packets` (177): IP do cliente, isto é, a origem com `dir=in` e o destino com
     `dir=out`, como no filtro do tempo real.
   - `LiveKind` (178): os 6 tipos filtráveis; `stream.dropped` não é filtrável (400 se pedido) e é sempre
     entregue a quem perdeu eventos.
   - `RawInfo.probe_line` (181): a linha `PROBE` como recebida, **incluindo o terminador** (CRLF ou LF), igual no
     raw e no web.
   - `head_too_large` (131, 155): cabeçalho acima de 1 MiB, de 1024 campos ou do orçamento de entrada do web
     (ADR 0033); resposta 431.
   - `body.chunks_truncated` (133): acima de 4096 pedaços **ou** de 256 KiB de extensões somadas na requisição.
   - `DNSQuery.rate_limited` (147): só UDP (resposta TC=1); TCP fica fora do RRL (ADR 0035).
   - `DELETE /api/v1/probes/{id}` (150): conexões abertas do probe somem na hora das leituras e são apagadas
     quando fecham (ADR 0034).
9. **Versões e exemplos.** `openapi.yaml` 0.6.0 e `asyncapi.yaml` 0.5.0. Os exemplos são regravados pelos testes
   dos produtores nas tarefas de implementação. Por delegação nesta ADR (ADR 0023, task 204): o teste de contrato
   de `pkg/event` exige que `event.WebSocketFrame` e `event.HTTP3Info` tenham toda propriedade dos esquemas, então
   eles ganham `UpgradeOnly`, `TransportParamsTruncated` e `H3SettingsTruncated` (`bool`, `omitempty`, falsos até
   os produtores os ligarem); a tabela de erros da API (`internal/store/testdata/api-error-cases.json`) marca os
   novos `503` como ainda não provocáveis até as tasks 129 e 152 os implementarem, e `TestParseOpenAPIOps` passa a
   esperar o `503` em `getProbe` e `getConnectionRaw`.

## Alternativas consideradas
- Probe sem teto, só com serialização em fluxo: tira o pico do `writeJSON`, mas não o de montar o conjunto nem o
  de um cliente que pede o probe em laço; o teto com `truncated` é previsível e o resto já tem rota paginável.
- Teto de esperas por variável de ambiente (`FS_PROBE_WAIT_MAX`): mais um botão sem caso de uso; 64 cabe na
  vCPU com a volta barata e pode virar variável depois sem mudar o contrato.
- Fila de espera em vez de 503 para downloads e `wait`: prende goroutines e memória exatamente quando o serviço
  está sob pressão; 503 com `Retry-After` devolve a decisão ao cliente.
- Responder 414 a alvos longos (160): mudaria a resposta que o espelho dá e contrariaria o "alvo literal" da
  spec 009; o corte só no evento não muda o que o cliente vê.
- Descartar o ClientHello acima do teto (165, comportamento de hoje): o espelho perderia justamente o registro
  anômalo que existe para mostrar.
- Subject novo para o upgrade WebSocket (185): mais limpo semanticamente, mas toca stream, `nats.conf` e o teste
  de subjects para um caso raro; o campo no payload existente é aditivo.
- `rejected: true` no `HTTP2Stream` (146) e `streams_truncated` (145): campos novos para casos raros que o
  conjunto `status: 0` + `frames` já explica.

## Consequências
- Specs 001, 004, 006, 007, 008, 009, 010, 011 e 012 atualizadas; openapi 0.6.0 e asyncapi 0.5.0.
- Tarefas: 152 e 153 (store: tetos do probe e do `wait`), 129 (store: downloads), 160 e 171 (web), 165 (web e
  raw), 185 (web e store, store antes ou junto), 145/146 (web e store), 177 (store), 181 (web).
- Um cliente que lia o probe inteiro precisa olhar `truncated` e paginar por `/connections?probe=`; o caso só
  aparece acima de 1000 conexões ou 1000 consultas no mesmo probe.
- Release seguinte: v0.3.0 (contratos 0.6.0/0.5.0).
