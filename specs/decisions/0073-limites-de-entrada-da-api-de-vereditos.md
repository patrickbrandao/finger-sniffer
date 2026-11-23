# 0073 — Limites de entrada da API de vereditos: conexões da 9002, ingest, chaves, feed, agregados e webhook

Status: aceita (item 1.1, teto por origem na 9002, provisório até o humano confirmar que o "sem limite por IP" da
ADR 0001 não alcança a porta do bot; números provisórios, revisar com a carga da F8 seguinte)
Data: 2026-11-23

## Contexto
A revisão completa de 2026-11-21 (commit `b30a5b1`) provou, com o código do bot e testes injetados por
`go test -overlay` (`tmp/revisao-2026-11-21/provas/`), que os limites da ADR 0051 item 4 (balde 20/s e 40, cota
100 000/dia por chave; 200 conexões na 9002; 64 clientes SSE; lote de 4 MiB) contam a coisa errada ou nenhuma em
sete pontos:

- **task 336**: as 200 vagas da 9002 (`netutil.LimitListener`) só voltam quando a conexão fecha; uma conexão TLS
  anônima com o prefácio do h2 (ou um `GET /bot/v1/health` com keep-alive) fica 120 s (`IdleTimeout`). ~1,7
  conexões novas por segundo de um único IP mantêm a porta cheia; o 201º cliente espera no `accept` do kernel.
- **task 370**: o ingest lê o corpo inteiro (até 4 MiB) sem teto de lotes simultâneos e sem prazo de leitura
  (`http.Server` sem `ReadTimeout`); numa conexão h2 uma chave abre dezenas de streams com corpo lento. ~200 corpos
  parciais passam do `GOMEMLIMIT=768MiB`, a unit morre por `MemoryMax=1G` e levam junto a 9003 (forwardAuth dos
  sites do humano em fail-open).
- **task 371**: a ficha é cobrada por requisição HTTP; um lote de 1 024 registros custa uma ficha. O índice
  (`FS_BOT_MAX_CONNS`, `FS_BOT_INDEX_MAX_BYTES`) e os agregados (200 000 entradas) são globais: uma chave da 9002
  despeja as conexões do traefix do humano e as do store e esgota os agregados de todos por até 24 h. O feed tem um
  teto único de 64 para todas as chaves e para a 9003.
- **task 408**: com chave, balde e cota valem também na 9003, a cada forwardAuth, isto é, a cada requisição de cada
  visitante. Com os padrões da CLI um site acima de 20 req/s ou de 100 000 requisições no dia recebe 429 sem
  `X-Traefix-Verdict`, que o traefix trata como fail-open: o modo `block` para sozinho no meio do dia, sem aviso.
- **task 372 item 3**: `fs_bot_webhook_sent_total{code}` leva o status cru da resposta, escolhido pelo servidor
  remoto: até ~900 séries contra o teto de 512 chaves do heartbeat e, no `/metrics` aberto da 9001, um oráculo do
  SSRF que a mesma tarefa fecha nos itens 1 e 2.
- **task 332**: no ingest só `path` (256 bytes) e o valor dos campos permitidos (512 runas) têm teto; `method`,
  `authority`, `sni`, `entryPoint`, `router`, `service`, `fieldNames`, `cookieNames`, `ja4h`, nomes `Sec-Fetch-*` e
  os demais aceitam até o corpo de 4 MiB. O interner (`feed.go`) segura os textos depois que a conexão sai do índice:
  64 registros com `method` de 1 MiB deram 64 MiB de heap com `bot_index_bytes` em 1 MiB (contra a ADR 0057 item 2).
- **task 363**: o teto dos agregados não distingue o IP. Um visitante com `Host` aleatório numa conexão keep-alive
  cria 2 entradas por requisição; 100 000 requisições enchem o teto, e daí nenhum outro IP acumula: `rate_high`,
  `no_reuse`, `interval_regular` e `route_breadth` somem para todos (`view.behavior=false`) e `ip_hourly` para de
  crescer.

A ADR 0051 item 4 não fala de prazo, concorrência, registros, partes por chave nem cortes; nada aqui reabre o que
ela decidiu (os números dela ficam): os limites novos se somam aos dela. O "sem limite de conexões por IP" da ADR
0001 é uma escolha do humano para o espelho, decidida antes de o bot existir; o item 1.1 abaixo o aplica só às
portas do espelho (capturadas e a API do store) e põe na 9002 um teto por origem, provisório até o humano confirmar.

## Decisão
Todos os números são constantes do código (sem variável de ambiente), como o teto de 200 da ADR 0051; a CLI da chave
ganha `--ingest-rate` e `--ingest-burst` (item 3.1). "Origem" é o IPv4 e, em IPv6, o /64, com o IPv4 mapeado
normalizado.

1. **Conexões da 9002** (task 336; spec 020 RF-04):
   1. **Teto por origem: 16 conexões simultâneas** (provisório, ver Status). Embrulho do listener antes do
      `LimitListener`: a 17ª conexão da mesma origem é fechada no `Accept`, sem ocupar vaga global, e conta em
      `bot_public_conns_closed_total{reason="source"}`. Só na 9002; a 9003 fica sem teto por origem (rede do
      traefik, ADR 0047 item 4).
   2. **`IdleTimeout` de 30 s** na 9002 (a 9003 fica com 120 s, para o pool do traefik); **`ReadHeaderTimeout` de 5 s**
      nas duas portas (o `net/http` usa o menor de `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout` também como
      prazo do handshake TLS, então o handshake da 9002 fica em 5 s, sem listener próprio).
   3. **Ociosas sob pressão**: com 180 conexões ou mais (90% de 200), o servidor fecha as conexões em `StateIdle`
      mais antigas (`http.Server.ConnState` mantém o conjunto) até voltar a menos de 180; cada uma conta em
      `bot_public_conns_closed_total{reason="idle"}`. Vale para h1 com keep-alive e para h2 sem stream aberto.
   4. **Health**: `degraded` com `public conns` quando a 9002 chegou às 200 conexões nos últimos 60 s.

2. **Lotes do ingest** (task 370; spec 020 RF-04 e RF-05):
   1. **Semáforo de lotes**: no máximo **8 lotes** em leitura, decodificação e aplicação ao mesmo tempo no processo;
      os lotes da 9002 usam no máximo **6** das 8 (2 ficam para a 9003); cada chave da 9002 no máximo **2**. A vaga
      é pega antes de ler o corpo e nunca espera: sem vaga global (ou das 6 da 9002), **503** `busy` com
      `Retry-After: 1`, sem ler o corpo (o traefix conta `http_5xx` e descarta o lote, sem atrasar requisição de
      site); sem vaga da chave, **429** `rate_limited` com `Retry-After: 1`. Conta em
      `bot_ingest_refused_total{reason="busy"|"key_concurrency"}`.
   2. **Prazo do corpo: 10 s** desde o início do handler
      (`http.NewResponseController(w).SetReadDeadline`), nas duas portas (o `sendTimeout` do traefix é 2 s). Corpo
      que não chega no prazo: a leitura falha, a vaga volta, resposta 400 `bad_request` (`body read failed`) e
      `bot_ingest_refused_total{reason="body_timeout"}`.
   3. Código de erro novo **`busy`** no enum de `Error` (aditivo), só para os 503 de capacidade deste item. O 503
      do feed cheio (64 clientes) continua com `internal`, como hoje.

3. **Chaves: registros e parte dos tetos globais** (task 371; as duas opções da tarefa):
   1. **Cobrança por registro no ingest da 9002**: balde de registros próprio da chave, **500 registros/s** e
      rajada de **2 048** (dois lotes cheios), definidos por `key create --ingest-rate --ingest-burst` (colunas
      `api_keys.ingest_rate` e `ingest_burst`, nulas = padrão; migration 0003 do bot). Depois de decodificar, o lote
      tira `len(records)` fichas de uma vez: sem fichas para o lote inteiro, **429** `rate_limited` com
      `Retry-After` = segundos até ter as fichas, nenhum registro aplicado, `bot_ingest_refused_total{reason=
      "key_records"}`. A ficha da requisição (balde da ADR 0051) continua sendo cobrada antes. Os registros aceitos
      somam em `key_usage_daily.records` (coluna nova, `NOT NULL DEFAULT 0`); sem cota diária de registros.
   2. **Parte por chave nos tetos globais**: toda conexão do fork e toda entrada dos agregados tem um dono, a chave
      da 9002 que a criou ou "interno" (9003, com ou sem chave, e o store). Cada chave da 9002 fica com no máximo
      **10%** de cada teto (conexões do fork: 10% de `FS_BOT_MAX_CONNS` e 10% de `FS_BOT_INDEX_MAX_BYTES`;
      agregados: 10% das 200 000 entradas) e todas as chaves da 9002 juntas com no máximo **50%**. No índice, passar
      da parte despeja primeiro as conexões mais antigas da própria chave (ou, nos 50%, das chaves da 9002), nunca
      as internas nem as do store, e conta em `bot_conns_evicted_total{reason="key"}`. Nos agregados, a observação
      que criaria entrada acima da parte é descartada e conta em `bot_agg_limited_total{reason="key"}`. Sem rótulo
      de chave nas métricas (cardinalidade livre); o uso por chave fica no `key_usage_daily`.
   3. **Feed**: dos 64 clientes, a 9002 usa no máximo **48** (16 ficam para a 9003) e cada chave da 9002 no máximo
      **4**. Acima da parte da chave, **429** `rate_limited` com `Retry-After: 15`; acima dos 48 da 9002 ou dos 64,
      **503** `internal` como hoje.

4. **9003 sem limites de chave** (task 408, opção 1): na 9003 a chave só escolhe domínios e modo; balde, cota,
   cobrança por registro (3.1), parte por chave (3.2 e 3.3) e vaga por chave do ingest (2.1) não se aplicam ali, em
   nenhuma rota. Os limites da 9003 são os globais, com ou sem chave (spec 020 RF-02). O uso continua gravado em
   `key_usage_daily` (requisições e registros), sem recusar. Na 9002 tudo vale como antes, inclusive para o
   forwardAuth de um traefix externo (uma ficha por requisição do visitante: o `docs/bot.md` diz para criar a chave
   com `--rate`/`--burst` acima do pico e `--daily` acima do volume diário). Health `degraded` com
   `block key limited` quando uma chave em modo `block` recebeu 429 nos últimos 60 s.

5. **Rótulo do webhook por classe** (task 372 item 3; spec 018 RF-12): `bot_webhook_sent_total{code}` passa a ter
   só `2xx` (200–299), `3xx` (300–399; com o item 1 da 372 o redirecionamento não é seguido e conta como resposta
   final, sem nova tentativa, como 4xx), `4xx` (400–499), `5xx` (500–599) e `error` (erro de rede, prazo de 5 s,
   destino recusado no dial e qualquer status fora de 200–599). No máximo 5 séries. Mudança de valores de rótulo
   da série existente, sem contrato de API; `docs/metrics.md` troca a linha da métrica.

6. **Tetos dos textos do ingest** (task 332; spec 018 RF-03; os dois esquemas, em `check()`): o bot **corta** (não
   recusa) cada texto acima do teto, em bytes, na fronteira de UTF-8, e conta em
   `bot_ingest_clipped_total{field}` (rótulo fechado com os nomes da tabela). Cortar, e não recusar, porque o
   traefix é consumido como está (ADR 0062): nenhum registro que o traefix manda hoje passa a ser recusado.

   | Campo (`TraefikRecord` / `traefix.fingerprint/v1`) | Teto | `field` |
   | --- | --- | --- |
   | `method` | 32 bytes | `method` |
   | `http_version` / `httpVersion` | 16 bytes | `http_version` |
   | `authority`, `sni` / `tls.sni` | 255 bytes | `authority`, `sni` |
   | `entry_point` / `entryPoint`, `router`, `service` | 128 bytes | `entry_point`, `router`, `service` |
   | `tls_version`, `cipher` / `tls.version`, `tls.cipher` | 64 bytes | `tls_version`, `cipher` |
   | `alpn` / `tls.alpn`; cada item de `alpn_offered` / `tls.alpnOffered` | 255 bytes; até 16 itens | `alpn` |
   | cada item de `field_names`/`cookie_names` / `fieldNames`/`cookieNames` | 64 bytes; até 128 itens | `field_names`, `cookie_names` |
   | nome de campo em `fields` | 64 bytes (acima, o valor é descartado, como campo fora da lista permitida) | `field_name` |
   | valor de campo permitido | 512 bytes (era 512 runas e recusava o registro) | `field_value` |
   | `ja4h` | 128 bytes (acima, tratado como ausente) | `ja4h` |

   Listas acima do teto de itens ficam com os primeiros. `path` continua recusando acima de 256 bytes (contrato
   atual). Defesa em profundidade: o interner não compartilha texto acima de 1 KiB (devolve a cópia, que sai com a
   conexão). No openapi os tetos entram como texto (descrição da operação e dos registros), não como `maxLength`:
   o esquema do traefix não fica mais estreito no contrato do bot.

7. **Agregados por IP** (task 363; spec 018 RF-08 e RF-09):
   1. **Sites distintos por origem por hora: 32.** A observação que criaria a 33ª entrada de comportamento (IP +
      site) ou de hora aberta da mesma origem na mesma hora é descartada; conta em
      `bot_agg_limited_total{reason="ip_sites"}`. As entradas que a origem já tem continuam acumulando.
   2. **Fingerprints novas por origem por dia: 256.** Acima, a origem não cria entrada nova em `fp_daily` (as
      existentes continuam contando); `bot_agg_limited_total{reason="ip_fingerprints"}`. Os contadores por origem
      vivem enquanto a origem tem entradas e zeram na virada da hora e do dia.
   3. **Requisição sem router fora dos agregados**: registro `request` do ingest com `router` ausente ou vazio **e**
      `status` 404 (o traefik não achou rota para o `Host`) é indexado e julgado como hoje, mas não entra em
      `ip_hourly` nem em `fp_daily`. O forwardAuth só recebe hosts que um router aceitou. Os dois campos juntos,
      para não tirar dos agregados os registros do formato anterior que não trazem `router`.
   4. **Despejo com o teto global cheio**: em vez de recusar, despeja em lote os comportamentos (IP + site) menos
      recentes com todas as horas já gravadas (1% do teto por passo), contados em `bot_agg_evicted_total`; o
      histórico deles continua no banco e só sai do cache de memória: observado de novo, o comportamento recomeça da
      hora corrente e os sinais dele (RF-09) olham menos de 24 h até a janela se refazer, sem ler o disco. Sem nada despejável (tudo por gravar), a observação é descartada como hoje
      (`bot_agg_dropped_total`). Health `degraded` com `agg full` quando houve despejo ou descarte pelo teto global
      nos últimos 60 s (o motivo de health pedido na task 371).

8. **Contrato**: openapi do bot **0.6.0** (aditivo): `busy` no enum de `Error`; 503 `busy` e 429 de concorrência e
   de registros no ingest; 429 por chave no feed; os tetos do item 6 na descrição do ingest e dos registros; os
   limites da 9003 (item 4) na descrição. Nada muda no contrato com o traefix (spec 019): nenhum campo, cabeçalho
   ou formato novo pedido, nenhum registro hoje válido recusado; os 429/503 novos caem no fail-open e no descarte
   de lote que o traefix já tem.

## Alternativas consideradas
- **Só a cobrança por registro (371 opção 1)**: barata, mas qualquer chave dentro do próprio balde ainda enche o
  índice e os agregados de todos aos poucos; a parte por chave é o que protege a 9003 e o store.
- **Só a parte por chave (371 opção 2)**: não limita o custo de CPU de decodificar ~80 MiB/s de JSON.
- **Recusar o registro acima dos tetos (332)**: mais simples de testar, mas o traefix é consumido como está e um
  campo longo legítimo de uma versão nova faria o bot perder o registro inteiro.
- **`maxLength`/`maxItems` nos esquemas do traefix no openapi**: estreitaria, no contrato do bot, o que o traefix
  pode mandar (e a cópia validada do esquema dele, ADR 0063 item 3); fica como texto.
- **Manter balde e cota na 9003 e só documentar (408 opção 2)**: deixa o `block` cair em fail-open no meio do dia
  por um padrão da CLI; a 9003 sem chave já não tem limite de chave, então tirar o limite com chave não abre nada.
- **Site sintético `~other` acima do teto por IP (363)**: guardaria contagens sem significado; descartar é mais
  simples e não afeta os outros IPs.
- **Sem teto por origem na 9002** (manter a ADR 0001 em todo o sistema): os itens 1.2–1.3 sozinhos encarecem o
  ataque (cada conexão precisa ficar ativa ou no handshake de 5 s), mas um IP ainda segura a porta; o teto por
  origem fica provisório até o humano.
- **Prazo de handshake de 3 s com listener TLS próprio (336 item 3)**: 5 s pelo `ReadHeaderTimeout` resolve sem
  código novo.

## Consequências
- Spec 020 RF-02, RF-04, RF-05 (ingest e feed) e Contexto; spec 018 RF-02, RF-03, RF-08, RF-09, RF-10, RF-11, RF-12 e
  "Dados" (migration 0003); openapi do bot 0.6.0. `docs/bot.md` (limites, perfil do `block` na 9002, versão 0.6.0)
  e `docs/metrics.md` (métricas novas e a linha do webhook) nas tarefas de implementação.
- Métricas novas: `bot_public_conns_closed_total{reason}` (`source`|`idle`), `bot_ingest_refused_total{reason}`
  (`busy`|`key_concurrency`|`key_records`|`body_timeout`), `bot_ingest_clipped_total{field}`,
  `bot_agg_limited_total{reason}` (`ip_sites`|`ip_fingerprints`|`key`), `bot_agg_evicted_total`; valor novo
  `key` em `bot_conns_evicted_total{reason}`; `bot_webhook_sent_total{code}` com classes. Motivos de health novos:
  `public conns`, `agg full`, `block key limited`.
- Migration 0003 do bot (implementer-bot escreve, architect aprova no PR): `api_keys.ingest_rate`,
  `api_keys.ingest_burst` (INTEGER, nulas) e `key_usage_daily.records` (INTEGER NOT NULL DEFAULT 0).
- Implementação em série no `internal/bot` (`server.go` e `api.go` são compartilhados, ADR 0059): 336 → 370 → 408 →
  363 → 371; a 332 em paralelo (ingest e interner, sem `api.go`/`server.go`); o item 3 da 372 na task 412, depois da
  372 (`internal/bot/webhook`).
- Limites que ficam: `fp_daily` não tem site, então as observações de uma chave entram nas contagens que
  `/fingerprints` mostra às outras (agora limitadas a 10% das entradas por chave); um ataque distribuído de muitas
  origens ainda enche a 9002 (o teto por origem só encarece); números a medir na próxima carga da F8.
