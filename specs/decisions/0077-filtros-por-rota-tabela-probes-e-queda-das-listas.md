# 0077 — Filtros por rota na API do store, fim da tabela `probes` e queda das listas de IP pelo espaço coberto

Status: aceita
Data: 2026-11-24

## Contexto
Três fatos da revisão de 2026-11-21 (commit `b30a5b1`), de baixa severidade, que tocam decisões aceitas:
- **Task 378**: `GET /api/v1/dns` não tem `until` e devolve as consultas mais novas primeiro; com mais de 2000
  consultas num probe, as do meio ficam inalcançáveis (o `/probes/{id}` dá as 1000 mais antigas, ADR 0032). O
  `ParseListFilter` comum aceita em `/dns` e `/packets` filtros que só `/connections` declara (`until`, `src_ip`,
  `dst_port` em `/dns`; `dst_port`, `probe` em `/packets`) e os ignora: o cliente recebe 200 com a mesma página, sem
  erro. A ADR 0001 diz que `/api/v1` só recebe mudanças aditivas.
- **Task 383**: a tabela `probes` (`first_seen`/`last_seen`) é escrita no lote do escritor único a cada evento com
  probe e a cada consulta DNS com probe, e nenhuma leitura a usa: o `/probes/{id}` vem de `connections` e
  `dns_queries`, e o openapi não tem `first_seen`/`last_seen`. A ADR 0068 item 1 cita "apaga a linha de `probes`"
  no `DELETE`.
- **Task 404**: a ADR 0050 item 3 recusa a lista de IP nova com "queda de > 50% das faixas", e o código conta
  prefixos. Um publicador que troca muitas faixas pequenas por poucas maiores é recusado em todo download, para
  sempre: a cópia velha fica, o health do bot fica `degraded` (`list <nome> stale`) depois de 72 h e não há saída
  operacional (`lists refresh` passa pela mesma validação).

## Decisão
1. **Filtros por rota no store (task 378; interpreta a ADR 0001).**
   - `GET /api/v1/dns` ganha `until` (inclusivo, `ts_ns <= until`), como `/connections` e `/packets` (aditivo,
     contrato 0.9.0). Paginação para trás: o cliente repete com `until` = `ts` da mais velha recebida e descarta as
     linhas repetidas da borda (mesmo `ts`); o índice `dns_queries_probe (probe_id, ts_ns)` atende.
   - Os filtros do conjunto comum da API (`src_ip`, `dst_port`, `since`, `until`, `probe`) que a rota **não declara**
     no openapi respondem **400** (`{"error":"parameter <nome> not supported on <rota>"}`): `src_ip` e `dst_port` em
     `/dns`; `dst_port` e `probe` em `/packets`. Parâmetro fora desse conjunto continua ignorado em todas as rotas
     (ex.: `_=<cache-buster>`).
   - Não é quebra da ADR 0001: o contrato nunca declarou esses parâmetros nessas rotas, e a resposta de hoje é
     errada em silêncio (filtro pedido e não aplicado). Nenhum cliente versionado (htdocs, e2e, docs) os usa.
2. **Fim da tabela `probes` (task 383; ajusta a ADR 0068 item 1).** Migration nova do store remove a tabela e o
   índice `probes_last_seen` (o `down` os recria vazios); saem a escrita no ingest (`upsertProbe`), o passo da
   retenção e o `DELETE` da linha no `DELETE /api/v1/probes/{id}`. A existência de um probe passa a ser só a de
   conexões ou consultas DNS visíveis com o probe ID: `DELETE` e `GET` respondem 404 quando não há nenhuma, 204/200
   quando há (como hoje, salvo o probe cuja única marca era a linha de `probes`, que já não aparecia em leitura
   nenhuma). O resto da ADR 0068 segue.
3. **Queda das listas de IP pelo espaço coberto e refresh forçado (task 404; substitui o critério de queda da ADR
   0050 item 3).**
   - A lista de IP nova é recusada quando vazia ou quando, em alguma família (IPv4, IPv6) presente na lista anterior,
     o **espaço coberto** (número de endereços da união dos prefixos, sem contar duas vezes os que se sobrepõem) cai
     a menos da metade do anterior; a família que some inteira conta como queda. A contagem de prefixos deixa de ser
     critério (consolidar 40 /28 em 4 /24 é aceito). A ja4db (não é lista de IP) segue a regra pela contagem de
     entradas.
   - Saída operacional: `finger-sniffer-bot lists refresh --force <nome>` (nome obrigatório) grava em
     `control_requests` o pedido `lists_refresh` com `arg` = `force:<nome>` (sem migration: os nomes do catálogo são
     `[a-z0-9_]+`, então o prefixo não é ambíguo; ADR 0056 item 2). O serviço baixa e aplica a validação do formato e
     de lista não vazia, sem a regra da queda, e registra no log (`warn`, com o espaço anterior e o novo por
     família). O resto da ADR 0050 item 3 (atualização diária, cópia, métricas, `lists_version`) segue.

## Alternativas consideradas
- Item 1: ignorar os filtros não declarados de forma documentada — mantém 200 com dados que não respondem ao filtro;
  400 para qualquer parâmetro desconhecido — quebraria cache-busters e parâmetros de clientes sem motivo; dar
  sentido a `src_ip` em `/dns` (IP do resolvedor) — aditivo, mas ninguém pediu, e o nome confunde com o cliente.
- Item 2: dar uso à tabela (`first_seen`/`last_seen` no `Probe`, uma escrita por probe por lote) — nenhum cliente
  pediu; os instantes já saem das conexões e consultas do probe.
- Item 3: aplicar a regra pela contagem só acima de um mínimo de entradas (ex.: 100) — deixa as listas pequenas sem
  proteção contra um arquivo truncado; só o `--force` — exige ação manual a cada consolidação legítima.

## Consequências
- Contrato do store 0.9.0 (aditivo: `until` em `/dns`; 400 dos filtros não declarados); spec 004 e `docs/api.md`.
- Uma escrita a menos por evento com probe no escritor único e um passo a menos na retenção; migration nova do
  store aprovada pelo architect no PR.
- O bot passa a aceitar consolidações de faixas; uma queda real do espaço continua recusada e pode ser forçada pelo
  operador. `docs/bot.md` traz o procedimento.
