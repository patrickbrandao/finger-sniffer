# 0056 — Segunda onda da F8: ja4db desligada até a P4, pedidos da CLI ao serviço, visão HTTP do store e métricas com rótulos

Status: aceita (item 1 provisório: revisar quando o humano responder à pendência P4 da spec 018)
Data: 2026-11-16

## Contexto
Fatos da primeira onda da F8 (tasks 267–270, PRs #237–#244) que a segunda onda precisa resolver:
- **P4 aberta**: os termos da ja4db da FoxIO (download diário, uso como sinal, redistribuição) seguem sem resposta do
  humano. A ADR 0050 item 2 previa o download diário com URL padrão; quem coordena a rodada pediu que o download e o
  uso fiquem atrás de uma opção desligada até a resposta.
- **CLI e serviço são processos distintos** (PR #239): `finger-sniffer-bot forget` apaga o banco, mas a memória do
  serviço em execução (índice, vereditos, agregados ainda não gravados) só expira em 10 min — e o flush seguinte
  regravaria no disco o IP que acabou de ser esquecido. `lists refresh` tem o mesmo problema, e quem tem rede de
  saída e escrita em `var/bot/lists` com o endurecimento da unit é o serviço.
- **Visão HTTP do store**: o índice do bot descarta as listas `http`, `websocket` e `raw` do `Connection`
  (`slimRecord`). O veredito por probe (spec 020, clientes externos sem traefix) e o de conexões diretas ao espelho
  dependem do `User-Agent`, da ordem dos campos, do JA4H e do `Origin`/`Referer` dessas requisições, que só o store
  vê.
- **Métricas com rótulos**: a spec 018 RF-12 pede `bot_verdicts_total{class,source}`, `bot_auth_seconds`
  (histograma), `bot_list_age_seconds{list}` e outras com rótulo, mas o heartbeat é um mapa plano nome → número e o
  `/metrics` do store republica cada chave como `fs_<chave>{service}` com `sanitize` no nome.
- **IP da bridge**: os exemplos da spec 019 e o `servers` do openapi do bot usavam `10.249.0.1`; o IP do host na
  bridge `br-net-public` do finger-01 é `10.249.255.254` (task 269).

## Decisão
1. **ja4db desligada por padrão** (altera a ADR 0050 item 2 só no padrão): opção `FS_BOT_JA4DB_ENABLE` (padrão
   `false`); `FS_BOT_JA4DB_URL` passa a ter o padrão `https://ja4db.com/api/read/`. Desligada: nada é baixado nem
   lido de `var/bot/lists/ja4db.json`, o sinal `ja4db_match` nunca aparece, `ja4db_label` é `null`, a ja4db fica fora
   do `lists_version`, das métricas por lista e do `list ja4db stale`. O código, a validação e os testes (amostra
   sintética em `testdata`) entram completos; ligar é ação do humano depois da P4 (env no finger-01), sem código novo.
2. **Pedidos da CLI ao serviço** pela tabela `control_requests` do banco do bot (migration 0002, escrita pelo
   implementer-bot e aprovada pelo architect): `id INTEGER PRIMARY KEY`, `op TEXT NOT NULL CHECK (op IN ('forget',
   'lists_refresh'))`, `arg TEXT` (prefixo ou nome da lista), `created_at INTEGER NOT NULL`, `done_at INTEGER`,
   `result TEXT`; `STRICT`. O serviço lê os pedidos pendentes no mesmo ciclo de 2 s da recarga das chaves.
   - `forget <ip|prefixo>`: a CLI continua apagando o disco ela mesma (funciona com o serviço parado) e grava o
     pedido; o serviço apaga da memória tudo daquele prefixo (índice das duas visões, vereditos, acumuladores dos
     agregados antes do flush, contadores de caminhos, cache de comportamento e cache da verificação de robô), apaga o
     disco de novo (cobre o flush concorrente) e marca `done_at`. A CLI espera até 10 s e diz se a memória foi
     alcançada ou se o serviço não respondeu (memória expira em 10 min).
   - `lists refresh [nome]`: a CLI grava o pedido e espera até 120 s pelo resultado por lista; o download, a
     validação e a troca são do serviço (rede e permissões da unit).
   - Pedidos concluídos são apagados depois de 24 h (o `arg` do `forget` é dado pessoal, ADR 0052).
   - Sem rota de administração na API: nada de controle exposto em 9002/9003.
3. **Resumo HTTP do store no índice**: em vez de descartar `http`, o índice guarda por conexão do store até 16
   requisições resumidas (a primeira e as mais recentes): método, versão, `authority` (só o host), `User-Agent`
   (até 512 bytes), ordem dos nomes de campo, presença de `Accept-Language`, JA4H e o host de `Origin`/`Referer`.
   Nunca caminho com query, corpo, valores de cookie ou de `Authorization` (ADR 0052 item 2). `websocket` e `raw`
   continuam fora. É a visão `http` do veredito quando não há a do traefix (probe e conexões diretas).
4. **Métricas com rótulos no heartbeat** (asyncapi 0.6.1, documental): uma chave de `metrics` pode trazer rótulos no
   formato Prometheus, `nome{rotulo="valor",...}`, com nomes de rótulo `[a-z_]+` e valores `[A-Za-z0-9_.:/-]{1,64}`;
   histograma vai como as séries cumulativas `nome_bucket{le="..."}`, `nome_sum` e `nome_count`. O `/metrics` do
   store republica `fs_<nome>{service="<svc>",<rótulos>}` (contador quando o nome termina em `_total` ou `_count`,
   `_sum` e `_bucket` também como contador, o resto gauge); chave malformada é ignorada e contada em
   `fs_store_heartbeat_metrics_invalid_total`. Chaves sem rótulo seguem como hoje. No máximo 512 chaves por heartbeat
   de um serviço (o resto é ignorado e contado na mesma métrica).
5. **IP da bridge corrigido**: `10.249.255.254` nos exemplos da spec 019 e no `servers` do openapi do bot (0.1.1,
   documental). Nenhum código mudou: a task 269 já usa esse IP.

## Alternativas consideradas
- Rota de administração na 9003 só de loopback para `forget`/`lists refresh` — expõe controle na rede da bridge se o
  filtro de origem falhar e acrescenta rota fora do uso previsto do contrato; a tabela já é o canal das chaves.
- Sinal ao processo (`SIGHUP`) para recarregar — não carrega argumento (o prefixo do `forget`) nem devolve resultado.
- A CLI baixar as listas — roda como outro usuário, fora do endurecimento da unit, e deixaria arquivos com dono
  errado em `var/bot/lists`.
- Guardar o `Connection` inteiro do store no índice — 100 000 conexões com todas as requisições h2 estouram o
  `GOMEMLIMIT` de 768 MiB; o resumo limitado basta para os sinais da ADR 0049.
- Métricas do bot num `/metrics` próprio na 9003 — um segundo ponto de coleta; o `/metrics` agregado do store já é o
  único da operação (spec 004).

## Consequências
- Migration 0002 do bot; `.env.example` ganha `FS_BOT_JA4DB_ENABLE=false` e as URLs `FS_BOT_LIST_<NOME>_URL`
  comentadas (delegação ao implementer-bot pela tarefa das listas).
- Métricas novas do bot na spec 018 RF-12: `bot_auth_wait_seconds` (a espera da RF-04 à parte, para a carga medir o
  RNF-01 sem ela), `bot_ingest_parse_errors_total{part}` e `bot_agg_dropped_total`.
- Tarefa do implementer-store para republicar as métricas com rótulos; `docs/metrics.md` descreve o formato.
- O sinal `ja4db_match` só é coberto pelos goldens com a opção ligada sobre a amostra sintética; os goldens com as
  listas reais rodam com a ja4db desligada até a P4.
