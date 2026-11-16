# 0057 — Regras v1.1, teto de bytes do índice do bot e ajustes da segunda onda da F8

Status: aceita (pesos de 1 provisórios como os da 0049 — revisar com o e2e e a carga da F8)
Data: 2026-11-16

## Contexto
Fatos das tasks 276–281 (PRs #248–#252), levantados antes de a 282 ligar o veredito às rotas:
- **Regras v1.0 fracas para clientes de biblioteca** (276): com a ja4db desligada (ADR 0056 item 1), IP fora de
  nuvem e sem comportamento, curl, Go e python-requests saem `human` com score 20 (só `ja4h_library`); o Chrome
  headless sai `human` com score 0 e nenhum sinal: TLS e h2 são os do Chrome e nenhum sinal olha o marcador
  `HeadlessChrome` que o próprio UA declara. A base própria (task 270) já mede curl, Go, python-requests e o headless;
  o veredito não usa isso a favor da detecção, só contra o navegador incoerente.
- **Robôs sem sufixo de DNS reverso** (278): GPTBot, OAI-SearchBot (OpenAI) e DuckDuckBot publicam só a lista de IP;
  a verificação por DNS dá `unknown` e, pela ADR 0049 item 3 (`good_bot` exige a verificação de DNS), eles nunca
  seriam `good_bot` mesmo vindo das faixas publicadas.
- **Memória do índice** (277): típico ≈ 4,1 KB por conexão (≈ 393 MiB a 100 000), mas no pior caso hostil (valores
  únicos, 16 requisições por conexão com campos longos) ≈ 40 KB por conexão (≈ 3,8 GB) contra `MemoryMax=1G` e
  `GOMEMLIMIT=768MiB` do bot (spec 018 RNF-02). O único teto é `FS_BOT_MAX_CONNS`, em conexões.
- **`le="+Inf"`** (281): o store rejeita o valor como inválido, porque o conjunto de valores de rótulo da ADR 0056
  item 4 (`[A-Za-z0-9_.:/-]`) não tem `+`; o bucket `+Inf` do histograma já sai de `_count`.
- **`lists_version`** (278): o veredito ainda sai com `"none"` (constante em `internal/bot/verdict.go`); a troca pela
  versão real é da 282.

## Decisão
1. **Regras v1.1** (`rules_version = "v1.1"`; ADR 0049 item 6: goldens regravados no mesmo PR). Dois sinais novos,
   sem depender da ja4db, e a prova por lista para robôs sem DNS reverso:
   - `ua_automation` (tipo `list`, peso **70**): o UA declara automação — marcadores fixos em
     `internal/bot/rules/ua.go`, sem diferenciar maiúsculas: `headlesschrome`, `phantomjs`, `slimerjs`, `selenium`,
     `webdriver`, `puppeteer`, `playwright`, `cypress`, `htmlunit`. É `bot` sozinho: quem se declara automatizado
     não é humano, e não há lista que o verifique como robô bom. `detail` = o marcador achado.
   - `library_client` (tipo `list`, peso **50**): cliente de biblioteca ou ferramenta, por um de dois caminhos
     (`detail` diz qual): (a) o UA é de família de biblioteca da RF-06 (`curl`, `go`, `python`, `java`, `node`); ou
     (b) o UA está vazio ou é `other` e o JA4 visto, na base própria, só aparece em medidas de famílias de
     biblioteca. Nunca com UA de navegador (os sinais de incoerência cobrem o navegador falso), de headless (coberto
     por `ua_automation`) ou de robô (coberto por `ua_claims_crawler` e pela verificação). Com `ja4h_library` (20),
     curl/Go/python-requests chegam a 70 (`bot`); sem ele, 50 (`suspect`).
   - **Prova por lista** (altera a ADR 0049 item 3 e a ADR 0050 item 4): para operadores sem sufixo de DNS reverso
     publicado — `openai` (GPTBot, OAI-SearchBot, ChatGPT-User) e `duckduckgo` (DuckDuckBot e afins) — `good_bot`
     exige o IP numa lista publicada **do mesmo operador** e o UA declarando um robô dele; a verificação por DNS não
     é consultada. O `detail` de `ip_verified_crawler` diz `verified by ip list`. Fora da lista do operador, o UA de
     robô dá `ua_claims_crawler` como hoje. Para Google, Bing e Apple nada muda (lista **e** DNS reverso/direto).
     A tabela de operadores com o método (`dns` ou `list`) fica em `internal/bot/rules`, ao lado dos sufixos da 278.
   - **Classes esperadas nos goldens** (ja4db desligada, IP residencial, sem comportamento; a 282 e a 284 usam as
     mesmas):

     | Cliente | Sinais | Score | Classe |
     | --- | --- | --- | --- |
     | curl (h1/h2/h3) | `ja4h_library`, `library_client` | 70 | `bot` |
     | Go `net/http` | `ja4h_library`, `library_client` | 70 | `bot` |
     | python-requests | `ja4h_library`, `library_client` | 70 | `bot` |
     | Chrome | `known_client` | 0 | `human` |
     | Firefox | `known_client` | 0 | `human` |
     | Chrome headless | `ua_automation` | 70 | `bot` |
     | Googlebot falso (TLS de curl, IP fora da lista) | `ja4h_library`, `ua_claims_crawler` | 80 | `bot` |
     | GPTBot de IP da lista da OpenAI | `ja4h_library`, `ip_verified_crawler` | — | `good_bot` |
     | GPTBot de IP fora da lista | `ja4h_library`, `ua_claims_crawler` | 80 | `bot` |
     | python-requests sem UA | `ua_missing`, `ja4h_library`, `library_client` | 100 | `bot` |

     Os demais goldens da 276 são regravados com a v1.1 e revistos no PR (ex.: `python_ja4db` passa a `bot`).
   - **Limite conhecido da v1.1**: um Chrome automatizado que não declara a automação (Selenium sem headless,
     headless com UA trocado) tem TLS, h2 e UA do Chrome e sai `human` sem comportamento; quem o pega são os sinais de
     comportamento (`rate_high`, `interval_regular`, `route_breadth`, `no_reuse`). Sinal de JavaScript ou desafio
     segue fora de escopo (spec 018).
2. **Teto de bytes do índice do bot**: `FS_BOT_INDEX_MAX_BYTES` (padrão **384 MiB**), além de `FS_BOT_MAX_CONNS`.
   - Contabilidade aproximada: cada entrada (conexão do store, do traefix, requisições resumidas) soma um custo fixo
     por estrutura mais o tamanho dos textos e listas que ela guarda, na inserção e na substituição, e desconta na
     remoção; texto compartilhado pelo interner conta uma vez, no interner, enquanto vive. Erro aceito: ±25% contra
     o heap medido (`runtime/metrics`) nos benchmarks típico e hostil da task.
   - Passou do teto: despeja as conexões mais antigas (a mesma ordem do teto de conexões) até voltar abaixo dele.
     `bot_conns_evicted_total` ganha o rótulo `reason` (`count` | `bytes`; o vencimento pelo TTL não conta) e há o
     gauge `bot_index_bytes`. Health `degraded` com `index bytes` enquanto houver despejo por bytes nos últimos 60 s.
   - Por que 384 MiB: a 100 novas/s (RNF-01 do espelho, ADR 0046) e TTL de 10 min o índice tem ≈ 60 000 conexões
     (≈ 236 MiB típicos), abaixo do teto; o resto dos 768 MiB fica para listas de IP, agregados (com teto próprio,
     279), cache de verificação, buffers e a folga do GC. O tráfego hostil perde as conexões mais antigas (já
     decididas) em vez de levar o bot a OOM; o fail-open do forwardAuth (ADR 0047) cobre a visão perdida.
   - A carga da F8 (285) mede o índice no tráfego oficial e num trecho hostil (valores únicos, 16 requisições por
     conexão, UA de 512 bytes) com o bot dentro de `MemoryMax`/`GOMEMLIMIT`, sem OOM, e despejo por bytes contado.
3. **`le="+Inf"` fica fora** (mantém a ADR 0056 item 4): o heartbeat **não** envia o bucket `+Inf`; ele é por
   definição igual a `_count`, de onde o store já o tira. O conjunto de valores de rótulo não muda. asyncapi 0.6.2
   (documental) diz isso no `metrics`; a 282 confere que o bot não manda `+Inf` (o pacote do histograma do bot só
   emite os limites finitos).
4. **`lists_version` real na 282**: a constante `"none"` de `internal/bot/verdict.go` sai na 282, que preenche
   `rules_version` com `rules.RulesVersion` e `lists_version` com o da 278 (hash dos hashes da base própria e das
   listas de IP; a ja4db só quando ligada). Teste da 282 exige os dois diferentes de `"none"`.

## Alternativas consideradas
- Esperar a ja4db (P4) para pegar bibliotecas pelo `ja4db_match` — deixa o produto sem utilidade para o caso mais
  comum até uma resposta sem data; a base própria já mede as bibliotecas que importam.
- `library_client` como `bot` sozinho (peso 70) — um UA de biblioteca sem nenhum outro indício (ex.: ferramenta com
  `Accept-Language`) ficaria `bot` só pelo nome; com 50 ele fica `suspect` e precisa de mais um indício.
- Peso negativo para o Chrome headless coerente — o headless declarado é automação por definição.
- Teto só em conexões, mais baixo (ex. 20 000) — corta o tráfego típico (60 000 a 100/s) e não limita o pior caso
  por conexão; o teto em bytes limita o que de fato estoura.
- Teto de bytes por conexão — não limita o total (100 000 × teto ainda passa do `GOMEMLIMIT`); o teto global basta,
  com o limite de 16 requisições e 512 bytes de UA já existentes.
- Ampliar o conjunto de valores de rótulo para aceitar `+` — mexe no contrato para enviar um número redundante.

## Consequências
- Spec 018: tabela de pesos "rules v1.1" com os dois sinais novos e a prova por lista; RF-02 com
  `FS_BOT_INDEX_MAX_BYTES`; RF-11 com `index bytes`; RF-12 com `bot_index_bytes` e
  `conns_evicted_total{reason}`; env novo. ADR 0049 item 3 e ADR 0050 item 4 ganham nota apontando para cá.
- asyncapi 0.6.2 (documental): `+Inf` não enviado.
- Tarefas: 289 (implementer-bot, regras v1.1) e 290 (implementer-bot, teto de bytes do índice, com delegação do
  `.env.example`); a 282 passa a depender da 289 e da 290; a 283 e a 285 dependem da 290 (a 285 mede o trecho
  hostil).
