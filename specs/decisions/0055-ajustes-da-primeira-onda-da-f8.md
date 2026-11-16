# 0055 — Ajustes da primeira onda da F8 (publicação do store, migration e API do bot)

Status: aceita
Data: 2026-11-16

## Contexto
Fatos das entregas da primeira onda:
- Task 268 (PR #241): o store publica `fs.v1.store.connection`. O benchmark `BenchmarkIngestOfficialMix` no finger-01
  deu +20% de CPU por conexão com a publicação (0,62 → 0,75 cpu-ms/conexão; ~2,85 `updated` por conexão no mix), acima
  da meta de ≤ 10% da tarefa. Na carga real a 100 novas/s e 400 simultâneas foram ~+7%, com o store longe do limite
  (~0,13 ms/conexão, ~1,3% de um núcleo a 100/s). Para chegar aí, o `updated` passou a sair no máximo um a cada 100 ms
  por conexão, desvio do "a cada evento de aplicação" da spec 004 RF-12. O health passou a esperar 6 serviços e mostra
  `bot: down` até o deploy do bot (task 269).
- Task 267 (PR #239): a migration 0001 do bot difere em detalhes do esquema previsto na spec 018; o implementer-bot
  pediu regra para o `Authorization` que não é chave na 9003 e para o forwardAuth com chave cujo domínio não casa; e
  acrescentou as chaves `FS_BOT_*` ao `.env.example` (arquivo do infra) no próprio PR, com o aval de quem coordenou a
  rodada.

## Decisão
1. **`updated` com intervalo mínimo de 100 ms por conexão** (altera a spec 004 RF-12): o primeiro `updated` sai na
   hora; os eventos de aplicação seguintes dentro de 100 ms viram um só `updated` no fim da janela, com o estado daquele
   instante. O bot substitui o registro a cada estágio (spec 018), então só estados intermediários se perdem.
   `opened` e `closed` não mudam.
2. **Custo da publicação aceito**: a meta de ≤ 10% no benchmark era da tarefa, não de RNF. O critério que vale é o RNF-02
   da spec 018 (com o bot assinando, o store mantém as metas da ADR 0046), medido na carga da F8. O benchmark fica como
   medida de regressão (referência 0,75 cpu-ms/conexão). Se a carga da F8 falhar por CPU do store, abre-se tarefa para
   reduzir o custo do `updated` (ex.: registro parcial).
3. **Health com 6 serviços**: `bot: down` e `ok: false` entre a 268 e a 269 são aceitos como transição; o smoke confere
   os serviços por nome e o `versions_match`.
4. **Migration 0001 do bot aprovada com os desvios** (spec 018 "Dados" atualizada): tabelas `STRICT`;
   `key_usage_daily`, `ip_hourly` e `fp_daily` `WITHOUT ROWID`; contadores `NOT NULL DEFAULT 0`; `CHECK` em
   `api_keys.mode` (`observe|block`) e `fp_daily.kind` (`ja4|akamai|ja4h|ja4t`); índice `fp_daily_day` para o expurgo;
   tempos em segundos Unix e `day` = epoch/86400; `auto_vacuum=INCREMENTAL`; uso diário das chaves expurgado depois de
   90 dias (não tem IP; a ADR 0052 não se aplica).
5. **`Authorization` na 9003**: valor que não é `Bearer fsk_...` é ignorado (requisição sem chave), porque o forwardAuth
   repassa os cabeçalhos do visitante e um `Basic`/`Bearer` do próprio site não pode virar 401. `Bearer fsk_...`
   inválida dá 401 como na 9002. Na 9002 a regra da spec 020 RF-02 não muda.
6. **forwardAuth com chave cujo domínio não casa com `X-Forwarded-Host`**: 400 `bad_request` (erro de configuração do
   operador do traefik). O 404 indistinguível da ADR 0051 item 3 protege recursos de outros sites; no forwardAuth o
   sujeito é a própria requisição, e o erro precisa aparecer para o operador.
7. **Delegação registrada** (ADR 0023): a task 267 passa a listar o `.env.example` em `arquivos`, só para as chaves
   `FS_BOT_*` da spec 018 com os padrões; a task 269 cuida dos valores do finger-01 e do `FS_CAPTURE_EXCLUDE_PORTS`.

## Alternativas consideradas
- Exigir os ≤ 10% no benchmark antes de seguir — custaria uma reescrita do registro para um ganho de ~1% de um núcleo,
  sem RNF em risco na carga medida.
- Um `updated` por evento — refaz o registro inteiro a cada stream h2/h3 numa rajada, sem informação nova para o bot.
- 404 no forwardAuth com domínio fora da chave — esconderia do operador um erro de configuração que ele mesmo fez.

## Consequências
- asyncapi: `StoreConnection` passa a ter exemplos dos goldens do store e a descrição do intervalo de 100 ms.
- openapi do bot: descrições do 400 do forwardAuth e da regra do `Authorization` na 9003 (sem mudança de esquema).
- A carga da F8 (spec 017 RF-17) registra a CPU do store com e sem o bot assinando.
