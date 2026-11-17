# 0058 — forwardAuth do bot: JA4H por cabeçalho, chave na requisição de auth, fail-open de 4xx sem veredito e JA4T sem MSS

Status: aceita (pesos e regras seguem provisórios, ADRs 0049 e 0057)
Data: 2026-11-16

## Contexto
Fatos da segunda onda da F8 (tasks 282, 286 e 289; PRs #254, #256–#258):
- **JA4H na primeira requisição**: o forwardAuth do traefik repassa os cabeçalhos do visitante num mapa (`http.Header`)
  e perde a ordem; o bot não consegue calcular o JA4H, e o resumo da requisição (`type=request`, com `ja4h`) só chega
  pelo ingest depois da resposta. A primeira requisição de cada conexão fica sem `ja4h_library`: um `curl` puro sai
  `suspect` 50 em vez de `bot` 70 e passa em modo `block`. As seguintes reaproveitam o JA4H do ingest da conexão.
- **Chave no forwardAuth**: a spec 019 não dava ao traefix como mandar `Authorization: Bearer fsk_...` na requisição
  de auth. Sem chave a 9003 é sempre `observe` (o modo é da chave), então `block` é inalcançável; no caso (c) da spec
  020 (traefix público apontando para a 9002) a auth recebe 401, e como 4xx volta ao cliente, o 401 chega ao visitante
  e derruba o site. Um middleware `headers` antes do forwardAuth sobrescreveria o `Authorization` do visitante também
  no backend. O forwardAuth do upstream ainda manda ao servidor de auth todos os cabeçalhos do visitante, inclusive
  `Cookie` e `Authorization` (contra a minimização da ADR 0052).
- **JA4T e MSS**: pelo caminho do Mac ao finger-01 o MSS do SYN cai 48 bytes (grampo de MSS no caminho). O JA4T
  medido em `internal/bot/lists/known_clients.json` carrega esse MSS e não bate com Chrome/Firefox reais vindos de
  outro caminho; `known_client` (−20) nunca se aplica pelo probe (as classes saem certas, só o score não).
- **Automação declarada** (PR #254): a 289 negou `known_client` a UA de navegador com marcador de automação; sem isso
  o Selenium com pilha real de Chrome dá 70 − 20 = 50 (`suspect`), e a ADR 0057 pede `bot`.

## Decisão
1. **`X-Fs-Ja4h`**: o traefix envia o JA4H completo da requisição (o mesmo do `ja4h` do registro `type=request`,
   spec 019 RF-04) no cabeçalho `X-Fs-Ja4h` da requisição de auth e do backend, junto com os `X-Fs-*` da RF-06 (o do
   cliente é removido como os outros). No bot, `GET /bot/v1/auth` usa `X-Fs-Ja4h` quando presente e bem formado
   (`^[a-z0-9]{12}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`); ausente ou malformado, cai no JA4H da última requisição
   do ingest na mesma conexão (comportamento atual) e, sem ele, nenhum. Métrica nova
   `bot_auth_ja4h_total{source}` (`header`|`ingest`|`none`). openapi do bot 0.2.0 (aditivo: parâmetro opcional).
2. **forwardAuth do bot no traefix** (spec 019 RF-07): opção nova `fingerSniffer` (bool, padrão `false`) no
   `forwardAuth` marca o middleware que fala com o bot. Só com ela:
   - `apiKey` (string, por middleware, para cada site ter a própria chave, domínios e modo): o traefix põe
     `Authorization: Bearer <apiKey>` na requisição de auth; sem `apiKey`, nenhum `Authorization` vai ao bot;
   - o `Cookie` e o `Authorization` do visitante nunca vão ao bot (o JA4H chega pelo item 1);
   - com `failOpen`, **4xx sem `X-Fs-Verdict` na resposta** (401 `invalid_key`, 403 `forbidden_origin`, 400, 429) é
     falha de configuração ou limite do operador, não decisão sobre o visitante: segue ao backend com
     `X-Fs-Verdict: unavailable`, conta em `fingersniffer_forwardauth_failopen_total{reason="http_4xx"}` e loga no
     máximo uma linha por minuto com o código e o `error` do corpo. Só a resposta com `X-Fs-Verdict` (403 do modo
     `block`) volta ao cliente;
   - carga falha com `apiKey` num `address` `http://` que não seja loopback nem IP privado (chave em claro) e com
     `apiKey` vazia num `address` que não seja loopback nem IP privado (caso (c) sem chave).
   Sem `fingerSniffer`, `failOpen` segue genérico (rede, prazo e 5xx; 4xx volta ao cliente), seguro para um servidor
   de auth qualquer. A chave é uma por middleware; `experimental.fingerSniffer.apiKey` continua só do ingest e
   **não** é herdada (evita mandar a chave a um forwardAuth de terceiro).
3. **Respostas do bot na auth**: o 403 do modo `block` traz sempre `X-Fs-Verdict`, `X-Fs-Score` e `X-Fs-Signals`;
   nenhuma resposta de erro (`400`, `401`, `403 forbidden_origin`, `429`, `5xx`) traz `X-Fs-Verdict`. É o que o
   traefix usa para separar bloqueio de falha (item 2).
4. **JA4T sem MSS no `known_client`** (rules `v1.2`): a coerência com a base própria compara o JA4T sem o campo do
   MSS (janela, opções e escala); o MSS fica com o `tunnel_mss`. O grampo de MSS no caminho não muda a janela
   escolhida pelo cliente, e a base continua guardando o JA4T medido inteiro (formato sem mudança).
   `rules_version` passa a `v1.2`; goldens regravados (o score de Chrome/Firefox por probe passa a ter o −20).
5. **Automação declarada sem `known_client`** (confirma a 289): UA com marcador de `ua_automation` não é coerente
   com o cliente medido da base própria; `known_client` exige UA sem marcador. Selenium/headless com pilha real de
   Chrome ficam `bot` (70).

## Alternativas consideradas
- Bot reconstruir o JA4H dos cabeçalhos do forwardAuth — a ordem já se perdeu no traefik; o JA4H sairia errado.
- Esperar o registro `type=request` no forwardAuth — ele só existe depois da resposta do backend.
- `authRequestHeaders`/middleware `headers` para a chave — não põe valor fixo (o primeiro só filtra) ou vaza a chave
  e sobrescreve o `Authorization` do visitante no backend (o segundo).
- Herdar `experimental.fingerSniffer.apiKey` em todo forwardAuth — vaza a chave a servidores de auth de terceiros e
  impede chave por site.
- Bot responder 5xx em erro de configuração para cair no fail-open de hoje — mascara 401/400 como falha do bot e
  mudaria o contrato da spec 020.
- JA4T com faixa de MSS — a referência medida já vem com o MSS reduzido do caminho do Mac; não há faixa honesta.

## Consequências
- spec 019 RF-04, RF-06–RF-08, RF-10 e RF-12; spec 020 RF-05; spec 018 (pesos, RF-05, RF-12); openapi do bot 0.2.0.
- Tarefa do implementer-bot (292): `X-Fs-Ja4h`, `bot_auth_ja4h_total`, cabeçalhos das respostas da auth, JA4T sem
  MSS e rules `v1.2`. Tarefa de docs (293): `docs/bot.md` com o forwardAuth do bot e a limitação da primeira
  requisição resolvida pelo `X-Fs-Ja4h`. e2e (284) e carga (285) passam a simular `X-Fs-Ja4h` e a chave.
- O fail-open de 4xx sem veredito é do traefix: aqui só se testa o lado do bot (item 3).
