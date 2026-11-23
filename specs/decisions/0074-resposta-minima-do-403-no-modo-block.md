# 0074 — Resposta mínima do 403 do forwardAuth no modo `block`

Status: aceita (item 3, marcador `X-Traefix-Deny` para o traefix, provisório até o humano confirmar e até conferir no
traefix `latest`; substitui o trecho do 403 da ADR 0051 item 1)
Data: 2026-11-23

## Contexto
A ADR 0051 item 1 fez o 403 do modo `block` levar o mesmo corpo `Verdict` do 200, e a ADR 0063 item 1 os mesmos
cabeçalhos (`X-Traefix-Verdict`, `-Score`, `-Signals` e os `X-Fs-*` obsoletos). A questão de manter isso ficou aberta
ao humano na saída da F8 (`specs/PLAN.md`). A task 367 (revisão de 2026-11-21) trouxe o fato novo: numa resposta fora
de 2xx o traefik devolve ao visitante a resposta da auth inteira, cabeçalhos inclusive (`authResponseHeaders` só
filtra o que vai ao backend no 2xx). O robô bloqueado recebe o score e os ids dos sinais que o pegaram, que são o guia
para fugir do veredito.

Decisão do humano em 2026-11-23 (task 367, opção b): **corpo mínimo `{"error":"forbidden"}` e 403 sem os cabeçalhos de
veredito**; o 200 continua com eles.

Fato que limita a opção b com a configuração atual: o perfil da spec 019 RF-04 usa
`failOpen.denyRequiresResponseHeader: X-Traefix-Verdict`. O traefix só devolve um 4xx ao visitante quando ele traz esse
cabeçalho; sem ele, trata a resposta como falha e segue ao backend com `X-Traefix-Verdict: unavailable` (é o
fail-open de 4xx da ADR 0058 item 3, que separa o bloqueio de uma chave inválida ou de um 429). Um 403 sem
`X-Traefix-Verdict` com esse perfil **não bloqueia nada**.

## Decisão
1. **Corpo**: o 403 do modo `block` (chave `--mode block`, `class=bot`) tem o corpo `Error` `{"error":"forbidden"}`,
   sem `detail`. Código novo `forbidden` no enum de `Error`.
2. **Cabeçalhos**: o 403 não leva `X-Traefix-Verdict`, `X-Traefix-Score`, `X-Traefix-Signals`, `X-Fs-Verdict`,
   `X-Fs-Score` nem `X-Fs-Signals`. O 200 fica como está. O veredito do 403 continua no feed, no webhook e na consulta
   (`/bot/v1/verdict/conn/{fs_conn_id}`), e em `bot_verdicts_total`.
3. **Marcador do bloqueio para o traefix** (provisório, ver Status): o 403 do `block` leva só `X-Traefix-Deny: 1`, sem
   classe, score nem sinais; nenhuma outra resposta do bot leva `X-Traefix-Deny`. O perfil da spec 019 RF-04 passa a
   `failOpen.denyRequiresResponseHeader: X-Traefix-Deny`, e o fail-open de 4xx do traefix fica igual (4xx sem o
   marcador segue ao backend com `unavailable`). O visitante vê `X-Traefix-Deny: 1`, que não diz mais que o próprio
   403. Ainda não foi conferido no traefix `latest` que `denyRequiresResponseHeader` aceita outro nome: a task 367
   confere num container de teste, como na task 273, antes de fechar.
4. **Ordem de troca**: nenhum site usa `block` hoje (ligá-lo é ação do humano, ADR 0048). Com o bot novo e o perfil
   antigo, o `block` vira fail-open (nunca bloqueia demais); com o perfil novo e o bot antigo, também. O humano troca o
   perfil para `X-Traefix-Deny` antes de ligar `block` em qualquer site.
5. **Contrato**: openapi do bot **0.7.0**. A resposta 403 do `/bot/v1/auth` deixa de ter corpo `Verdict` e cabeçalhos
   de veredito: mudança **não aditiva** em `/bot/v1`, aceita como exceção à regra da ADR 0001 ("`/bot/v1` só
   aditivo"), porque o 403 é lido pelo navegador do visitante, não por um cliente da API, e a decisão é do humano.
   `forbidden` no enum e `X-Traefix-Deny` são aditivos. A ADR 0051 item 1 fica substituída só no trecho do 403.

## Alternativas consideradas
- **(a) Manter corpo e cabeçalhos**: entrega ao robô o guia de evasão. O humano recusou.
- **(c) Corpo mínimo com só `X-Traefix-Verdict: bot`**: funciona com o perfil atual sem troca, mas a decisão do
  humano tira todos os cabeçalhos de veredito; fica como recuo se o traefix não aceitar outro nome no item 3.
- **(b) ao pé da letra, sem marcador nenhum**: desliga o `block` (fail-open em todo 403) com o perfil atual.
- **Pedido `PT-nn` ao traefix para tirar o marcador antes de responder ao visitante**: esconderia até o marcador, mas
  depende de uma entrega do traefix; `X-Traefix-Deny` não revela nada e só depende de configuração.

## Consequências
- Spec 020 RF-05, RF-07 e critérios; spec 019 RF-04 (perfil), regras e critérios de aceite do 403; openapi 0.7.0;
  `specs/PLAN.md` (questão da F8 respondida).
- Task 367 para o implementer-bot, depois da 371 (toca `api.go`): 403 com corpo mínimo, sem cabeçalhos de veredito,
  com `X-Traefix-Deny: 1`; testes do 403 e do 200; `docs/bot.md` (perfil com `X-Traefix-Deny` e o modo `block`) e as
  frases correspondentes em `docs/docs_test.go`; conferência no traefix num container de teste.
- **Aviso ao humano**: o perfil do traefix nos sites que forem usar `block` precisa trocar o
  `denyRequiresResponseHeader` para `X-Traefix-Deny`; sem isso o `block` não bloqueia. Se o traefix não aceitar o
  nome, o recuo é a opção (c), por decisão dele.
