# 0059 — Deploy por onda, CI reaproveitado depois de rebase limpo e paralelismo por pacote

Status: aceita
Data: 2026-11-16

## Contexto
Decisão do humano (2026-11-16) para reduzir o tempo das tarefas em modo autônomo. Fatos da F8: cada tarefa fazia
`make deploy` completo e smoke no finger-01 (deploys concorrentes esperando a trava remota); cada rebase sem conflito
disparava o CI inteiro de novo (~300 s só dos testes do store com `-race`); tarefas paralelas no mesmo serviço
(ex.: `internal/bot/server.go`) entravam em conflito e repetiam rebase e CI.

## Decisão
1. **Deploy por onda**: em modo autônomo, o `make deploy` completo no finger-01 e o smoke (health com os serviços `ok`
   e `versions_match`) são feitos uma vez por onda, a partir da `main` com todos os merges da onda, pelo orquestrador
   ou pela última tarefa da onda. A tarefa que precisa medir algo no servidor (e2e, carga, smoke de um comportamento
   novo) ainda implanta antes de medir. O item "quando muda comportamento em runtime: `make deploy` e smoke" da
   Definition of Done passa a valer por onda.
2. **CI reaproveitado**: depois de um rebase na `main` **sem conflito**, em que o que entrou na `main` desde o commit
   testado não toca os mesmos arquivos nem pacotes que dependem dos pacotes do PR (ou dos quais o PR depende), o
   merge pode usar o CI verde do commit anterior ao rebase (todos os checks `pass`, citado na descrição do PR). Com
   conflito, arquivo em comum ou pacote dependente em comum, o CI roda de novo e o merge espera todos os checks `pass`.
   Contratos (`openapi.yaml`, `asyncapi.yaml`), migrations, `go.mod`/`go.sum`, `Makefile`, `scripts/` e `.github/`
   contam como comuns a tudo.
3. **Paralelismo por pacote**: no máximo 3 tarefas em paralelo no mesmo pacote ou serviço (`internal/<svc>`,
   `pkg/<pacote>`); tarefas que tocam o mesmo arquivo compartilhado (ex.: `internal/bot/server.go`, `api.go`) vão em
   série. Quem cria as tarefas da onda (architect ou orquestrador) declara a ordem em `depende-de`.
4. **CI mais rápido**: tarefa de infra (294) para reduzir o tempo dos testes do store com `-race` no CI (lotes
   paralelos como o fuzz da task 253, ou outro meio), mantendo a mesma cobertura.

## Alternativas consideradas
- Deploy por tarefa (como antes) — serializa as tarefas na trava remota e repete smoke sem ganho entre merges.
- Pular o CI depois de qualquer rebase — perde a interação entre mudanças de pacotes dependentes.
- Fila de merge do GitHub — mudança de configuração do GitHub (escalonamento 4 da spec 002).

## Consequências
- spec 002 ("Git e PR", Definition of Done), spec 017 (RF-11) e `AGENTS.md`.
- A `main` pode ficar à frente do que roda no finger-01 durante a onda; o health `versions_match` só é exigido no
  smoke da onda.
