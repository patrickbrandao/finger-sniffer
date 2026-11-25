# Plano de implementação

Status: aprovada
Depende de: todas as specs

Regra: uma fase só começa quando a anterior atinge o critério de saída; o architect cria as tarefas da fase seguinte em
`./tasks/` nesse momento. Frentes ‖ rodam em paralelo, cada uma no seu worktree. O registro das fases F1–F8
(objetivos, frentes, saídas, PRs e medidas) está em [PLAN-HISTORICO.md](PLAN-HISTORICO.md), fora do contexto de
todo agente.

## Fase atual
Nenhuma fase aberta: F8 concluída (releases `v0.5.0`–`v0.5.2`). As tarefas da revisão de 2026-11-21
(`fase: revisao-2026-11`) foram entregues, salvo as da tabela abaixo; restam elas e as pendências da F8, quase todas
à espera do humano ou do traefix. A próxima release junta o que entrar na `main`.

## Pendências abertas
Mantida pelo architect (atualizar ao criar, bloquear ou remover tarefa). Detalhe no arquivo da tarefa em `tasks/`,
na spec ou na ADR citada.

| Id | Tipo | Bloqueio / estado | Detalhe |
| --- | --- | --- | --- |
| 221 | tarefa (humano) | bloqueada com o humano | carga contra o teto da tabela de fluxos |
| 256 | tarefa (tester) | só o passo 3, escalado ao humano: host fora do Mac | carga oficial 400/100 sem NAT doméstico |
| 287 | tarefa (docs) | bloqueada até P5 e P6 | página de privacidade |
| 306 | tarefa (infra) | bloqueada até o PT-12 e a escolha do `headerDetail` pelo humano | troca do `traefik-app` |
| 309 | tarefa (tester) | em revisão (PR #412); teto decidido na ADR 0079 | teto do índice com a visão TCP |
| 427 | tarefa (implementer-store) | em andamento, prioridade alta (revert da 424 no PR #413 até ela) | conexão h3 dividida em 2–3 registros depois da 424 |
| 428 | tarefa (infra) | aberta, depois do merge da ADR 0079 | teto padrão do índice do bot em 320 MiB, também no env do finger-01 |
| P4 | humano | sem resposta (`FS_BOT_JA4DB_ENABLE=false`) | termos da ja4db, spec 018 |
| P5, P6 | humano | sem resposta; travam a 287 | base legal (LGPD), controlador e canal do titular, spec 018 |
| `X-Traefix-Deny` | questão | provisório até o humano confirmar e conferir no traefix | 403 mínimo do `block`, ADR 0074 |
| PT-10, PT-11, PT-12, PT-14, PT-16, PT-17, PT-18 | pedido ao traefix | pedidos | spec 019, tabela dos pedidos |
