# Plano de implementação

Status: aprovada
Depende de: todas as specs

Regra: uma fase só começa quando a anterior atinge o critério de saída; o architect cria as tarefas da fase seguinte em
`./tasks/` nesse momento. Frentes ‖ rodam em paralelo, cada uma no seu worktree. O registro das fases F1–F8
(objetivos, frentes, saídas, PRs e medidas) está em [PLAN-HISTORICO.md](PLAN-HISTORICO.md), fora do contexto de
todo agente.

## Fase atual
Nenhuma fase aberta: F8 concluída (releases `v0.5.0`–`v0.5.2`); trabalho por tarefas avulsas da revisão de
2026-11-21 (`fase: revisao-2026-11`) e pendências da F8. A próxima release junta o que entrar na `main`.

## Pendências abertas
Mantida pelo architect (atualizar ao criar, bloquear ou remover tarefa). Detalhe no arquivo da tarefa em `tasks/`,
na spec ou na ADR citada.

| Id | Tipo | Bloqueio / estado | Detalhe |
| --- | --- | --- | --- |
| 221 | tarefa (humano) | bloqueada com o humano | carga contra o teto da tabela de fluxos |
| 287 | tarefa (docs) | bloqueada até P5 e P6 | página de privacidade |
| 306 | tarefa (infra) | bloqueada até o PT-12 e a escolha do `headerDetail` pelo humano | troca do `traefik-app` |
| 256, 296, 308, 309, 314, 315, 406 | tarefa (tester, bot) | abertas, baixa prioridade | gerador fora do Mac, probe h3, fuzz e teto do índice com o traefix, TTL/relay agregados, feed sem cabeçalhos, `latest` reproduzível |
| 299, 400, 401, 403, 404, 409, 413 | tarefa (implementer-bot) | abertas | `forget`/webhook e IP no arquivo, flush final, JA4H, lista que encolhe, 404 do feed, cota 9002/9003 |
| 342, 379–381, 384, 416 | tarefa (implementer-store) | abertas | revisão de 2026-11-21 |
| 345, 346–351, 376, 377, 385, 386 | tarefa (raw, web, capture, dns) | abertas | revisão de 2026-11-21 |
| 341, 378, 383, 387, 407 | tarefa (architect primeiro) | abertas | decisão ou contrato antes do código |
| 391–393, 395 | tarefa (docs, infra) | em andamento | CSP, termos da ADR 0053, deploy delta, toolchain fixa |
| P4 | humano | sem resposta (`FS_BOT_JA4DB_ENABLE=false`) | termos da ja4db, spec 018 |
| P5, P6 | humano | sem resposta; travam a 287 | base legal (LGPD), controlador e canal do titular, spec 018 |
| `X-Traefix-Deny` | questão | provisório até o humano confirmar e conferir no traefix | 403 mínimo do `block`, ADR 0074 |
| PT-10, PT-11, PT-12, PT-14, PT-16, PT-17, PT-18 | pedido ao traefix | pedidos | spec 019, tabela dos pedidos |
