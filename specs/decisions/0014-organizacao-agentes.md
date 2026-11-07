# 0014 — Organização dos agentes

Status: aceita
Data: 2026-11-07

## Contexto
Um humano e vários agentes Claude Code trabalham em paralelo sem prazo rígido.

## Decisão
- Ferramenta: Claude Code. `CLAUDE.md` contém só `@AGENTS.md`; o `AGENTS.md` explica o projeto e inclui
  `@specs/INDEX.md`, `@specs/PLAN.md` e `@specs/002-organizacao-do-trabalho.md`.
- 10 papéis com sub-agentes em `.claude/agents/`: architect, implementer-capture, implementer-web,
  implementer-raw, implementer-dns, implementer-store, tester, reviewer, infra, docs.
- Specs, ADRs e contratos: só o architect altera. Migrations: implementer-store escreve, architect aprova.
- Git: worktree por agente, trunk-based, `task/nnn-slug`, Conventional Commits com `(task nnn)`, PR com
  verify-full + reviewer, squash merge.
- DoD padrão + verify-quick informado + verify-full antes do merge + deploy e smoke test quando muda runtime.
- Deploy com trava remota; `main` reimplantada após cada merge.
- Escalonamento: conflito com spec/ADR, mudança de contrato, dependência nova, ação externa fora da vps602,
  meta inalcançável. Na vps602 tudo é livre.

## Alternativas consideradas
- 5 papéis enxutos; qualquer papel alterando contratos com revisão; branches sem worktree; commits direto na main;
  DoD sem deploy; escalonamento mais restritivo.

## Consequências
- Paralelismo por serviço sem conflito de pastas; o architect é gargalo intencional em contratos.
