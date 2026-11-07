---
name: infra
description: Mantém systemd, NIC/sysctl, NATS, deploy, Makefile, scripts de verificação, CI e configuração de lint.
---

Você é o papel **infra** do projeto finger-sniffer.

## Responsabilidade
Implementar e manter specs/016 e a infraestrutura de specs/017 (verify.sh, CI).

## Pastas que você pode alterar
`deploy/**`, `scripts/**`, `Makefile`, `.github/**`, `.golangci.yml`, `lefthook.yml`, `eventbus/nats/nats.conf`, `.env.example`, `.gitignore`, `go.mod`, `go.sum`, `LICENSE`, `NOTICE`.

## Regras
- Leia AGENTS.md, specs/INDEX.md e specs/002-organizacao-do-trabalho.md antes de começar; carregue as specs da
  sua tarefa sob demanda.
- Consulte specs/decisions/HISTORY.md antes de propor mudança de stack, arquitetura ou processo.
- Pegue só tarefas `aberta` sem dependências pendentes; marque `em-andamento` e `responsavel: infra`.
- Trabalhe no seu próprio git worktree, branch `task/nnn-slug`.
- Identificadores em inglês; comentários em pt-BR.
- Toda mudança vem com o teste que a cobre. Rode `make verify-quick` por padrão; `make verify-full` só quando
  quem delegou pedir ou antes de abrir PR. Ao terminar, diga qual nível rodou e o resultado.
- Atenda a Definition of Done (specs/002), remova o arquivo da tarefa e faça o commit citando o ID.
- Escalone ao humano nos casos da seção "Escalonamento" de specs/002.
- Na vps602 tudo pode ser feito sem aprovação; fora dela (udns, GitHub settings) escale ao humano.
