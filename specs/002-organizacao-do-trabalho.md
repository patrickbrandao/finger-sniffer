# 002 — Organização do trabalho

Status: aprovada
Depende de: 000, 001

## Contexto
Um humano e vários agentes Claude Code trabalham em paralelo. Esta spec define papéis, propriedade de pastas,
Git, fluxo de tarefas, Definition of Done e quando parar para perguntar.

## Papéis

| Papel | Responsabilidade | Pode alterar | Sub-agente |
| --- | --- | --- | --- |
| architect | guardião das specs, ADRs e contratos; aprova migrations; resolve conflitos de contrato; cria tarefas da próxima fase | `specs/**`, `cmd/finger-sniffer-store/openapi.yaml`, `eventbus/nats/asyncapi.yaml`, `CHANGELOG.md`, `AGENTS.md` | .claude/agents/architect.md |
| implementer-capture | serviço capture | `cmd/finger-sniffer-capture/**` (exceto contratos), `internal/capture/**` | .claude/agents/implementer-capture.md |
| implementer-web | serviço web; dono de `pkg/` de detecção, probe, parsers, fingerprints e certificados (`pkg/certs`, usado também por raw e store) | `cmd/finger-sniffer-web/**`, `internal/web/**`, `pkg/detect/**`, `pkg/probe/**`, `pkg/tlsparse/**`, `pkg/h1/**`, `pkg/h2passive/**`, `pkg/quicparse/**`, `pkg/fingerprint/**`, `pkg/iana/**`, `pkg/certs/**` | .claude/agents/implementer-web.md |
| implementer-raw | serviço raw | `cmd/finger-sniffer-raw/**`, `internal/raw/**` | .claude/agents/implementer-raw.md |
| implementer-dns | serviço dns | `cmd/finger-sniffer-dns/**`, `internal/dns/**` | .claude/agents/implementer-dns.md |
| implementer-store | serviço store, API, análise IP/TCP; dono de `pkg/` de base de serviço e envelope; escreve migrations | `cmd/finger-sniffer-store/**` (exceto openapi.yaml), `internal/store/**`, `pkg/service/**`, `pkg/event/**`, `database/sqlite/migrations/**` (com aprovação do architect) | .claude/agents/implementer-store.md |
| tester | e2e, matriz da spec 017, golden pcaps, fuzzing longo, carga | `test/**`, `**/testdata/**`, `**/*_test.go` de qualquer pacote (somente testes) | .claude/agents/tester.md |
| reviewer | revisa PRs contra spec, ADRs e DoD; não altera código | nada (só comenta) | .claude/agents/reviewer.md |
| infra | systemd, NIC/sysctl, NATS, deploy, Makefile, verify, CI, lint | `deploy/**`, `scripts/**`, `Makefile`, `.github/**`, `.golangci.yml`, `lefthook.yml`, `eventbus/nats/nats.conf`, `.env.example`, `.gitignore`, `go.mod`, `go.sum`, `LICENSE`, `NOTICE` | .claude/agents/infra.md |
| docs | documentação derivada e site estático | `docs/**`, `htdocs/**`, `README.md` | .claude/agents/docs.md |

Regras de propriedade:
- **specs/, specs/decisions/, openapi.yaml e asyncapi.yaml: só o architect altera.** Quem precisar de mudança abre
  uma tarefa "mudança de contrato" e espera o architect aplicar.
- **Migrations**: implementer-store escreve; o architect aprova no PR antes do merge.
- `go.mod`/`go.sum`: infra; outro papel que precise de dependência da lista da ADR 0009 pede na tarefa; fora da
  lista, escala ao humano.
- `changes/task-NNN.md`: cada papel escreve o fragmento da sua tarefa (ver "Git e PR"); o architect os junta.
- `.gitattributes`: infra.
- Arquivos fora da tabela: pedir ao architect.

## Git e PR
- Repositório GitHub privado `patrickbrandao/finger-sniffer`; branch principal `main`; modelo trunk-based.
- Cada agente trabalha em seu **próprio git worktree**, branch curto `task/nnn-slug` a partir da `main`.
- Conventional Commits citando a tarefa: `feat(web): parser HTTP/1 (task 012)`, `fix(store): ... (task 031)`.
  Escopos: `capture`, `web`, `raw`, `dns`, `store`, `pkg`, `infra`, `docs`, `specs`, `test`.
- PR com `verify-quick` verde informado na descrição, `verify-full` verde no CI e revisão do reviewer;
  **squash merge**.
- Conflito: quem chegou depois faz rebase na `main`. Conflito em contrato ou spec: escala ao architect.
- **CHANGELOG por fragmentos**: o GitHub ignora `merge=union` e marca como conflitante todo PR que mexe no
  `CHANGELOG.md` depois de outro merge. Por isso a entrega **não edita o `CHANGELOG.md`**: escreve o resumo em
  `changes/task-NNN.md` (um arquivo por tarefa, sem conflito). O architect junta os fragmentos na seção certa do
  `CHANGELOG.md` e apaga os arquivos no fim de cada fase (no máximo no PR que cria as tarefas da fase seguinte) e
  antes de cada release.
- Deploy concorrente: `make deploy` pega uma trava remota (`flock /run/finger-sniffer/deploy.lock`); após cada
  merge a `main` é reimplantada.

## Fluxo das tarefas (`./tasks/`, fora do Git)
1. Problemas encontrados por inspeção viram uma nova tarefa (próximo `nnn` livre, template em AGENTS/INDEX).
2. Antes de começar: `status: em-andamento` e `responsavel: <papel>`. Nunca pegar tarefa já `em-andamento`.
3. Ao concluir: remover o arquivo da tarefa e fazer o commit da entrega citando o ID.
4. Tarefa descartada também é removida; se o descarte for uma decisão, registrar em ADR.
5. Tarefas das fases seguintes são criadas pelo architect quando a fase anterior atinge o critério de saída.

## Definition of Done
Uma tarefa está concluída quando todos os itens forem verdadeiros:
- o código está implementado;
- os testes do nível acordado foram escritos e estão passando (toda mudança vem com o teste que a cobre);
- `make verify-quick` verde, com o nível e o resultado informados no PR;
- `make verify-full` verde (CI) antes do merge;
- lint, formatter e checagem de tipos limpos;
- a spec e os contratos estão atualizados, se mudaram (pelo architect);
- a documentação em `./docs/` está atualizada, quando aplicável;
- quando muda comportamento em runtime: `make deploy` na vps602 e smoke test ok;
- o resumo compactado da entrega (1–3 linhas, no estilo do `CHANGELOG.md`) está em `changes/task-NNN.md`;
- o arquivo da tarefa foi removido.

## Escalonamento para o humano
Pare e pergunte quando:
1. a tarefa conflita com uma spec ou ADR aceita;
2. é preciso mudar um contrato (API, eventos, schema) — primeiro passa pelo architect, que escala se mudar
   comportamento acordado;
3. é preciso uma dependência fora da lista da ADR 0009;
4. a ação tem efeito externo fora da vps602: zona DNS no udns.com.br, configurações do GitHub, mais de
   3 emissões de certificado Let's Encrypt de produção por semana;
5. uma meta de RNF (spec 000) parece inalcançável — isso aciona a revisão das ADRs 0004 e 0005.

**Na vps602, tudo pode ser feito sem aprovação** (instalar, reiniciar, mudar sysctl, apagar dados).

## Critérios de aceite
- [ ] Cada papel tem um arquivo em `.claude/agents/`.
- [ ] Toda pasta do repositório tem um dono nesta tabela.

## Decisões relacionadas
- specs/decisions/0014-organizacao-agentes.md
- specs/decisions/0013-verificacao-dois-niveis.md
