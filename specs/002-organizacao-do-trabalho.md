# 002 — Organização do trabalho

Status: aprovada
Depende de: 000, 001

## Contexto
Um humano e vários agentes Claude Code trabalham em paralelo. Esta spec define papéis, propriedade de pastas,
Git, fluxo de tarefas, Definition of Done e quando parar para perguntar.

## Papéis

| Papel | Responsabilidade | Pode alterar | Sub-agente |
| --- | --- | --- | --- |
| architect | guardião das specs, ADRs e contratos; aprova migrations; resolve conflitos de contrato; cria tarefas da próxima fase | `specs/**`, `cmd/finger-sniffer-store/openapi.yaml`, `cmd/finger-sniffer-bot/openapi.yaml`, `cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json`, `eventbus/nats/asyncapi.yaml`, `CHANGELOG.md`, `AGENTS.md`, `CLAUDE.md`, `.claude/agents/**`, `tasks/**` | .claude/agents/architect.md |
| implementer-capture | serviço capture | `cmd/finger-sniffer-capture/**` (exceto contratos), `internal/capture/**` | .claude/agents/implementer-capture.md |
| implementer-web | serviço web; dono de `pkg/` de detecção, probe, parsers, fingerprints e certificados (`pkg/certs`, usado também por raw e store) | `cmd/finger-sniffer-web/**`, `internal/web/**`, `pkg/detect/**`, `pkg/probe/**`, `pkg/tlsparse/**`, `pkg/h1/**`, `pkg/h2passive/**`, `pkg/quicparse/**`, `pkg/fingerprint/**`, `pkg/iana/**`, `pkg/certs/**` | .claude/agents/implementer-web.md |
| implementer-raw | serviço raw | `cmd/finger-sniffer-raw/**`, `internal/raw/**` | .claude/agents/implementer-raw.md |
| implementer-dns | serviço dns | `cmd/finger-sniffer-dns/**`, `internal/dns/**` | .claude/agents/implementer-dns.md |
| implementer-store | serviço store, API, análise IP/TCP; dono de `pkg/` de base de serviço e envelope; escreve migrations | `cmd/finger-sniffer-store/**` (exceto openapi.yaml), `internal/store/**`, `pkg/service/**`, `pkg/event/**`, `database/sqlite/migrations/**` (com aprovação do architect) | .claude/agents/implementer-store.md |
| implementer-bot | serviço bot (F8): veredito, sinais, listas, agregados, chaves, API de vereditos, feed e webhook; escreve as migrations do banco do bot | `cmd/finger-sniffer-bot/**` (exceto openapi.yaml e traefix-fingerprint-v1.schema.json), `internal/bot/**` (exceto `internal/bot/lists/known_clients.json`), `database/sqlite/bot/**` (com aprovação do architect) | .claude/agents/implementer-bot.md |
| tester | e2e, matriz da spec 017, golden pcaps, fuzzing longo, carga; base própria de fingerprints medidos | `test/**`, `**/testdata/**`, `**/*_test.go` de qualquer pacote (somente testes), `internal/bot/lists/known_clients.json` | .claude/agents/tester.md |
| reviewer | revisa PRs contra spec, ADRs e DoD; não altera código | nada (só comenta) | .claude/agents/reviewer.md |
| infra | systemd, NIC/sysctl, NATS, deploy, Makefile, verify, CI, lint, versão do build | `deploy/**`, `scripts/**`, `Makefile`, `.github/**`, `.golangci.yml`, `lefthook.yml`, `redocly.yaml`, `eventbus/nats/nats.conf`, `.env.example`, `.gitignore`, `go.mod`, `go.sum`, `LICENSE`, `NOTICE`, `internal/version/**` | .claude/agents/infra.md |
| docs | documentação derivada e site estático | `docs/**`, `htdocs/**`, `README.md` | .claude/agents/docs.md |

Regras de propriedade:
- **specs/, specs/decisions/, os dois openapi.yaml (store e bot), asyncapi.yaml e a cópia do esquema do traefix
  (ADR 0063, sem edição): só o architect altera.** Quem precisar de mudança abre
  uma tarefa "mudança de contrato" e espera o architect aplicar.
- **Migrations**: implementer-store (`database/sqlite/migrations/`) e implementer-bot (`database/sqlite/bot/`)
  escrevem; o architect aprova no PR antes do merge.
- **traefix** (traefik modificado): projeto externo do humano (ADR 0054), fora deste repositório e sem papel aqui;
  a interface é a spec 019 e o openapi do bot (architect), mudada só de forma aditiva e avisada ao humano.
- `go.mod`/`go.sum`: infra; outro papel que precise de dependência da lista da ADR 0009 pede na tarefa; fora da
  lista, escala ao humano.
- `changes/task-NNN.md`: cada papel escreve o fragmento da sua tarefa (ver "Git e PR"); o architect os junta no
  `CHANGELOG.md` e remove os arquivos.
- **Delegação**: um papel só altera arquivo de outro (contrato, spec, `pkg/` alheio) quando a tarefa, escrita pelo
  architect, lista o arquivo em `arquivos` e traz o bloco ou a decisão exata; o PR cita a tarefa (ADR 0023). Sem
  isso, vale a regra geral acima.
- Arquivos fora da tabela: pedir ao architect.

## Git e PR
- Repositório GitHub privado `patrickbrandao/finger-sniffer`; branch principal `main`; modelo trunk-based.
- Cada agente trabalha em seu **próprio git worktree**, branch curto `task/nnn-slug` a partir da `main`.
- Conventional Commits citando a tarefa: `feat(web): parser HTTP/1 (task 012)`, `fix(store): ... (task 031)`.
  Escopos: `capture`, `web`, `raw`, `dns`, `store`, `pkg`, `infra`, `docs`, `specs`, `test`.
- PR com `verify-quick` verde informado na descrição, `verify-full` verde no CI e revisão do reviewer
  registrada no próprio PR (`gh pr review --comment` ou comentário com o veredito); **squash merge**.
- **Modo autônomo** (o humano autoriza trabalho sem supervisão com merge a cada etapa): o PR é mergeado com o CI
  verde, sem esperar o reviewer; a revisão passa a ser a auditoria do conjunto pelo reviewer antes da release e
  a revisão do PR de release (ADR 0023).
- Conflito: quem chegou depois faz rebase na `main`. Conflito em contrato ou spec: escala ao architect.
- **CI depois de rebase** (ADR 0059): rebase sem conflito, em que o que entrou na `main` desde o commit testado não
  toca os mesmos arquivos nem pacotes dependentes (nos dois sentidos) dos do PR, pode mergear com o CI verde do
  commit anterior ao rebase (todos os checks `pass`, citado no PR). Conflito, arquivo ou pacote dependente em comum,
  contrato, migration, `go.mod`/`go.sum`, `Makefile`, `scripts/` ou `.github/` em qualquer dos lados: o CI roda de
  novo e o merge espera todos os checks `pass`.
- **Paralelismo por pacote** (ADR 0059): no máximo 3 tarefas em paralelo no mesmo pacote ou serviço
  (`internal/<svc>`, `pkg/<pacote>`); tarefas que tocam o mesmo arquivo compartilhado (ex.: `internal/bot/server.go`,
  `api.go`) vão em série, declaradas em `depende-de` por quem cria a onda.
- **CHANGELOG por fragmentos**: o GitHub ignora `merge=union` e marca como conflitante todo PR que mexe no
  `CHANGELOG.md` depois de outro merge. Por isso a entrega **não edita o `CHANGELOG.md`**: escreve o resumo em
  `changes/task-NNN.md` (um arquivo por tarefa, sem conflito). O architect junta os fragmentos na seção certa do
  `CHANGELOG.md` e apaga os arquivos no fim de cada fase (no máximo no PR que cria as tarefas da fase seguinte) e
  antes de cada release.
- Deploy concorrente: `make deploy` pega uma trava remota (`flock /run/finger-sniffer/deploy.lock`).
- **Deploy por onda** (ADR 0059): em modo autônomo, o `make deploy` completo e o smoke (health com os serviços `ok`
  e `versions_match`) são feitos uma vez por onda, a partir da `main` com os merges da onda, pelo orquestrador ou pela
  última tarefa da onda; a tarefa que precisa medir algo no servidor (e2e, carga, smoke de comportamento novo)
  implanta antes de medir. Fora do modo autônomo, a `main` é reimplantada após cada merge.

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
- quando muda comportamento em runtime: `make deploy` no finger-01 e smoke test ok (em modo autônomo, uma vez por
  onda; ADR 0059);
- o resumo compactado da entrega (1–3 linhas, no estilo do `CHANGELOG.md`) está em `changes/task-NNN.md`;
- o arquivo da tarefa foi removido.

## Escalonamento para o humano
Pare e pergunte quando:
1. a tarefa conflita com uma spec ou ADR aceita;
2. é preciso mudar um contrato (API, eventos, schema) — primeiro passa pelo architect, que escala se mudar
   comportamento acordado;
3. é preciso uma dependência fora da lista da ADR 0009;
4. a ação tem efeito fora do espelho no finger-01: zona DNS no udns.com.br, configurações do GitHub, o resto do
   host (containers, Docker, sysctls e THP do host, snmpd, opencode; o script do traefik só nos termos da ADR 0038
   item 6), mais de 3 emissões de certificado Let's Encrypt de produção por semana, publicar imagem no Docker Hub,
   trocar a imagem do `traefik-app` ou ligar o forwardAuth nos sites do humano (ADR 0054 item 9);
5. uma meta de RNF (spec 000) parece inalcançável — isso aciona a revisão das ADRs 0004 e 0005.

**No finger-01, tudo o que é do espelho pode ser feito sem aprovação** (`/finger-sniffer`, units
`finger-sniffer-*`, o nosso arquivo de sysctl: instalar, reiniciar, apagar dados; ADR 0038). O servidor anterior
não recebe nenhuma ação.

## Critérios de aceite
- [ ] Cada papel tem um arquivo em `.claude/agents/`.
- [ ] Toda pasta do repositório tem um dono nesta tabela.

## Decisões relacionadas
- specs/decisions/0014-organizacao-agentes.md
- specs/decisions/0013-verificacao-dois-niveis.md
- specs/decisions/0059-deploy-por-onda-ci-reaproveitado-e-paralelismo.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
