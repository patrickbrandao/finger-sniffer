# finger-sniffer

Servidor espelho de análise de conexões. Recebe conexões em portas capturadas (HTTP/1.x, h2, h3/QUIC, WebSocket,
TLS, TCP cru, DNS autoritativo), registra **como** os pacotes e as conexões chegaram (IP, TCP, TLS, HTTP, DNS,
temporização) e devolve tudo, cru e analisado, por uma API em portas não capturadas (9000 HTTPS, 9001 HTTP).
Serve para qualquer cliente descobrir se o seu tráfego é interceptado e com quais características ele alcança o
servidor, repetindo a mesma sondagem por caminhos diferentes (direto, proxies, túneis) e comparando o que o
espelho viu (ADR 0028). Na fase F8, o serviço `bot` usa essa análise para dar vereditos de bot por API (forwardAuth
do traefik, consulta, probe, feed e webhook) e um traefik modificado em `./traefik/` entrega a visão dos sites
(ADRs 0047–0053).

Roda em `finger-01.tmsoft.com.br` (também `finger-01.badblock.net.br`; Debian 13, VM VMware, 16 vCPU, 32 GB, NIC
`ens192`), em `/finger-sniffer`, como 7 units systemd (rede + NATS + 5 serviços; 8 com o `bot` da F8) agrupadas num target, dentro da
fatia `finger-sniffer.slice` (6 GiB, 8 vCPU; ADR 0039). O host é compartilhado com o traefik e os sites do humano
(Docker): o espelho não mexe no resto do host (ADR 0038). Web em TCP 8080/8443 e UDP 8443 (80/443 são do traefik),
API em `finger-01.badblock.net.br:9000/9001`, zona dos probes: `<id>.finger-west-01.badblock.net.br`.

**O servidor anterior (vps602) foi abandonado e fica intocado**: nunca rode ssh, deploy, carga nem e2e contra ele.
Enquanto a task 224 não sair, os scripts ainda o têm como padrão: rode `make verify-full` só com
`FS_SKIP_LINUX_PRIV=1` e sem `--e2e`, e não rode `make deploy` fora da task 231. O finger-01 só recebe e2e e carga
depois que a task 231 o declarar pronto.

## Fonte da verdade
As especificações em ./specs/ são a fonte da verdade. Toda mudança de comportamento começa pela spec.
Carregue cada spec sob demanda a partir do índice.

@specs/INDEX.md
@specs/PLAN.md
@specs/002-organizacao-do-trabalho.md

## Antes de propor mudanças
Consulte ./specs/decisions/ (comece pelo HISTORY.md). Não reabra uma decisão aceita sem um fato novo. Para mudá-la,
proponha uma nova ADR. Specs, ADRs e contratos só são alterados pelo papel `architect`.

## Fluxo de trabalho
- Pegue tarefas em ./tasks/ com status "aberta" e sem dependências pendentes.
- Marque a tarefa como "em-andamento" e preencha `responsavel` antes de começar.
- Trabalhe no seu próprio git worktree, branch `task/nnn-slug` a partir da `main`.
- Altere apenas os arquivos listados na tarefa e as pastas do seu papel (specs/002).
- Não edite o `CHANGELOG.md`: escreva o resumo da entrega (1–3 linhas) em `changes/task-NNN.md`; o architect junta
  os fragmentos no CHANGELOG no fim de cada fase (specs/002, "Git e PR").
- Ao concluir, atenda a Definition of Done (specs/002), remova o arquivo da tarefa e faça o commit da entrega
  citando o ID, por exemplo `feat(web): parser HTTP/1 (task 012)`.

## Regras de código
- Endpoints, funções, variáveis, chaves JSON, subjects NATS e nomes de arquivos de código em **inglês**.
- Comentários de código **somente em português do Brasil**.
- Go 1.27, `CGO_ENABLED=0`, binários estáticos linux/amd64.
- Dependências permitidas: lista da ADR 0009. Qualquer outra exige pedir ao humano. O fork em `./traefik/` usa o
  `go.mod` do upstream (ADR 0048); dependência nova além dele também vai ao humano.

## Comandos
- Instalar ferramentas: `make tools` (golangci-lint, gofumpt, goose, lefthook, govulncheck)
- Compilar: `make build` (5 binários em ./bin/, linux/amd64; 6 com o `bot` da F8)
- Implantar: `make deploy` (todos) ou `make deploy SVC=web` (um serviço) — sem aprovação, servidor de testes
- Testar (padrão, durante o trabalho e ao concluir cada tarefa): `make verify-quick`
  - testes explícitos: `make verify-quick ARGS="-- ./pkg/detect -run TestTLS"`
- Verificação completa (antes de PR, antes de release, ou quando o humano pedir "rode tudo"): `make verify-full`
  - com ponta a ponta contra o finger-01: `make verify-full ARGS="--e2e"`
- Lint e formatação: `make lint`, `make fmt`
- Logs no servidor: `ssh -p 48022 root@finger-01.tmsoft.com.br journalctl -u 'finger-sniffer-*' -f`

## Testes e verificação (dois níveis)
- **Toda mudança vem com o teste que a cobre.** O nível só decide quanto da suíte roda, nunca se o teste é escrito.
- `verify-quick` (padrão): olha só o que mudou desde `git merge-base HEAD main` (commits, alterações e arquivos
  novos); roda lint nos arquivos alterados, vet/build dos pacotes afetados e dos que dependem deles, os testes dos
  pacotes afetados e os testes de SQLite contra um banco-modelo já migrado (copiado por teste, refeito só quando o
  hash de `database/sqlite/migrations` muda; ligado por `FS_TEST_DB=local`). Não roda build final, e2e nem a
  suíte inteira. Roda todos os passos e sai com código ≠ 0 se algum falhar.
- `verify-full`: lint, vet, todos os testes com `-race`, govulncheck, build linux/amd64, testes Linux
  (AF_PACKET, ethtool) executados no finger-01 por ssh; `--e2e` acrescenta a matriz da spec 017. Para na primeira
  falha. O CI roda sempre o nível completo (sem e2e) em todo PR e na `main`.
- Ao terminar, diga qual nível rodou e o resultado. Subagentes seguem a mesma regra: rápido por padrão, completo só
  quando quem delegou pedir.
- Detalhes: specs/017-verificacao.md.

## Estrutura
- ./specs/: especificações (fonte da verdade)
- ./specs/decisions/: registro de decisões (ADRs) e HISTORY.md
- ./tasks/: fila de trabalho (fora do Git)
- ./changes/: fragmentos do CHANGELOG, um por tarefa (`task-NNN.md`), juntados pelo architect no fim da fase
- ./tmp/: arquivos temporários (fora do Git)
- ./docs/: documentação derivada
- ./cmd/finger-sniffer-<svc>/: binário de cada serviço (capture, web, raw, dns, store; bot na F8)
- ./traefik/: fork do traefik (módulo Go separado, papel `implementer-traefik`, ADR 0048)
- ./internal/<svc>/: código de cada serviço
- ./pkg/: código comum (detecção de protocolo, probe, fingerprints, parsers, envelope de eventos)
- ./htdocs/: site estático (inglês) servido nas portas capturadas
- ./deploy/: units systemd, sysctl, NIC, journald, script de deploy
- ./database/sqlite/: migrations do store (`migrations/`) e do bot (`bot/`, F8)
- ./eventbus/nats/: configuração do NATS e asyncapi.yaml
