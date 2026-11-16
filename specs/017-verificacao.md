# 017 — Verificação e testes

Status: aprovada
Depende de: 002, 016

## Contexto
Dois níveis de verificação, criados junto com a estrutura inicial; e a matriz de testes que prova o MVP.

## Requisitos
### Implementação
- RF-01: `scripts/verify.sh` com modos `quick` e `full`, exposto como `make verify-quick` e `make verify-full`
  (`ARGS="..."` repassa argumentos). No fim mostra um resumo com ✓/✗/pulado e o tempo de cada passo.

### Nível rápido (padrão)
- RF-02: base = `git merge-base HEAD main`; considera commits, alterações e arquivos novos não rastreados.
- RF-03: passos: `golangci-lint run` só nos arquivos alterados; `go vet` + build (sem gerar binário) dos pacotes
  afetados e dos que dependem deles (`go list -deps`/reverse deps); `go test` dos pacotes afetados (arquivo de
  teste alterado ou `x.go` → `x_test.go` no mesmo pacote); testes de SQLite alterados.
- RF-04: não roda build final, e2e, `-race` nem a suíte inteira. Exceção: quando `Makefile` ou
  `scripts/release*`/`scripts/repro-check.sh` mudam, roda o `release-test` (build dos 5 binários e do pacote de
  release, ~10 s), único teste desses arquivos (ADR 0023).
- RF-05: aceita testes explícitos depois de `--`: `make verify-quick ARGS="-- ./pkg/h1 -run TestChunked"`.
- RF-06: SQLite local: banco-modelo `tmp/testdb/template.sqlite` migrado pelo goose, refeito só quando o hash
  (sha256) de `database/sqlite/migrations/` muda (hash guardado em `PRAGMA user_version`/tabela `meta`); cada teste
  copia o modelo para um arquivo temporário (< 1 s). Ligado por `FS_TEST_DB=local` no setup comum de testes.
- RF-07: roda todos os passos; código de saída ≠ 0 se algum falhar.

### Nível completo (sob pedido, antes de PR e de release; CI sempre)
- RF-08: `golangci-lint run ./...`, `gofumpt -l`, `go vet ./...`, validação dos contratos (`openapi.yaml` com
  Redocly CLI e `asyncapi.yaml` com AsyncAPI CLI, com as dependências travadas por `package-lock.json` e instaladas com
  `npm ci --ignore-scripts`; erros falham, avisos não; os
  `examples` de cada mensagem do asyncapi validados contra o payload por um script próprio (JSON Schema 2020-12),
  porque o AsyncAPI CLI só confere exemplos de documentos 2.x — no quick, só quando um dos dois contratos ou um
  exemplo referenciado mudou), `go test -race -cover ./...` (banco isolado:
  arquivo SQLite temporário novo migrado do zero), metas de cobertura (≥ 80% em `pkg/{detect,probe,tlsparse,h1,
  h2passive,quicparse,fingerprint}`, ≥ 60% total sem contar `cmd/`, cujas funções `main` o e2e cobre), fuzz curto (10 s por alvo; 60 s por alvo antes de cada release com `FS_FUZZ_TIME=60s`, registrado no PR de
  release), `govulncheck ./...`,
  build linux/amd64 dos 5 binários, testes com tag `linux_priv` (AF_PACKET, ethtool) executados no finger-01 por ssh
  (`FS_VPS_SSH`, padrão `root@finger-01.tmsoft.com.br`, porta 48022; ADR 0038).
- RF-09: `--e2e` acrescenta a matriz abaixo contra o finger-01 (exige deploy da versão em teste).
- RF-10: para na primeira falha.
- RF-11: CI (GitHub Actions) roda `verify-full` sem `--e2e` e sem `linux_priv` em todo PR e na `main`. Toda action
  dos workflows é fixada pelo SHA de 40 caracteres do commit da release, com a tag em comentário (nunca tag nem
  branch, que são mutáveis).

### Níveis de teste
- RF-12: unidade com golden files: pcaps da FoxIO (portados do `ja4pcap`) e capturas próprias de curl, Go, Chrome e
  Firefox em `pkg/**/testdata/`; integração com NATS embutido (nats-server como biblioteca só nos testes);
  contrato: respostas da API validadas contra o openapi.yaml e eventos contra o asyncapi.yaml (cada produtor grava
  exemplos golden dos seus eventos em `internal/<svc>/testdata/`, regravados com `-update`, e o asyncapi os
  referencia em `examples`); e2e: matriz.

### Matriz e2e (caminho direto, a partir de uma máquina cliente)
Caminho direto × caso (ADR 0028):
1. HTTP/1.1 simples, cabeçalhos com caixa e ordem incomuns, campos duplicados, valor com espaços.
2. HTTP/1.0 sem e com `Connection: keep-alive`.
3. 5 requisições numa conexão, depois com `Connection: close`, depois pipelining.
4. Corpo com Content-Length, chunked com extensões e trailers, `Expect: 100-continue`.
5. Respostas provocadas: 1xx, close-delimited, `Connection: close`, `Keep-Alive`, RST no meio, atraso.
6. Ociosidade: cliente mantém a conexão por 30/90/180 s — quem fecha, quando.
7. HTTPS por CONNECT com curl/OpenSSL, Go e um cliente que imita Chrome: ClientHello byte a byte, JA3/JA4,
   Akamai h2.
8. CONNECT para portas baixas em `banner` e `echo`, com meio-fechamento.
9. WebSocket `ws://` e `wss://`.
10. DNS: qual resolvedor consulta, com ECS ou não, A/AAAA/HTTPS.
11. TCP: JA4T/p0f e TTL de cada caminho; RTT handshake × aplicação; relógio de timestamps entre IPs de saída.
12. HTTP/3 (só caminho direto; proxies HTTP não transportam QUIC): `curl --http3-only`, quic-go, Chrome (Alt-Svc e
    HTTPS RR) e Firefox quando der sem desligar o sandbox; transport params na ordem, JA4 `q`, fim da conexão.
13. Tempo real e site: `/ws` e `/stream` (filtros, `stream.dropped`, 503), página do htdocs em Chrome headless
    mostrando a própria sondagem no feed em < 1 s, sem requisições a terceiros.

Critério: o teste e2e roda os 13 casos pelo caminho direto e verifica que cada caso gera os campos esperados e
que o espelho expõe tudo o que um cliente precisa para comparar caminhos: campos estáveis entre execuções, sinais
de proxy, bytes crus e o reaproveitamento de conexões visível no registro. A comparação entre caminhos (proxies,
túneis) é do cliente, que usa as receitas genéricas e a lista de campos estáveis e de diferenças esperadas de
`docs/probes.md` (ex.: `absolute-form` → `origin-form`, ausência de `Proxy-*`; ADRs 0022 e 0028). Casos 6
(ociosidade 30/90/180 s) e 11 (JA4T/p0f/TTL, RTT, relógio TS entre execuções) no caminho direto comparam execuções
repetidas do mesmo cliente.

### Carga
- RF-13: `test/load/`: 400 conexões simultâneas e 100 novas/s por 10 min (RNF-01, ADR 0046), depois de 9 min de
  pré-aquecimento no mesmo perfil (o expurgo roda dentro da janela), mix h1/h2/h3/raw;
  mede CPU/RAM por serviço, `cpu.stat nr_throttled` por unit, latência da API (p95), atraso do feed,
  `dropped_events_total`, `kernel_drops`, `fs_store_flows_dropped_total` e o `conntrack -S` antes e depois;
  `fs_store_stream_lost_total` sem crescer e health do store sem `ingest backlog`/`stream lost` (ADR 0041), com
  `fs_store_ingest_backlog_seconds` máximo e `fs_store_stray_midflow_total`/s registrados; memória do store por 5 s
  (`memory.current`, `file`, `anon`, `memory.events`, `pgscan`/`pgsteal`/`workingset_refault_file`,
  `memory.pressure`, `io.pressure`) e tamanho do banco e do WAL registrados (ADR 0042); com o banco em tmpfs
  (ADR 0045), também `shmem` do store e da fatia e `fs_store_db_fs_bytes`, com `memory.events max`/`oom_kill`
  do store e `fs_store_db_full_total` sem crescer. Degraus de 3 min (50, 75,
  100 novas/s, sem meta) medem o teto do ingest quando ele muda (ADR 0041; fase F7).
  Gerador em Go fora do finger-01 (a máquina cliente), para medir o caminho real e não disputar CPU com o espelho e
  os sites. As metas do gerador (conexões com erro no cliente 0, puladas pelo teto do gerador 0) ficam no
  relatório; falha nelas é aceita como do cliente só quando o espelho não a acompanha na mesma janela (modo
  degradado desligado; `kernel_drops`, `flows_dropped`, `conntrack -S` drop/insert_failed/early_drop e
  `nr_throttled` sem crescer; backlog < 1 s; erros concentrados num caminho do cliente), e o relatório diz qual
  condição sustenta a aceitação (ADR 0046 item 2). Ressalva: com o gerador no Mac (NAT doméstico, outros
  processos) essas duas metas não são medidas de forma limpa; um gerador fora do Mac é a task 256; amostragem de CPU/RAM por unit (cgroup, em `finger.slice/finger-sniffer.slice/`) no finger-01;
  metas e percentis da ADR 0022, primeiro minuto descartado. Relatório em `test/load/RESULTS.md` com versão,
  data, perfil, números por meta (passou/falhou) e a decomposição do atraso do feed.

### Regras para os agentes
- Toda mudança vem com o teste que a cobre; o nível só decide quanto da suíte roda.
- Ao terminar, dizer qual nível rodou e o resultado. Subagentes: rápido por padrão, completo só sob pedido.

### Fase F8 (ADRs 0047 e 0048)
- RF-14: `traefik/**` fica fora dos passos do módulo raiz (lint, gofumpt, vet, testes, cobertura, govulncheck,
  `go_source_files`); passo próprio "traefik": `go build ./cmd/traefik` e `go test` de `./pkg/fingersniffer/...` e
  dos pacotes com gancho `// finger-sniffer:` dentro de `traefik/`, no quick só quando `traefik/**` muda, sempre no
  full e no CI.
- RF-15: contratos: o passo valida também `cmd/finger-sniffer-bot/openapi.yaml` (Redocly) e o teste de contrato
  do bot confere as respostas das rotas contra ele.
- RF-16: banco-modelo do bot (`database/sqlite/bot/`) como o do store (RF-06), com hash próprio.
- RF-17: e2e da F8 (`--e2e`, depois do deploy do bot e do fork num traefik de teste no finger-01): veredito de
  curl, Go, python-requests, Chrome, Firefox e um Googlebot falso, pelo traefik de teste (forwardAuth e consulta) e
  por probe; casamento fork ↔ store ≥ 99%; fail-open com o bot parado. Carga da F8: forwardAuth a 200
  requisições/s por 10 min com a carga oficial 400/100 do espelho ao mesmo tempo (RNF da spec 018).

## Critérios de aceite
- [ ] `make verify-quick` sem mudanças termina em < 10 s com tudo "pulado".
- [ ] Alterar um `.go` de `pkg/h1` roda só lint/vet/test de `pkg/h1` e dependentes.
- [ ] Alterar uma migration refaz o banco-modelo; sem alteração, não refaz.
- [ ] `make verify-full` no CI verde no primeiro PR.

## Decisões relacionadas
- specs/decisions/0013-verificacao-dois-niveis.md
- specs/decisions/0022-prova-do-mvp-no-espelho.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
- specs/decisions/0041-ingest-atrasado-relogio-e-lacunas.md
- specs/decisions/0045-banco-do-store-em-ram.md
- specs/decisions/0046-rnf-01-400-100-com-o-banco-em-ram.md
