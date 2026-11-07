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
- RF-04: não roda build final, e2e, `-race` nem a suíte inteira.
- RF-05: aceita testes explícitos depois de `--`: `make verify-quick ARGS="-- ./pkg/h1 -run TestChunked"`.
- RF-06: SQLite local: banco-modelo `tmp/testdb/template.sqlite` migrado pelo goose, refeito só quando o hash
  (sha256) de `database/sqlite/migrations/` muda (hash guardado em `PRAGMA user_version`/tabela `meta`); cada teste
  copia o modelo para um arquivo temporário (< 1 s). Ligado por `FS_TEST_DB=local` no setup comum de testes.
- RF-07: roda todos os passos; código de saída ≠ 0 se algum falhar.

### Nível completo (sob pedido, antes de PR e de release; CI sempre)
- RF-08: `golangci-lint run ./...`, `gofumpt -l`, `go vet ./...`, `go test -race -cover ./...` (banco isolado:
  arquivo SQLite temporário novo migrado do zero), metas de cobertura (≥ 80% em `pkg/{detect,probe,tlsparse,h1,
  h2passive,quicparse,fingerprint}`, ≥ 60% total), fuzz curto (10 s por alvo), `govulncheck ./...`,
  build linux/amd64 dos 5 binários, testes com tag `linux_priv` (AF_PACKET, ethtool) executados na vps602 por ssh.
- RF-09: `--e2e` acrescenta a matriz abaixo contra a vps602 (exige deploy da versão em teste).
- RF-10: para na primeira falha.
- RF-11: CI (GitHub Actions) roda `verify-full` sem `--e2e` e sem `linux_priv` em todo PR e na `main`.

### Níveis de teste
- RF-12: unidade com golden files: pcaps da FoxIO (portados do `ja4pcap`) e capturas próprias de curl, Go, Chrome e
  Firefox em `pkg/**/testdata/`; integração com NATS embutido (nats-server como biblioteca só nos testes);
  contrato: respostas da API validadas contra o openapi.yaml e eventos contra o asyncapi.yaml; e2e: matriz.

### Matriz e2e (a partir de uma máquina cliente e do xproxy03)
Caminho {direto, squid 1080, go-xproxy 4128, go-xproxy HTTPS-proxy 4443} × sufixo {fixo, `-random`,
`-session-X`} × caso:
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

Critério: em HTTP/TLS/keep-alive, o que chega pelo proxy é idêntico ao direto (diferenças esperadas listadas:
`absolute-form` → `origin-form`, ausência de `Proxy-*`; `-random` abre conexão nova por requisição). Em TCP, o
critério é consistência entre saídas e execuções. **No espelho**, o teste e2e verifica que cada caso gera os
campos esperados; a comparação entre caminhos é do script do xProxy.

### Carga
- RF-13: `test/load/`: 200 conexões simultâneas e 50 novas/s por 10 min, mix h1/h2/h3/raw; mede CPU/RAM por
  serviço, latência da API (p95), atraso do feed, `dropped_events_total`, `kernel_drops`.

### Regras para os agentes
- Toda mudança vem com o teste que a cobre; o nível só decide quanto da suíte roda.
- Ao terminar, dizer qual nível rodou e o resultado. Subagentes: rápido por padrão, completo só sob pedido.

## Critérios de aceite
- [ ] `make verify-quick` sem mudanças termina em < 10 s com tudo "pulado".
- [ ] Alterar um `.go` de `pkg/h1` roda só lint/vet/test de `pkg/h1` e dependentes.
- [ ] Alterar uma migration refaz o banco-modelo; sem alteração, não refaz.
- [ ] `make verify-full` no CI verde no primeiro PR.

## Decisões relacionadas
- specs/decisions/0013-verificacao-dois-niveis.md
