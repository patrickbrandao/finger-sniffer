# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Versionamento: [SemVer](https://semver.org/lang/pt-BR/).
Detalhe das decisões em `specs/decisions/`.

## [Não lançado]

### Adicionado
- Esqueleto: go.mod, 5 stubs de serviço com `-version`, Makefile (build estático, lint, tools), golangci-lint v2, lefthook, LICENSE Apache-2.0, NOTICE (task 001).
- `make verify-quick`/`verify-full` (scripts/verify.sh), banco-modelo SQLite por hash das migrations (scripts/testdb), CI GitHub Actions com verify-full (task 002).
- VPS: unit de rede (offloads off, sysctl TCP fixado), 7 units systemd + target com hardening, NATS v2.15.2 e p0f.fp com checksum, journald 24 h/200 MB, `make deploy [SVC=]` idempotente com trava remota e smoke test (task 003).

### Decidido
- Espelho genérico de conexões; consumidor principal go-xproxy (ADR 0001).
- 5 serviços (capture, web, raw, dns, store), 1 binário cada, Go 1.27 estático (ADR 0002, 0009).
- NATS + JetStream local; todos os pacotes pelo barramento (provisório) (ADR 0003, 0004).
- SQLite com BLOBs, goose, retenção 10 min / 2 GiB (provisório) (ADR 0005, 0012).
- Portas capturadas do §3 + QUIC; API 9000 HTTPS / 9001 HTTP sem captura, aberta, feed global (ADR 0006, 0007).
- Zona `dns-monitor.tmsoft.com.br`, ACME embutido DNS-01/HTTP-01 (ADR 0008).
- Offloads off, sysctls TCP fixados (ADR 0011).
- Apache-2.0; JA4+ isolado (FoxIO License) (ADR 0010).
- Verificação em dois níveis, CI = full, deploy local (ADR 0013).
- 10 papéis de agente, worktree por agente, trunk-based (ADR 0014).
