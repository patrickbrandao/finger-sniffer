# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Versionamento: [SemVer](https://semver.org/lang/pt-BR/).
Detalhe das decisões em `specs/decisions/`.

## [Não lançado]

### Adicionado
- Esqueleto: go.mod, 5 stubs de serviço com `-version`, Makefile (build estático, lint, tools), golangci-lint v2, lefthook, LICENSE Apache-2.0, NOTICE (task 001).
- `make verify-quick`/`verify-full` (scripts/verify.sh), banco-modelo SQLite por hash das migrations (scripts/testdb), CI GitHub Actions com verify-full (task 002).
- VPS: unit de rede (offloads off, sysctl TCP fixado), 7 units systemd + target com hardening, NATS v2.15.2 e p0f.fp com checksum, journald 24 h/200 MB, `make deploy [SVC=]` idempotente com trava remota e smoke test (task 003).
- Contratos 0.1.0: OpenAPI com esquemas completos dos registros, AsyncAPI 3.1 com payloads, lote de pacotes binário FSPB v1 (ADR 0015), migration SQLite 00001 com cascata; validação dos contratos no verify (task 004).
- `pkg/detect` (protocolo pelos primeiros bytes, bytes reentregues) e `pkg/probe` (probe ID em host, caminho e linha PROBE, rótulos de controle), 100% de cobertura e fuzz (task 005).
- Spike de carga (test/spike, docs/dev/spike-carga.md): 50 conexões/s em 1 vCPU com CPU ~22%; gargalo no JetStream em arquivo (p95 ~1–2 s), resolvido com stream em memória (p95 178 ms); SQLite com BLOBs viável (task 006).
- ADRs 0004 e 0005 aceitas; ADR 0016: stream FS_EVENTS em memória (32 MiB) e NATS com MemoryMax 192M (task 006).
- `pkg/event` (envelope v1, FSPB v1), `pkg/service` (config FS_*, slog JSON, NATS com reconexão, buffer 30 s/16 MiB, heartbeat 5 s); store mínimo: SQLite migrado, stream FS_EVENTS em memória, `/api/v1/health`, `/api/v1/openapi.yaml` e `/metrics` na 9001; os 5 serviços publicam heartbeat (task 007).
- Serviço capture: AF_PACKET TPACKET_V3 com block timeout de 10 ms, filtro BPF de exclusão no kernel (IPv4/IPv6/VLAN), direção pelos IPs locais, lotes FSPB v1 pelo produtor com buffer, health `degraded` com offload de agregação ligado (ethtool), perdas no kernel ou frame > MTU+14 (task 008).

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
