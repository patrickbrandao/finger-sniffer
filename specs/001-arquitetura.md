# 001 — Arquitetura

Status: aprovada
Depende de: 000

## Contexto
Cinco serviços independentes, um por protocolo, ligados por um NATS local. A análise junta duas fontes no mesmo
`conn_id`: os pacotes capturados (IP/TCP) e os servidores de aplicação (TLS/HTTP/DNS/raw). O store correlaciona,
analisa IP/TCP, guarda em SQLite e serve a API.

## Componentes

```
                         eth0 (capturada, offloads off)
   clientes ──► TCP 80/443/8080/8443, UDP 443 ──► finger-sniffer-web ─┐
            ──► TCP 7/21/22/25/110/143/587/993 ─► finger-sniffer-raw ─┤
            ──► UDP/TCP 53 ─────────────────────► finger-sniffer-dns ─┤  fs.v1.* (NATS 127.0.0.1:4222,
   AF_PACKET (todos os pacotes) ────────────────► finger-sniffer-capture ┤   JetStream FS_EVENTS)
                                                                         ▼
                                                     finger-sniffer-store ── SQLite (var/store)
   clientes da API ◄── 9000 HTTPS / 9001 HTTP (sem captura) ◄────────────┘
```

| Unit systemd | Binário | Responsabilidade | Portas | Capabilities | Spec |
| --- | --- | --- | --- | --- | --- |
| finger-sniffer-net.service (oneshot) | script | offloads, sysctls, antes de tudo | — | root | 016 |
| finger-sniffer-nats.service | nats-server (oficial, fixado) | barramento + JetStream | 127.0.0.1:4222, :8222 | — | 016 |
| finger-sniffer-capture.service | finger-sniffer-capture | captura AF_PACKET de todos os pacotes da eth0 (exceto portas excluídas) e publica | — | NET_RAW | 003 |
| finger-sniffer-store.service | finger-sniffer-store | ingest, correlação `conn_id`/probe, análise IP/TCP, retenção, SQLite, API, SSE/WS, métricas agregadas | 9000, 9001 | NET_BIND_SERVICE não necessário | 004, 013 |
| finger-sniffer-web.service | finger-sniffer-web | HTTP/1, h2, h2c, h3, WS, TLS, htdocs, controles de resposta, ACME | TCP 80/443/8080/8443, UDP 443 | NET_BIND_SERVICE | 005, 008–012, 014, 015 |
| finger-sniffer-raw.service | finger-sniffer-raw | portas TCP cruas, echo/banner/sink/source, TLS opcional | 7/21/22/25/110/143/587/993 | NET_BIND_SERVICE | 006 |
| finger-sniffer-dns.service | finger-sniffer-dns | autoritativo de `dns-monitor.tmsoft.com.br`, TXT ACME | UDP/TCP 53 | NET_BIND_SERVICE | 007 |

Biblioteca comum (`./pkg/`): detecção de protocolo pelos primeiros bytes, extração de probe ID, parsers
(TLS ClientHello, HTTP/1, frames h2/HPACK, QUIC Initial), fingerprints, envelope de eventos, base de serviço
(config, slog, NATS, heartbeat, buffer do produtor). Dono: implementer-web (detecção/parsers/fingerprints) e
implementer-store (base de serviço/envelope), conforme spec 002.

## Dono de cada dado

| Entidade | Produzida por | Dona (persistência) | Retenção |
| --- | --- | --- | --- |
| Packet (pacote cru + metadados) | capture | store | 10 min / teto |
| Connection (`conn_id` ULID, 5-tupla, linha do tempo, fechamento) | store (a partir de capture + app) | store | 10 min |
| IP/TCP analysis (TTL, IP ID, opções, JA4T, p0f, RTT, relógio TS, segmentação) | store | store | 10 min |
| TLS / HTTP1 / HTTP2 / HTTP3 / WebSocket analysis + bytes enviados | web, raw | store | 10 min |
| Raw session (bytes de cada sentido, modo) | raw | store | 10 min |
| DNS query | dns | store | 10 min |
| Probe (agrupamento por probe ID) | store | store | enquanto houver conexões |
| Certificados e conta ACME | web | arquivos em `var/certs`, `var/acme` | renovados |
| Heartbeat/health | todos | store (memória) | 30 s |

## Correlação
- Toda conexão recebe `conn_id` (ULID) no store pela 5-tupla (`l4`, src ip:porta, dst ip:porta) e janela de tempo
  (primeiro SYN / primeiro datagrama). Eventos de aplicação trazem a 5-tupla e são associados ao mesmo `conn_id`.
- QUIC: 4-tupla UDP + DCID do Initial.
- Probe ID `[a-z0-9]{8,32}` extraído de: rótulo mais à esquerda do host em `<id>.dns-monitor.tmsoft.com.br`
  (SNI, `Host`, `:authority`, CONNECT, qname DNS); caminho `/p/<id>/...`; primeira linha `PROBE <id>\r\n` em TCP cru.
- Conexões sem probe continuam consultáveis por IP de origem, porta de destino e janela de tempo.

## Integrações externas e falhas
| Integração | Uso | Se falhar |
| --- | --- | --- |
| Let's Encrypt (ACME) | certificados válidos | mantém o anterior; sem nenhum, autoassinado; backoff até 1 h; health `degraded` (spec 015) |
| udns.com.br (zona pai) | delegação NS de `dns-monitor` e nomes `vps602`, `fingerprint`, `tcp`, `udp` | fora do nosso controle; health não cobre |
| NTP (systemd-timesyncd) | tempos ns UTC | health `degraded` se não sincronizado |
| NATS local | barramento | produtores guardam 30 s / 16 MiB e reenviam; depois descartam e contam `dropped_events` |
| Store fora do ar | — | JetStream retém 60 s / 64 MiB; consumidor durável retoma |

## Barramento (NATS)
- Subjects versionados `fs.v1.<origem>.<tipo>` (ex.: `fs.v1.capture.packet`, `fs.v1.web.http1.request`,
  `fs.v1.dns.query`, `fs.v1.svc.heartbeat`); request/reply `fs.v1.dns.acme.set`/`.clear` para o TXT do DNS-01.
- Envelope comum (JSON): `schema_version`, `service`, `service_version`, `ts` (ns UTC), `flow` (5-tupla),
  `probe_id`, `payload`. Exceção: o lote de pacotes `fs.v1.capture.packet` é binário (FSPB v1, envelope nos
  cabeçalhos NATS — ADR 0015).
- Stream JetStream `FS_EVENTS` (`fs.v1.>`), `max_age` 60 s, `max_bytes` 64 MiB, consumidor durável `store`.
- Contrato: [eventbus/nats/asyncapi.yaml](../eventbus/nats/asyncapi.yaml); configuração:
  [eventbus/nats/nats.conf](../eventbus/nats/nats.conf).

## Interfaces para o usuário
- Portas capturadas: web, raw e DNS (specs 005–007).
- API `/api/v1` em 9000 (HTTPS, mesmo certificado) e 9001 (HTTP), CORS `*`, sem autenticação:
  [cmd/finger-sniffer-store/openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) (spec 004).
- Página estática (spec 014).
- Sem autenticação, sem administrador, sem bootstrap de admin (ADR 0007).

## Contratos
- OpenAPI 3.1: `cmd/finger-sniffer-store/openapi.yaml` (servido em `/api/v1/openapi.yaml`).
- AsyncAPI: `eventbus/nats/asyncapi.yaml`.
- Schema SQLite: `database/sqlite/migrations/` (goose).

## Stack (resumo — ADR 0009)
Go 1.27, `CGO_ENABLED=0`, binários estáticos linux/amd64 compilados no Mac. gopacket/gopacket (afpacket
TPACKET_V3), miekg/dns v1, certmagic (provedor DNS-01 próprio via NATS), quic-go (+http3), x/net (http2, hpack),
coder/websocket, nats.go, prometheus/client_golang, oklog/ulid v2, log/slog, modernc.org/sqlite, pressly/goose v3.
HTTP/1 com parser/escritor próprio; h2 com x/net/http2 sem fork + parser passivo; JA3/JA4/Akamai portados do
fingerproxy; tabela IANA própria. Sem Docker (ADR 0009). NATS oficial fixado (ADR 0003).

## Qualidade e operação (resumo)
- Verificação em dois níveis, cobertura ≥ 80% em parsers/fingerprints e ≥ 60% no total, golangci-lint v2 +
  gofumpt + lefthook, CI GitHub Actions = verify-full (ADR 0013, spec 017).
- Config: `/finger-sniffer/etc/finger-sniffer.env`, prefixo `FS_`, modelo em `.env.example`.
- Observabilidade: slog JSON → journald (24 h / 200 MB); `/metrics` agregado na 9001; heartbeat a cada 5 s;
  `/api/v1/health` por serviço com sysctls, offloads, certificado, disco/SQLite, versões (ADR 0012, spec 004).
- Ambiente único: vps602 (dev = teste). Testes de ACME com Pebble/LE staging.
- SemVer único, tag `vX.Y.Z`, versão via ldflags; contratos v1 só aditivos, quebra → v2 (ADR 0001).
- Sem backup (ADR 0012).

## Ameaças e controles
| Ameaça | Controle | Verificação |
| --- | --- | --- |
| Exaustão em 1 vCPU (slowloris, flood PRIORITY h2, cabeçalhos gigantes, SYN flood) | tetos de idle/delay/size/hsize, limite global `FS_MAX_CONNS`, limite de frames PRIORITY, syncookies=1 com backlog alto. **Sem limite por IP** | testes de carga e fuzz |
| Disco cheio por BLOBs | teto `FS_STORE_MAX_BYTES`, expurgo do mais antigo | teste de retenção |
| Parser travando/estourando com entrada maliciosa | `go test -fuzz` em todos os parsers | fuzz no verify-full (tempo curto), longo sob pedido |
| DNS usado para amplificação | sem recursão, só zona própria, REFUSED fora dela, rate limit de respostas por IP | teste do dns |
| Privilégios | capabilities mínimas, ProtectSystem=strict, usuário dedicado | revisão das units |
| Dependências vulneráveis | govulncheck no verify-full e CI | CI |
| Dados de terceiros expostos | aceito (ADR 0007); retenção curta | — |

## Critérios de aceite
- [ ] As 7 units sobem na ordem net → nats → store → capture/web/raw/dns e `/api/v1/health` mostra os 5 serviços `ok`.
- [ ] Uma sondagem `curl https://<id>.dns-monitor.tmsoft.com.br/p/<id>/` gera, sob o mesmo `conn_id`, pacotes,
      análise TCP, análise TLS, requisição HTTP e a consulta DNS do probe.

## Fora de escopo
- Componentes fora da vps602.

## Decisões relacionadas
- specs/decisions/0002-arquitetura-cinco-servicos.md
- specs/decisions/0003-nats-jetstream.md
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0005-sqlite-com-blobs.md
- specs/decisions/0006-portas-e-api-sem-captura.md
- specs/decisions/0008-zona-dns-e-acme.md
- specs/decisions/0009-stack-go-estatico.md
- specs/decisions/0011-rede-offloads-e-pilha-tcp.md
- specs/decisions/0015-lote-binario-de-pacotes.md
