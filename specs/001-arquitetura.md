# 001 — Arquitetura

Status: aprovada
Depende de: 000

## Contexto
Cinco serviços independentes, um por protocolo, ligados por um NATS local, mais o serviço `bot` da fase F8 (ADR
0047), que avalia bots a partir do que o store publica e do que o traefik modificado envia. A análise junta duas fontes no mesmo
`conn_id`: os pacotes capturados (IP/TCP) e os servidores de aplicação (TLS/HTTP/DNS/raw). O store correlaciona,
analisa IP/TCP, guarda em SQLite e serve a API.

## Componentes

```
                         ens192 (capturada, offloads off; inclui 80/443 do traefik)
   clientes ──► TCP 8080/8443, UDP 8443 ────────► finger-sniffer-web ─┐
            ──► TCP 7/21/22/25/110/143/587/993 ─► finger-sniffer-raw ─┤
            ──► UDP/TCP 53 ─────────────────────► finger-sniffer-dns ─┤  fs.v1.* (NATS 127.0.0.1:4222,
   AF_PACKET (todos os pacotes) ────────────────► finger-sniffer-capture ┤   JetStream FS_EVENTS)
                                                                         ▼
                                                     finger-sniffer-store ── SQLite (var/store, tmpfs)
   clientes da API ◄── 9000 HTTPS / 9001 HTTP (sem captura) ◄────────────┘

   visitantes ──► traefik do host (TCP 443, passthrough por SNI de finger-01.*) ──► web :8443 (página)

   F8 (ADR 0047):
   finger-sniffer-store ── fs.v1.store.connection (NATS core) ──► finger-sniffer-bot ── SQLite em disco (var/bot)
   visitantes dos sites ──► traefix (traefik modificado, container) ── ingest + forwardAuth ──► bot :9003
   sites e clientes externos (chave) ──► bot :9002 HTTPS (sem captura) ; webhook ◄── bot
```

| Unit systemd | Binário | Responsabilidade | Portas | Capabilities | Spec |
| --- | --- | --- | --- | --- | --- |
| finger-sniffer-net.service (oneshot) | script | offloads, sysctls, antes de tudo | — | root | 016 |
| finger-sniffer-nats.service | nats-server (oficial, fixado) | barramento + JetStream | 127.0.0.1:4222, :8222 | — | 016 |
| finger-sniffer-capture.service | finger-sniffer-capture | captura AF_PACKET de todos os pacotes da ens192 (exceto portas excluídas) e publica | — | NET_RAW | 003 |
| finger-sniffer-store.service | finger-sniffer-store | ingest, correlação `conn_id`/probe, análise IP/TCP, retenção, SQLite, API, SSE/WS, métricas agregadas | 9000, 9001 | NET_BIND_SERVICE não necessário | 004, 013 |
| finger-sniffer-web.service | finger-sniffer-web | HTTP/1, h2, h2c, h3, WS, TLS, htdocs, controles de resposta, ACME | TCP 8080/8443, UDP 8443 | nenhuma (portas > 1024, ADR 0038) | 005, 008–012, 014, 015 |
| finger-sniffer-raw.service | finger-sniffer-raw | portas TCP cruas, echo/banner/sink/source, TLS opcional | 7/21/22/25/110/143/587/993 | NET_BIND_SERVICE | 006 |
| finger-sniffer-dns.service | finger-sniffer-dns | autoritativo de `finger-west-01.badblock.net.br`, TXT ACME | UDP/TCP 53 | NET_BIND_SERVICE | 007 |
| finger-sniffer-bot.service | finger-sniffer-bot | veredito de bot, listas, agregados de 7 dias, chaves, feed e webhook (F8) | 9002 (HTTPS), 9003 (interna) | nenhuma | 018, 020 |

Fora das units: o traefik modificado é o **traefix**, projeto externo do humano (ADR 0054), que atende aos requisitos
da spec 019 e roda como o container `traefik-app` do host com a imagem `tmsoftbrasil/traefix` numa tag fixada; a
troca no finger-01 é só observando (sem forwardAuth nos sites) e o bloqueio por site é do humano.

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
| Visão do traefik (ClientHello, h2, resumo das requisições) | traefix | bot (memória) | 10 min |
| Veredito por requisição/conexão/probe | bot | bot (memória), feed e webhook | 10 min |
| Agregados por IP/site/hora e por fingerprint/dia | bot | bot (disco, `var/bot/bot.db`) | 7 dias (ADR 0052) |
| Chaves de API, uso diário, webhooks | operador (CLI) | bot (disco) | enquanto a chave existir |
| Listas de referência (ja4db, IPs de robôs e nuvens) | publicadores externos | bot (disco, `var/bot/lists`) | até a próxima atualização |

## Correlação
- Toda conexão recebe `conn_id` (ULID) no store pela 5-tupla (`l4`, src ip:porta, dst ip:porta) e janela de tempo
  (primeiro SYN / primeiro datagrama). Eventos de aplicação trazem a 5-tupla e são associados ao mesmo `conn_id`.
- QUIC: 4-tupla UDP + DCID do Initial.
- Probe ID `[a-z0-9]{8,32}` extraído de: rótulo mais à esquerda do host em `<id>.finger-west-01.badblock.net.br`
  ou `<id>.finger-01.badblock.net.br` (SNI, `Host`, `:authority`, CONNECT, qname DNS, depois de pular os rótulos
  iniciados por `_`); caminho `/p/<id>/...`; primeira linha `PROBE <id>\r\n` em TCP cru.
- Conexões sem probe continuam consultáveis por IP de origem, porta de destino e janela de tempo.

## Integrações externas e falhas
| Integração | Uso | Se falhar |
| --- | --- | --- |
| Let's Encrypt (ACME) | certificados válidos | mantém o anterior; sem nenhum, autoassinado; backoff até 1 h; health `degraded` (spec 015) |
| udns.com.br (zona pai `badblock.net.br`) | delegação NS de `finger-west-01` e nomes `finger-01`, `*.finger-01` | fora do nosso controle; health não cobre |
| traefik do host (container do humano) | entrega `https://finger-01.badblock.net.br` ao web na 8443 (passthrough) e a validação TLS-ALPN-01 do certificado B (ADRs 0038 e 0044) | a página continua direta em `:8443` e a API direta na 9000; o B não renova até voltar (health avisa < 14 dias) |
| NTP (systemd-timesyncd) | tempos ns UTC | health `degraded` se não sincronizado |
| NATS local | barramento | produtores guardam 30 s / 16 MiB e reenviam; depois descartam e contam `dropped_events` |
| Store fora do ar | — | JetStream retém 60 s / 128 MiB em memória (ADRs 0016 e 0039); consumidor durável retoma |
| ja4db (FoxIO) e listas de IP de robôs/nuvens | sinais de lista do bot (ADR 0050) | mantém a cópia anterior; health do bot `degraded` após 72 h |
| Bot fora do ar | vereditos | forwardAuth do traefix em fail-open (`X-Fs-Verdict: unavailable`); o espelho segue sem mudança |
| Receptores de webhook | entrega de vereditos | 3 novas tentativas, fila de 1000 por chave com descarte contado |

## Barramento (NATS)
- Subjects versionados `fs.v1.<origem>.<tipo>` (ex.: `fs.v1.capture.packet`, `fs.v1.web.http1.request`,
  `fs.v1.dns.query`, `fs.v1.svc.heartbeat`); request/reply NATS core `fs.v1.dns.acme.set`/`.clear` para o TXT do
  DNS-01 e `fs.v1.store.conn_id` para o web saber o `conn_id` da conexão (ADR 0017); NATS core
  `fs.v1.store.connection` do store para o bot (ADR 0047), fora do stream.
- Envelope comum (JSON): `schema_version`, `service`, `service_version`, `ts` (ns UTC), `flow` (5-tupla),
  `probe_id`, `payload`. Exceção: o lote de pacotes `fs.v1.capture.packet` é binário (FSPB v1, envelope nos
  cabeçalhos NATS — ADR 0015).
- Stream JetStream `FS_EVENTS` com lista explícita de subjects de eventos (`fs.v1.capture.>`, `fs.v1.web.>`,
  `fs.v1.raw.>`, `fs.v1.dns.query`, `fs.v1.svc.>` — ADR 0017), em memória, `max_age` 60 s, `max_bytes` 128 MiB,
  consumidor durável `store` (ADRs 0016 e 0039). Request/reply fica fora do stream.
- Nenhum evento JSON passa de 900 KiB; bytes grandes vão pelo fluxo de aplicação (ADR 0018). Listas e strings
  cortadas para caber levam marca `*_truncated` (ADR 0032).
- Desligamento: cada serviço para de aceitar entrada, escoa o NATS (`Drain`, com prazo) e só então sai, para
  não perder os eventos já publicados e ainda no buffer do cliente.
- Contrato: [eventbus/nats/asyncapi.yaml](../eventbus/nats/asyncapi.yaml); configuração:
  [eventbus/nats/nats.conf](../eventbus/nats/nats.conf).

## Interfaces para o usuário
- Portas capturadas: web, raw e DNS (specs 005–007).
- API `/api/v1` em 9000 (HTTPS, mesmo certificado) e 9001 (HTTP), CORS `*`, sem autenticação:
  [cmd/finger-sniffer-store/openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) (spec 004).
- Página estática (spec 014).
- Sem autenticação, sem administrador, sem bootstrap de admin (ADR 0007).
- API do bot `/bot/v1` em 9002 (HTTPS, chave) e 9003 (interna):
  [cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) (spec 020).

## Contratos
- OpenAPI 3.1: `cmd/finger-sniffer-store/openapi.yaml` (servido em `/api/v1/openapi.yaml`).
- AsyncAPI: `eventbus/nats/asyncapi.yaml`.
- Schema SQLite: `database/sqlite/migrations/` (goose).
- OpenAPI do bot: `cmd/finger-sniffer-bot/openapi.yaml`; schema SQLite do bot: `database/sqlite/bot/` (goose).

## Stack (resumo — ADR 0009)
Go 1.27, `CGO_ENABLED=0`, binários estáticos linux/amd64 compilados no Mac. gopacket/gopacket (afpacket
TPACKET_V3), miekg/dns v1, certmagic (provedor DNS-01 próprio via NATS), quic-go (+http3), x/net (http2, hpack),
coder/websocket, nats.go, prometheus/client_golang, oklog/ulid v2, log/slog, modernc.org/sqlite, pressly/goose v3.
HTTP/1 com parser/escritor próprio; h2 com x/net/http2 sem fork + parser passivo; JA3/JA4/Akamai portados do
fingerproxy; tabela IANA própria. Sem Docker no espelho (ADR 0009); o traefik modificado é o projeto externo traefix, com imagem própria (ADR 0054).
NATS oficial fixado (ADR 0003).

## Qualidade e operação (resumo)
- Verificação em dois níveis, cobertura ≥ 80% em parsers/fingerprints e ≥ 60% no total, golangci-lint v2 +
  gofumpt + lefthook, CI GitHub Actions = verify-full (ADR 0013, spec 017).
- Config: `/finger-sniffer/etc/finger-sniffer.env`, prefixo `FS_`, modelo em `.env.example`.
- Observabilidade: slog JSON → journald (24 h / 200 MB); `/metrics` agregado na 9001; heartbeat a cada 5 s;
  `/api/v1/health` por serviço com sysctls, offloads, certificado, disco/SQLite, versões (ADR 0012, spec 004).
- Ambiente único: finger-01 (dev = teste; ADR 0038), compartilhado com o traefik e os sites do humano; o espelho
  roda na fatia `finger-sniffer.slice` (6 GiB, 8 vCPU) e não mexe no resto do host. Testes de ACME com Pebble/LE
  staging.
- SemVer único, tag `vX.Y.Z`, versão via ldflags; contratos v1 só aditivos, quebra → v2 (ADR 0001).
- Sem backup (ADR 0012).

## Ameaças e controles
| Ameaça | Controle | Verificação |
| --- | --- | --- |
| Exaustão de CPU (slowloris, flood PRIORITY h2, cabeçalhos gigantes, SYN flood), inclusive tirando recursos dos sites do host | tetos de idle/delay/size/hsize, limite global `FS_MAX_CONNS` (web e raw, ADR 0035), limite de frames PRIORITY, syncookies=1 com backlog alto, `MemoryMax`/`CPUQuota` por unit e na fatia (ADR 0039). **Sem limite por IP** | testes de carga e fuzz |
| Memória do web esgotada por entrada retida (cabeçalho h1 de 1 MiB × conexões, campos HPACK, HEADERS h3 em espera, mensagens WebSocket) | orçamento global `FS_WEB_INPUT_BUDGET` (192 MiB, ADR 0039) reservado pela memória alocada e devolvido por h1/h2/h3/WebSocket e pelo pendente de `stream.bytes`, mais tetos por conexão: h1 1 MiB e 1024 campos, h2 1 MiB e 100 streams, h3 2 MiB e 10 s (quic-go com janela máxima 2/4 MiB), WebSocket 32 sessões de 2 MiB e eco com prazo de 30 s; buffers de kernel com teto: todo socket TCP com `SO_RCVBUF`/`SO_SNDBUF` de 16 KiB no `accept`, UDP do QUIC com 1 MiB; `GOMEMLIMIT` 512MiB e `GODEBUG=disablethp=1`; estouro → 431, `fields_truncated`, `H3_EXCESSIVE_LOAD`, 503 (ADRs 0033, 0036, 0037 e 0039) | teste de cada caminho com o contador voltando a zero e a reserva ≥ 90% do heap retido; buffers lidos por `getsockopt`; carga do orçamento com `memory.peak` ≤ 704 MiB e sem eventos `max` |
| Tabela de Initials QUIC ocupada por datagramas forjados; CRYPTO fragmentado | tracker com 4096 entradas e 8 MiB, entrada sem ClientHello sai em 2 s, despejo da mais antiga encerrada; no máximo 64 fragmentos CRYPTO pendentes (spec 011) | teste com relógio falso e benchmark |
| Store saturado por 5-tuplas novas (SYN flood de origens mudas, UDP solto) | tabela de fluxos com 8192 entradas, meio-aberto ocioso em 10 s, despejo do não estabelecido mais antigo, `fs_store_flows_dropped_total` (ADR 0034) | unitário com 100 mil SYNs; carga com flood |
| Memória do store esgotada por leitura (probe enorme, `wait` em laço, downloads de BLOB, cliente ao vivo lento, pcap truncado) | probe com até 1000 conexões e 1000 consultas e `truncated`; até 64 `wait` e 4 downloads simultâneos, 503 acima, prazo de escrita de 60 s (ADR 0032); filas ao vivo com 4 MiB por cliente e 64 MiB no hub; orçamento de "só cabeçalhos" no pcap (ADR 0034) | testes de alocação e de 503 |
| tmpfs do banco cheio por BLOBs (ADR 0045) | teto `FS_STORE_MAX_BYTES`, expurgo do mais antigo e pelo livre do tmpfs, `SQLITE_FULL` → expurgo de emergência e modo banco cheio, health `db full` | teste de retenção e de `SQLITE_FULL` |
| Parser travando/estourando com entrada maliciosa | `go test -fuzz` em todos os parsers | fuzz no verify-full (tempo curto), longo sob pedido |
| DNS usado para amplificação | sem recursão, só zona própria, REFUSED fora dela, rate limit de respostas UDP por IP (IPv6 por /64, balde de transbordo com a tabela cheia; TCP fora do RRL, ADR 0035) | teste do dns |
| Privilégios | capabilities mínimas, ProtectSystem=strict, usuário dedicado | revisão das units |
| Dependências vulneráveis | govulncheck no verify-full e CI | CI |
| Dados de terceiros expostos (inclusive visitantes dos sites atrás do traefik, ADR 0038) | aceito (ADR 0007); retenção curta; proposta de ocultar o tráfego dos sites na API aberta à espera do humano (ADR 0052 item 6) | — |
| Chave de API vazada ou abusada | só o SHA-256 no banco, chave mostrada uma vez, domínios por chave, balde e cota diária, `revoke`/`rotate` na CLI (ADR 0051) | testes de 401/404/429 |
| Cabeçalhos `X-Fs-*` forjados pelo cliente | o traefix remove todo `X-Fs-*` de entrada antes dos middlewares (spec 019 RF-05); a 9003 só aceita loopback e a rede do traefik (spec 020 RF-01) | aceite do traefix, teste de origem do bot e e2e da F8 |
| Agregados com dados pessoais retidos além do prazo | expurgo de hora em hora, teto de 7 dias, `forget` na CLI, minimização (ADR 0052) | teste com relógio falso |
| Listas externas envenenadas ou vazias | validação de formato e tamanho, queda > 50% não substitui, só HTTPS (ADR 0050) | teste das listas |

## Critérios de aceite
- [ ] As 8 units sobem na ordem net → nats → store → capture/web/raw/dns/bot e `/api/v1/health` mostra os 6 serviços
      `ok` (o bot entra na F8, task 269).
- [ ] Uma sondagem `curl https://<id>.finger-west-01.badblock.net.br:8443/p/<id>/` gera, sob o mesmo `conn_id`, pacotes,
      análise TCP, análise TLS, requisição HTTP e a consulta DNS do probe.

## Fora de escopo
- Componentes do espelho fora do finger-01.

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
- specs/decisions/0016-stream-em-memoria.md
- specs/decisions/0017-request-reply-e-conn-id.md
- specs/decisions/0018-tamanho-dos-eventos.md
- specs/decisions/0032-campos-da-auditoria-de-2026-11.md
- specs/decisions/0033-orcamento-de-memoria-de-entrada-do-web.md
- specs/decisions/0034-tetos-e-falhas-do-store.md
- specs/decisions/0035-tetos-do-raw-e-do-dns.md
- specs/decisions/0038-servidor-finger-01-e-coexistencia-com-o-traefik.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0048-fork-do-traefik.md
- specs/decisions/0054-traefix-projeto-externo.md
