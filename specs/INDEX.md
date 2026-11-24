# Índice das especificações

Fonte da verdade do projeto. Carregue cada spec sob demanda. Decisões em [decisions/HISTORY.md](decisions/HISTORY.md).

| Arquivo | Título | Escopo | Depende de | Status |
| --- | --- | --- | --- | --- |
| [000-visao-geral.md](000-visao-geral.md) | Visão geral | propósito, usuários, escopo, fora de escopo, MVP, restrições, RNF com números | — | aprovada |
| [001-arquitetura.md](001-arquitetura.md) | Arquitetura | 6 serviços + NATS, dono de cada dado, correlação, integrações e falhas, contratos, resumo de stack/operação, ameaças | 000 | aprovada |
| [002-organizacao-do-trabalho.md](002-organizacao-do-trabalho.md) | Organização do trabalho | papéis, propriedade de pastas, Git/PR, fluxo de tarefas, DoD, escalonamento | 000, 001 | aprovada |
| [003-capture.md](003-capture.md) | Serviço capture | AF_PACKET, BPF de exclusão, publicação de pacotes no NATS, buffer, perdas | 001, 016 | aprovada |
| [004-store-e-api.md](004-store-e-api.md) | Serviço store e API | ingest JetStream, `conn_id`/probe, pcap, SQLite com BLOBs, retenção, API 9000/9001, SSE/WS, health, métricas | 001, 003, 013 | aprovada |
| [005-web.md](005-web.md) | Serviço web | portas TCP 8080/8443 + UDP 8443, detecção por primeiros bytes, rotas, controles de resposta, Alt-Svc | 001, 008–012, 014, 015 | aprovada |
| [006-raw.md](006-raw.md) | Serviço raw | portas TCP cruas, modos echo/banner/sink/source, TLS opcional, PROBE, meio-fechamento | 001, 008 | aprovada |
| [007-dns.md](007-dns.md) | Serviço dns | autoritativo de finger-west-01.badblock.net.br, A/AAAA/HTTPS (prefixo de porta)/SOA/NS/TXT, rótulos de controle, ECS/EDNS, RRL | 001 | aprovada |
| [008-tls-e-fingerprints.md](008-tls-e-fingerprints.md) | TLS e fingerprints | ClientHello cru, parser, JA3/JA3N/JA4/JA4_r/JA4_o/stable, handshake | 005 | aprovada |
| [009-http1.md](009-http1.md) | HTTP/1.x | bytes crus, campos sem normalizar, corpo, 100-continue, pipelining, sinais de proxy, escritor | 005 | aprovada |
| [010-http2.md](010-http2.md) | HTTP/2 | parser passivo, SETTINGS/PRIORITY/HPACK, Akamai, JA4H, h2c | 005, 008 | aprovada |
| [011-http3-quic.md](011-http3-quic.md) | HTTP/3 e QUIC | servidor h3, análise do Initial, transport params, JA4 q | 005, 008 | aprovada |
| [012-websocket.md](012-websocket.md) | WebSocket | Upgrade, RFC 8441, eco, frames, extensões, fechamento | 005, 009 | aprovada |
| [013-analise-ip-tcp.md](013-analise-ip-tcp.md) | Análise IP e TCP | linha do tempo, fechamento, IP, SYN, JA4T, p0f, segmentação, relógio TS, RTT | 003, 004 | aprovada |
| [014-site-htdocs.md](014-site-htdocs.md) | Site estático | htdocs em inglês, JS puro, feed global pela 9000, sem terceiros | 004, 005 | aprovada |
| [015-acme-certificados.md](015-acme-certificados.md) | ACME e certificados | certmagic, DNS-01 próprio, HTTP-01, recarga a quente, falhas | 005, 007 | aprovada |
| [016-infra-e-deploy.md](016-infra-e-deploy.md) | Infra, rede e deploy | finger-01, offloads, sysctls, units/hardening, limites e fatia, NATS, layout, `make deploy`, traefik do host | 001 | aprovada |
| [017-verificacao.md](017-verificacao.md) | Verificação e testes | verify quick/full, níveis de teste, matriz e2e, carga | 002, 016 | aprovada |
| [018-bot.md](018-bot.md) | Serviço bot | veredito e sinais, listas (base própria, ja4db, IPs), agregados de 7 dias, LGPD, CLI de chaves, banco em disco | 001, 004, 008, 010, 013, 019, 020 | aprovada (pendências P4–P6) |
| [019-requisitos-do-traefix.md](019-requisitos-do-traefix.md) | Integração com o traefix | o traefix (traefik modificado, projeto externo, consumido como está; ADRs 0054, 0062 e 0063): perfil de configuração, `X-Traefix-*`, lote `traefix.fingerprint/v1` e esquema copiado, visão TCP, leitura pelo bot, forwardAuth fail-open, sempre `latest`, métricas, custo, pedidos ao traefix, critérios de aceite | 001, 013, 018, 020 | aprovada |
| [020-api-de-vereditos.md](020-api-de-vereditos.md) | API de vereditos | 9002/9003, chaves, domínios, limites, forwardAuth, consulta, probe, feed, webhook | 018, 019 | aprovada |
| [PLAN.md](PLAN.md) | Plano de implementação | regra das fases, fase atual, tabela de pendências abertas | todas | aprovada |
| [PLAN-HISTORICO.md](PLAN-HISTORICO.md) | Histórico do plano | fases F1–F8 concluídas: frentes, critérios e saídas, PRs e medidas (fora do `@` do AGENTS.md) | PLAN | registro |

## Contratos e pastas auxiliares
| Caminho | Conteúdo |
| --- | --- |
| [../cmd/finger-sniffer-store/openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) | API HTTP (OpenAPI 3.1) |
| [../cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) | API de vereditos do bot (OpenAPI 3.1) |
| [../cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json](../cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json) | cópia do esquema do lote do traefix (ADR 0063) |
| [../eventbus/nats/asyncapi.yaml](../eventbus/nats/asyncapi.yaml) | eventos NATS (AsyncAPI 3.0) |
| [../eventbus/nats/nats.conf](../eventbus/nats/nats.conf) | configuração do NATS |
| [../database/sqlite/migrations/](../database/sqlite/migrations/) | migrations goose do store |
| `../database/sqlite/bot/` | migrations goose do bot (spec 018, task 267) |

## Templates
- Spec: ver qualquer spec acima (Status, Depende de, Contexto, Requisitos, Comportamento, Interfaces e contratos,
  Dados, Critérios de aceite, Fora de escopo, Decisões relacionadas).
- Tarefa (`./tasks/nnn-titulo.md`): front-matter `id`, `status` (aberta | em-andamento | bloqueada | em-revisao),
  `responsavel`, `fase`, `spec`, `depende-de`, `arquivos`; seções "O que fazer" e "Critérios de aceite"
  (incluindo "Definition of Done (specs/002) atendida").
- ADR (`./specs/decisions/nnnn-titulo.md`): Status (aceita | provisória (revisar se …) | substituída por nnnn),
  Data, Contexto, Decisão, Alternativas consideradas, Consequências.
