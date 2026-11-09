# Plano de implementação

Status: aprovada
Depende de: todas as specs

Regra: uma fase só começa quando a anterior atinge o critério de saída. O architect cria as tarefas da fase
seguinte em `./tasks/` nesse momento. Frentes marcadas ‖ rodam em paralelo, cada uma em seu worktree.

## F1 — Fundação
- **Objetivo**: repositório, ferramentas, verificação em dois níveis, VPS preparada, contratos v0, biblioteca de
  detecção/probe e **validação de carga da arquitetura** (pacotes pelo NATS + BLOBs no SQLite) antes de construir
  em cima dela.
- **Specs**: 001, 002, 003 (RF-01..05), 004 (RF-01, RF-05), 016, 017.
- **Dependências**: nenhuma.
- **Frentes**:
  - infra: esqueleto do repo, go.mod, Makefile, lint, lefthook, GitHub (task 001) → verify.sh + CI (task 002)
    ‖ VPS: rede, units, NATS, deploy (task 003, depois de 001);
  - architect: contratos v0 — asyncapi, openapi, migration 0001 (task 004, desde o início);
  - implementer-web: `pkg/detect` e `pkg/probe` com fuzz (task 005, depois de 001);
  - implementer-store: `pkg/service`, `pkg/event`, store mínimo com health e heartbeat dos 5 stubs (task 007,
    depois de 001 e 004);
  - tester: spike de carga (task 006, depois de 003 e 004).
- **Critério de saída**:
  - `make verify-quick` e `make verify-full` funcionam; CI verde na `main`;
  - `make deploy` numa vps602 limpa sobe as 7 units; `GET http://vps602.tmsoft.com.br:9001/api/v1/health` mostra
    os 5 serviços `ok`, offloads desligados e sysctls aplicados;
  - relatório do spike em `docs/dev/spike-carga.md` com CPU/RAM/latência a 200 conexões e 50 novas/s, e o
    architect atualizou as ADRs 0004/0005 (confirmadas como aceitas ou substituídas).

## F2 — Captura e store
- **Objetivo**: pacotes da eth0 viram conexões com análise IP/TCP completa, pcap e API de consulta.
- **Specs**: 003, 004, 013.
- **Dependências**: F1.
- **Frentes**: implementer-capture (captura completa) ‖ implementer-store (ingest, correlação, retenção, API base,
  pcap, análise IP/TCP, p0f) ‖ tester (golden pcaps de curl/Go/Chrome/Firefox, teste de contrato da API).
- **Critério de saída**: `nc`/`curl` a qualquer porta aparecem em `GET /api/v1/connections` com SYN, JA4T, p0f,
  RTT e pcap válido no tshark; retenção de 10 min comprovada; JA4T bate com FoxIO.

## F3 — Protocolos
- **Objetivo**: web (detecção, TLS, HTTP/1, h2, WebSocket, controles, htdocs, ACME), raw e dns funcionando com
  certificado válido.
- **Specs**: 005, 006, 007, 008, 009, 010, 012, 015.
- **Dependências**: F2.
- **Frentes**: implementer-web (TLS/fingerprints → HTTP/1 → h2 → WS → ACME) ‖ implementer-raw ‖ implementer-dns
  (TXT ACME primeiro, para destravar o DNS-01) ‖ tester (casos 1–5, 7–10 da matriz contra caminho direto).
- **Critério de saída**: casos 1–5 e 7–10 passam no caminho direto; `curl` sem `-k` em `*.dns-monitor` e em
  `vps602:9000`; JA3/JA4/Akamai batem com tshark/FoxIO.

## F4 — HTTP/3, tempo real e site
- **Objetivo**: QUIC/h3, SSE/WS na API, página htdocs com feed global, métricas agregadas.
- **Specs**: 004 (RF-08..10), 011, 014.
- **Dependências**: F3.
- **Frentes** (tarefas 049–060, ADRs 0019 e 0020):
  - implementer-web: `pkg/quicparse` + JA4 `q` (049) → servidor h3, eventos, Alt-Svc (057, depois de 049, 051
    e 055);
  - implementer-store: ingest h3 e fim do QUIC (051) → tempo real SSE/WS (053) → métricas (054) ‖ long-poll
    `wait` (052);
  - implementer-dns: HTTPS RR conforme `FS_WEB_UDP_PORTS` (056);
  - infra: UDP/QUIC na vps602, env do tempo real e smoke h3 (055);
  - docs: página com feed global (058, depois de 053) ‖ docs/ de uso da API (059, depois de 052 e 053);
  - tester: golden de Initials QUIC (050, desde o início) → e2e da F4, casos 12 e 13 (060, no fim).
- **Critério de saída**: Chrome e Firefox usam h3 e veem o feed em < 1 s; `curl --http3-only` registrado com
  transport params; página sem recursos de terceiros.

## F5 — MVP
- **Objetivo**: provar a spec 000 (objetivos e RNF) no espelho e lançar `v0.1.0` (ADR 0022).
- **Specs**: 000, 005 (RF-07a), 017.
- **Dependências**: F4.
- **Frentes** (tarefas 065–073):
  - implementer-web: `Date` em h1/h3 e controle `date=0` (task 065, ADR 0021) → `h3_control_stream_seen`
    (task 073);
  - tester: matriz direta completa, casos 1–13 com 6 e 11 novos (task 066) ‖ conferência FoxIO/tshark consolidada
    de curl, Go, Chrome e Firefox (task 067) → carga de 10 min com as metas da ADR 0022 (task 068, sozinha na
    vps602, depois de 065–067 e 073);
  - docs: `docs/` completas, receitas por caso e campos estáveis para o cliente, README de raiz (task 069);
  - infra: build reproduzível, `make release`, checklist, limpeza do repositório (task 070);
  - reviewer: auditoria spec × implementação de todas as specs e ADRs (task 071, depois de 065 e 069);
  - architect: release `v0.1.0` (task 072, depois de todas e das tarefas que a carga e a auditoria abrirem).
- **Comparação entre caminhos**: é do cliente (proxies, túneis); não há pendência externa para a release
  (ADR 0028).
- **Critério de saída**: os três itens de sucesso da spec 000 registrados no PR de release (item 1 pelo caminho
  direto, item 3 com o relatório `test/load/RESULTS.md`); nenhuma divergência aberta da auditoria; tag `v0.1.0`;
  CHANGELOG com a seção `[0.1.0]`.
