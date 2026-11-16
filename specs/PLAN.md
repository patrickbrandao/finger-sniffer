# Plano de implementação

Status: aprovada
Depende de: todas as specs

As fases F1–F5 rodaram no servidor de testes anterior (até a v0.2.x); a partir da F6 o servidor é o finger-01
(ADR 0038). Nomes, portas e limites citados nas fases antigas valem como registro do que foi entregue.

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
  - `make deploy` num servidor limpo sobe as 7 units; `GET http://<servidor>:9001/api/v1/health` mostra
    os 5 serviços `ok`, offloads desligados e sysctls aplicados;
  - relatório do spike em `docs/dev/spike-carga.md` com CPU/RAM/latência a 200 conexões e 50 novas/s, e o
    architect atualizou as ADRs 0004/0005 (confirmadas como aceitas ou substituídas).

## F2 — Captura e store
- **Objetivo**: pacotes da interface capturada viram conexões com análise IP/TCP completa, pcap e API de consulta.
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
- **Critério de saída**: casos 1–5 e 7–10 passam no caminho direto; `curl` sem `-k` na zona dos probes e na
  API (9000); JA3/JA4/Akamai batem com tshark/FoxIO.

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
  - infra: UDP/QUIC no servidor, env do tempo real e smoke h3 (055);
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
    no servidor, depois de 065–067 e 073);
  - docs: `docs/` completas, receitas por caso e campos estáveis para o cliente, README de raiz (task 069);
  - infra: build reproduzível, `make release`, checklist, limpeza do repositório (task 070);
  - reviewer: auditoria spec × implementação de todas as specs e ADRs (task 071, depois de 065 e 069);
  - architect: release `v0.1.0` (task 072, depois de todas e das tarefas que a carga e a auditoria abrirem).
- **Comparação entre caminhos**: é do cliente (proxies, túneis); não há pendência externa para a release
  (ADR 0028).
- **Critério de saída**: os três itens de sucesso da spec 000 registrados no PR de release (item 1 pelo caminho
  direto, item 3 com o relatório `test/load/RESULTS.md`); nenhuma divergência aberta da auditoria; tag `v0.1.0`;
  CHANGELOG com a seção `[0.1.0]`.

## F6 — Migração para o finger-01 e v0.3.0
- **Objetivo**: o espelho no finger-01 (ADR 0038), com os limites e metas da ADR 0039, convivendo com o traefik do
  host, e a release `v0.3.0` do que está na `main`, testada lá.
- **Specs**: 000, 001, 002, 003, 004, 005, 007, 011, 014, 015, 016, 017.
- **Dependências**: v0.2.x e as tarefas da auditoria na `main`; o servidor anterior fica intocado.
- **Frentes** (tarefas 223–236):
  - architect: ADRs 0038 e 0039, specs e contratos documentais (223) → release `v0.3.0` (236, no fim);
  - infra: hosts, zona, portas, env, CI e verify (224) ‖ units, fatia, limites, sysctl, rede `ens192` e NATS
    (225) → deploy limpo no finger-01, certificado A e smoke, servidor pronto (231, depois de 224–230) → rota do
    traefik e certificado B por TLS-ALPN-01 (232);
  - implementer-web (226), implementer-dns (227), implementer-store (228), implementer-raw (229),
    implementer-capture (230): padrões de portas, zona, certificados, HTTPS RR, limites;
  - docs: `docs/`, `htdocs/`, README sem o servidor anterior (233);
  - tester: e2e, golden e carga apontando para o finger-01, matriz direta (234) → carga de verificação do
    orçamento do web (215) e carga oficial 200/50 (235, ADR 0042), sozinhas no servidor.
- **Critério de saída**: matriz direta (13 casos) verde no finger-01; carga oficial 200/50 com as metas das ADRs
  0039 e 0042 (exceção aceita pelo humano: RNF-02 e RNF-04 não atingidos, limite conhecido da ADR 0043);
  carga do orçamento com as metas da ADR 0039 item 4 (task 215 fechada); `curl` sem `-k` em
  `https://<id>.finger-west-01.badblock.net.br:8443/`, `https://finger-01.badblock.net.br:9000/` e
  `https://finger-01.badblock.net.br/` (pelo traefik); nenhum script, spec ou doc com o servidor anterior como alvo;
  tag `v0.3.0`; CHANGELOG com a seção `[0.3.0]`.

## F7 — Escrita e vazão do ingest: metas a 200/50 e RNF-01 de volta a 400/100 (concluída em 2026-11-16)
- **Objetivo**: o store cumpre RNF-02 e RNF-04 no finger-01 (limite conhecido da v0.3.0, ADR 0043) e sustenta 400
  simultâneas e 100 novas/s com as metas da carga oficial, sem perda no stream, e uma ADR nova devolve o RNF-01 a
  400/100 (ADR 0042 item 5).
- **Specs**: 000, 004, 016, 017.
- **Dependências**: F6 (tag `v0.3.0`).
- **Frentes**: implementer-store: paradas do escritor por IO do disco (task 248, ADR 0043; primeiro, partindo do
  rascunho `ef6c2a9`) → diagnóstico e tratamento da vazão do ingest (task 246; mudanças de unit, limites, durabilidade
  ou ADR voltam ao architect; diagnóstico no PR #226) → banco do store em RAM (ADR 0045): infra: tmpfs e limites
  (task 254) ‖ implementer-store: pragmas, teto e tmpfs cheio, medida rápida a 100/400 (task 255) → tester: degraus 50/75/100 e carga oficial 400/100 com pré-aquecimento de 9 min
  (task 247).
- **Critério de saída**: limite conhecido da ADR 0043 resolvido (248, RNF-02 e RNF-04 a 200/50 no finger-01);
  carga 247 com todas as metas da ADR 0042 item 3 a 400/100, `fs_store_stream_lost_total`
  Δ 0 do pré-aquecimento ao fim; ADR nova com RNF-01 400/100; release seguinte.
- **Saída (2026-11-16)**: atendido. Tasks 248, 246, 254, 255 e 247 na `main` (PRs #226–#231). Carga `official-f7`
  (`test/load/RESULTS.md`, "finger-01, F7") a 400/100 com o banco em tmpfs: feed p95/p99 232/352 ms, registro p95
  TCP 193 / QUIC 188 ms, backlog máx 0,11 s, `stream_lost`/`db_full`/`oom_kill` Δ 0, RAM do store 2,4 de 6 GiB;
  degrau de 50/s com feed p99 379 ms e registro p95 229/234 ms (limite da ADR 0043 resolvido). As duas metas do
  gerador que falharam (135 erros de cliente em TCP IPv4, 2 720 puladas no teto do gerador) foram aceitas como do
  cliente pela ADR 0046, que devolve o RNF-01 a 400/100 (substitui a 0042) e registra a ressalva do gerador fora do
  Mac (task 256, baixa prioridade). Adendo da ADR 0045 com a reserva de espaço e o checkpoint por passo da task 255.
  Release `v0.4.0` em 2026-11-16 (task 258, PR #235), com a correção bloqueante da auditoria (task 259, PR #234).

## F8 — Detecção de bots oferecida por API e traefik modificado
- **Objetivo**: a análise do espelho identifica bots e é oferecida por API (forwardAuth do traefik, consulta pelo
  site, probe, feed e webhook) a sites próprios atrás do traefik do finger-01 e a clientes externos não comerciais com
  chave emitida pelo operador; o **traefix** (traefik modificado, projeto externo do humano, imagem
  `tmsoftbrasil/traefix`) entrega a visão de aplicação dos sites pelos requisitos da spec 019; agregados de 7 dias com
  LGPD (ADRs 0047–0056).
- **Specs**: 018 (bot), 019 (requisitos do traefix), 020 (API de vereditos); mudanças em 000, 001, 002, 003, 004,
  016, 017. Contratos: `cmd/finger-sniffer-bot/openapi.yaml` 0.1.1, asyncapi 0.6.1 (`fs.v1.store.connection`,
  métricas com rótulos no heartbeat); migrations 0001 e 0002 do bot.
- **Dependências**: F7 (tag `v0.4.0`). Nenhuma dependência nova no módulo do espelho. O traefix é do humano (ADR
  0054): o calendário dele não é deste plano, e a integração é por contrato.
- **Frentes**:
  - **Primeira onda (tasks 262, 267–270, 272, 274; concluída em 2026-11-16)**: infra 262 (#238), 269 (#244, bot
    implantado no finger-01, health com 6 serviços `ok`) e 272; implementer-bot 267 (#239, esqueleto, migration
    0001, CLI de chaves, 9002/9003, ingest e índice); implementer-store 268 (#241, `fs.v1.store.connection`); tester
    270 (#237, `known_clients.json`), 260 (#240) e 274 (#243). Ajustes na ADR 0055.
  - **Segunda onda (tasks 276–287, ADR 0056)**:
    - implementer-bot, em paralelo desde já, cada uma no seu pacote: regras v1 e famílias de UA em
      `internal/bot/rules` (276) ‖ fingerprints do ClientHello/h2 no ingest e resumo HTTP do store no índice (277) ‖
      listas — base própria, ja4db atrás de `FS_BOT_JA4DB_ENABLE=false` até a P4, listas de IP, verificação de robô,
      atualização diária, `list stale` (278) ‖ agregados de 7 dias, flush, teto de bytes e cache de comportamento em
      `internal/bot/agg` (279) ‖ webhook com HMAC e `webhook backlog` em `internal/bot/webhook` (280);
    - implementer-store: métricas com rótulos do heartbeat no `/metrics` (281, desde já);
    - implementer-bot: veredito nas rotas — forwardAuth, consulta, probe, `ip`, `fingerprints`, feed e webhook uma vez
      por requisição, métricas `verdicts_total{class,source}` e `auth_seconds` (282, depois de 276–280) → `forget`
      alcançando a memória e `lists refresh` por `control_requests` (migration 0002), `store feed silent` e
      conferência das métricas da RF-12 (283, depois de 278, 279 e 282);
    - tester: e2e da F8 do lado do bot — probe, traefix simulado com `TraefikIngestBatch` na 9002 e a origem vista
      pelo store, erros, feed, `forget`; casos do traefix real pulando até a 273 (284, depois de 282 e 283) → carga
      da F8, sozinha no finger-01 (285, depois de 281 e 284);
    - docs: `docs/bot.md`, guia de integração e verificação do webhook testada (286, depois de 280–282) → página de
      privacidade (287, bloqueada até P5 e P6).
  - **Traefix** (depende do humano): o humano implementa a spec 019 no projeto traefix e avisa → infra: teste da
    imagem num container à parte, troca do `traefik-app` em modo só observação e aceite (273, bloqueada até o aviso).
    Ligar forwardAuth ou `block` nos sites é ação do humano. h3 no traefix: segunda entrega do traefix (spec 019
    RF-13).
- **Critério de saída**: e2e da F8 verde (vereditos esperados de curl, Go, python-requests, Chrome, Firefox e
  Googlebot falso por probe e consulta e, com a 273 concluída, pelo router de teste do traefix; casamento traefix ↔
  store ≥ 99%; fail-open); carga da F8 com forwardAuth p95 ≤ 10 ms / p99 ≤ 50 ms a 200 req/s junto com a carga
  oficial 400/100 sem perder as metas da ADR 0046; expurgo de 7 dias comprovado com relógio falso; pendências P4–P6
  respondidas ou registradas no PR de release; tag `v0.5.0`. Se o traefix não estiver no finger-01 na hora da
  release, o architect escala ao humano (esperar ou lançar sem a visão do traefix).
- **Pendências para o humano** (detalhe na spec 018): P4 termos da ja4db; P5 base legal (LGPD); P6 controlador,
  encarregado e canal do titular. Respondidas em 2026-11-16 (ADR 0054): P1 e P2 (traefix externo), P3 (os dois
  casos de clientes externos), P7 (tráfego dos sites segue visível), P8 (troca só observando, task 273).
