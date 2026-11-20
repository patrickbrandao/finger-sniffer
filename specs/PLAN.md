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

## F8 — Detecção de bots oferecida por API e traefik modificado (concluída em 2026-11-17, sem o traefix)
- **Objetivo**: a análise do espelho identifica bots e é oferecida por API (forwardAuth do traefik, consulta pelo
  site, probe, feed e webhook) a sites próprios atrás do traefik do finger-01 e a clientes externos não comerciais com
  chave emitida pelo operador; o **traefix** (traefik modificado, projeto externo do humano, imagem
  `tmsoftbrasil/traefix`) entrega a visão de aplicação dos sites pelos requisitos da spec 019; agregados de 7 dias com
  LGPD (ADRs 0047–0061).
- **Specs**: 018 (bot), 019 (requisitos do traefix), 020 (API de vereditos); mudanças em 000, 001, 002, 003, 004,
  016, 017. Contratos: `cmd/finger-sniffer-bot/openapi.yaml` 0.2.0 (era 0.1.1; ADR 0058), asyncapi 0.6.2 (`fs.v1.store.connection`,
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
    - implementer-bot, ajustes da ADR 0057 antes da 282: regras v1.1 — `ua_automation`, `library_client` e prova por
      lista para OpenAI/DuckDuckGo, goldens com as classes da ADR (289) ‖ teto de bytes do índice
      `FS_BOT_INDEX_MAX_BYTES`, `bot_index_bytes`, `conns_evicted_total{reason}` e `index bytes` no health (290);
    - implementer-bot: veredito nas rotas — forwardAuth, consulta, probe, `ip`, `fingerprints`, feed e webhook uma vez
      por requisição, métricas `verdicts_total{class,source}` e `auth_seconds`, `lists_version` real (282, depois de
      276–280, 289 e 290) → `forget`
      alcançando a memória e `lists refresh` por `control_requests` (migration 0002), `store feed silent` e
      conferência das métricas da RF-12 (283, depois de 278, 279, 282 e 290);
    - tester: e2e da F8 do lado do bot — probe, traefix simulado com `TraefikIngestBatch` na 9002 e a origem vista
      pelo store, erros, feed, `forget`; casos do traefix real pulando até a 273 (284, depois de 282 e 283) → carga
      da F8, sozinha no finger-01, com o trecho hostil do índice (285, depois de 281, 284 e 290; concluídas: 284 em
      #265, 285 em #268, com a meta de recuperação do health da ADR 0061) → probe h3 sem registro, 1 em 21 000
      (296, prioridade baixa, não bloqueia a release);
    - implementer-bot: `ja4h_library` sem `Origin`/`Referer` (rules `v1.3`), goldens do caminho do probe e e2e sem
      o veredito do probe no feed (295, ADR 0060; antes da 285);
    - docs: `docs/bot.md`, guia de integração e verificação do webhook testada (286, depois de 280–282) → página de
      privacidade (287, bloqueada até P5 e P6).
  - **Traefix** (depende do humano): o humano implementa a spec 019 no projeto traefix e avisa → infra: teste da
    imagem num container à parte, troca do `traefik-app` em modo só observação e aceite (273, bloqueada até o aviso).
    Ligar forwardAuth ou `block` nos sites é ação do humano. h3 no traefix: segunda entrega do traefix (spec 019
    RF-13).
  - **Traefix como está (depois da v0.5.0, ADR 0062)**: o humano avisou em 2026-11-18 que o traefix saiu
    (`fork-point-213-g5c011b2f3`) com formatos próprios; a spec 019 vira "Integração com o traefix" e o openapi do
    bot vai a 0.3.0 (aditivo). Frentes:
    - implementer-bot: ingest `traefix.fingerprint/v1` com ClientHello do QUIC e fingerprints prontas como reserva
      e visão TCP do traefix (302) → forwardAuth com `X-Traefix-*`, ALPN, JA4T e espera só do store (303; em série
      pelo `api.go`);
    - tester: e2e simulado e carga com o esquema novo (304, depois de 302 e 303);
    - docs: `docs/bot.md` e guia de integração com o perfil da spec 019 (305, depois de 302 e 303);
    - infra + tester: traefix (`latest`, digest e `sender` registrados) num container à parte no finger-01,
      router de teste, medida de CPU,
      lotes reais em `testdata` e casos `TestF8TraefixReal` (273, depois de 302–304, com deploy do bot antes);
    - infra: troca do `traefik-app` para a `latest`, só observando (306, depois da 273).
    Segunda entrega do traefix (`fork-point-218`, ADR 0063): `X-Traefix-*`, visão TCP, ALPN, prontas completas,
    esquema publicado; pedidos PT-01 a PT-09 entregues, PT-10 pedido.
    Decisão do humano (P9, 2026-11-18): sempre `traefix:latest` e os dois projetos andam juntos; necessidades novas
    viram pedidos `PT-nn` na spec 019.
    Critério: os da spec 019; release `v0.5.1` depois da 273 (a 306 não bloqueia a release).
    **Saída (2026-11-18)**: tasks 301–305, 273 e 307 na `main` (PRs #273–#280). Traefix real (`fork-point-218`)
    num container de teste no finger-01: JA4/Akamai/JA4T iguais aos do espelho, casamento traefix ↔ store 100%,
    `mismatch` Δ 0, PT-01..PT-09 entregues; CPU do bloco `fingerprint` +21–24% h1, +9–11% h2 (task 273,
    `docs/dev/traefix-finger-01.md`). Auditoria do reviewer sem bloqueante (achados corrigidos na task 307; fuzz na
    308). `verify-full --e2e` verde no finger-01. Carga da F8 com `traefix.fingerprint/v1`: janela oficial com todas as
    metas; trecho hostil acima da RNF-01 do bot no cliente (p95 11,4 / p99 52,5 ms), limite conhecido aceito pelo
    humano (ADR 0064, task 309). Release `v0.5.1`. Pendentes: 306 (espera o PT-12 por decisão do humano), 308, 309,
    pedidos PT-10..PT-15 ao traefix.
  - **Terceira entrega do traefix (`fork-point-223`, 2026-11-19, ADR 0065)**: tempos (relay), TTL em h3, cabeçalhos de
    detalhe. Frentes: architect (311: ADR 0065, specs, openapi 0.5.0, cópia do esquema) → implementer-bot (312: tempos,
    `relay_rtt_gap` em rules `v1.4`, TTL em h3 e no cabeçalho, ALPN pelo `00` do JA4, detalhe no `Fingerprints`) →
    infra + tester (313: traefix `latest` num container à parte com cliente direto e por relay SOCKS5, TTL em h3,
    PT-13/PT-14, lotes reais, e2e) → release `v0.5.2`. Baixa prioridade: 314 (TTL TCP × h3 e relay agregados por IP).
    **Saída (2026-11-19)**: tasks 311–313 na `main` (PRs #282–#284). Traefix `fork-point-223` num container de teste
    no finger-01: relay SOCKS5 com `rtt_gap` de 14,6–21,3 ms contra 3,8–4,6 ms no direto; `relay_rtt_gap` com os
    limiares do adendo da ADR 0065 em 35 de 50 conexões por relay e 2 de 40 diretas; TTL inicial em h3; 461 lotes sem
    recusa, `mismatch` Δ 0, casamento 100%; PT-13 entregue. Falso `ua_missing` de resumos sem cabeçalhos corrigido.
    Release `v0.5.2`. Pendentes: 306 (PT-12 e escolha do `headerDetail` pelo humano), 308, 309, 314, pedidos PT-10,
    PT-11, PT-12, PT-14, PT-16, PT-17, PT-18.
- **Critério de saída**: e2e da F8 verde (vereditos esperados de curl, Go, python-requests, Chrome, Firefox e
  Googlebot falso por probe e consulta e, com a 273 concluída, pelo router de teste do traefix; casamento traefix ↔
  store ≥ 99%; fail-open); carga da F8 com forwardAuth p95 ≤ 10 ms / p99 ≤ 50 ms a 200 req/s junto com a carga
  oficial 400/100 sem perder as metas da ADR 0046; expurgo de 7 dias comprovado com relógio falso; pendências P4–P6
  respondidas ou registradas no PR de release; tag `v0.5.0`. Se o traefix não estiver no finger-01 na hora da
  release, o architect escala ao humano (esperar ou lançar sem a visão do traefix).
- **Saída (2026-11-17)**: atendido do lado do bot; **lançada sem o traefix por decisão do humano** (escalonamento
  previsto no critério). Tasks 260–262, 267–272, 274–286 e 288–295 e 298 na `main` (PRs #236–#272). e2e da F8 (`TestF8Bot`, tasks
  284 e 295, PRs #265, #267 e #270) contra o finger-01: pelo probe curl, Go e python-requests `bot` 75 e o Googlebot
  falso `bot` 85 (`ja4h_library` normalizado, ADR 0060, + `tunnel_mss` do caminho; goldens sem o caminho 70/80),
  Chrome e Firefox `human` 0; traefix simulado (`TraefikIngestBatch` na 9002) com as classes esperadas nos 6 clientes
  e casamento traefix ↔ store 100/100; forwardAuth com `X-Fs-Ja4h` e `block`, erros sem `X-Fs-Verdict` (fail-open),
  feed em ≤ 1 s sem o veredito do probe, `forget`. Carga da F8 (task 285, PR #268, `test/load/RESULTS.md`,
  "finger-01, F8") a 200 forwardAuth/s junto da oficial 400/100: forwardAuth p95 0,62 / p99 1,62 ms no cliente,
  consulta p95 0,31 ms, veredito no feed ≤ 86 ms, `bot_auth_ja4h_total{source="header"}` = 318 217 requisições;
  metas da ADR 0046 no espelho com o bot assinando (backlog máx 0,07 s, `stream_lost`/`db_full` Δ 0, feed global p99
  327 ms), CPU do store igual com e sem o bot; trecho hostil com o índice no teto de 384 MiB, sem OOM (`anon` 733 MiB),
  forwardAuth p99 44,8 ms e health de volta a `ok` em 7 min 23 s, dentro da meta da ADR 0061 (`FS_BOT_CONN_TTL` +
  60 s). Expurgo de 7 dias com relógio falso em `TestForgetAndPurge` (`internal/bot`). Auditoria do reviewer: o bloqueante (uma chave escrevia em site de outra pelo ingest) e os ajustes de retenção ≤ 7 d 1 h e campos por lista permitida corrigidos na task 298 (PR #272); `forget` sem limpar a fila do webhook (task 299) e `control_requests` na privacidade do `docs/bot.md` (task 300, adendo da ADR 0052 já feito) ficam para depois, não bloqueantes. Release `v0.5.0` (task 297).
  **Pendente na release**:
  - task 273 (traefix real no finger-01, router de teste e casos `TestF8TraefixReal`): o aviso do humano veio em
    2026-11-18 (ADR 0062); refeita com o perfil novo, depois das 302–304; o critério "pelo router de teste do
    traefix" fica para quando ela sair;
  - P4 (termos da ja4db; `FS_BOT_JA4DB_ENABLE=false`), P5 (base legal, LGPD) e P6 (controlador, encarregado e canal
    do titular): sem resposta, registradas no PR de release; task 287 (página de privacidade) bloqueada até P5 e P6;
  - task 296 (probe h3 sem registro, 1 em 21 000 na carga da F8), prioridade baixa;
  - task 256 (gerador de carga fora do Mac, ressalva da ADR 0046), prioridade baixa;
  - task 221 (carga contra o teto da tabela de fluxos do store), bloqueada com o humano;
  - questão aberta ao humano: no modo `block`, o 403 do forwardAuth devolve o corpo `Verdict` completo (ADR 0051
    item 1: classe, score e sinais) ao visitante bloqueado; manter assim ou responder com corpo mínimo é decisão
    dele, por nova ADR, antes de ligar `block` nos sites.
- **Pendências para o humano** (detalhe na spec 018): P4 termos da ja4db; P5 base legal (LGPD); P6 controlador,
  encarregado e canal do titular. Respondidas em 2026-11-16 (ADR 0054): P1 e P2 (traefix externo), P3 (os dois
  casos de clientes externos), P7 (tráfego dos sites segue visível), P8 (troca só observando, task 273).
  P9 respondida em 2026-11-18 (ADR 0062 itens 7–9): sempre `tmsoftbrasil/traefix:latest`, base RC e custo de CPU
  aceitos, os dois projetos andam juntos.
