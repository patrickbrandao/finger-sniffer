# 0001 — Decisões iniciais (agrupadas)

Status: aceita (endereços: ver 0023; meta de registro do QUIC: ver 0024)
Data: 2026-11-07

## Contexto
Entrevista de início de projeto sobre o documento "Servidor espelho de análise de conexões" e a missão inicial do
usuário. Decisões menores reunidas aqui; as significativas têm ADR própria (ver HISTORY.md).

## Decisão
- Nome `finger-sniffer` (binários, units, módulo Go); no servidor, `/finger-sniffer` ("finger-proxy" era engano).
- Produto genérico de análise de conexões; consumidor principal o go-xproxy; qualquer software pode consumir.
- O fingerproxy (wi1dcard) é só referência: portar fingerprints (JA3, JA3 raw, JA3N, JA4, JA4 stable, Akamai h2 com
  limite de PRIORITY), captura de ClientHello cru e frames h2, nomes legíveis, testes JA4 com pcaps FoxIO,
  recarga a quente de certificado e métricas Prometheus. Fora: modo reverse-proxy e atalho kube-probe.
- MVP inclui cabeçalhos/resposta, TLS+h2, TCP+keep-alive, DNS autoritativo e HTTP/3 (servir h3 + analisar Initial).
- Metas: 200 conexões simultâneas, 50 novas/s; evento ao vivo < 1 s; GET p95 < 100 ms; registro ≤ 500 ms após o fim.
- Fora de escopo: comparação entre caminhos, histórico/banco permanente, HA, contas de usuário.
- Equipe: 1 humano + agentes, sem prazo rígido.
- Página htdocs só em inglês, HTML + JS puro, sem build, sem CDN, sem cookies.
- Sucesso do MVP: matriz e2e + fingerprints conferidos com FoxIO/tshark + metas atingidas.
- Rotas web: `/p/<id>/`, `/r`, `?inline=1` para depuração; resto é htdocs.
- Tetos dos controles: idle 120 s (máx 600), delays 60 s, size 64 MiB, hsize 1 MiB, com marca `clamped`.
- Modos das portas cruas: 7 echo; 21/25/587/110/143/22 banner; 993 TLS + banner.
- DNS: A, AAAA, HTTPS, SOA, NS, TXT; rótulos `noh3`, `v4`, `v6`, `nodata`, `nx`; REFUSED fora da zona.
- Endereços: listeners só nos IPs públicos da eth0; NATS em 127.0.0.1.
- SemVer único do repositório, tag `vX.Y.Z`, versão via ldflags; envelope NATS com `schema_version`.
- Compatibilidade: `/api/v1` e `fs.v1.*` só aditivos; quebra → v2 convivendo ≥ 1 minor; migrations com down.
- Config: um env compartilhado `/finger-sniffer/etc/finger-sniffer.env`, prefixo `FS_`, `.env.example` versionado.
- Observabilidade: slog JSON, journald, Prometheus agregado na 9001, heartbeat 5 s, health por serviço; sem tracing
  e sem alertas externos.
- Ambiente único: vps602 (dev = teste); Mac para unidade e integração.
- Ameaças: tetos, fuzzing, DNS sem recursão + RRL, capabilities mínimas, govulncheck. **Sem limite de conexões
  por IP** (escolha do usuário).

## Alternativas consideradas
- Página bilíngue; limite de 100 conexões por IP; versão por serviço; "livre até 1.0" — rejeitadas pelo usuário.

## Consequências
- Sem limite por IP, um único cliente pode ocupar as 200 conexões; o modo degradado (spec 004 RF-11) é a defesa.
