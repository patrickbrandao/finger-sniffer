# 0003 — NATS local com JetStream

Status: aceita
Data: 2026-11-07

## Contexto
Os cinco serviços precisam entregar eventos ao store e o store precisa empurrar tempo real; reinícios do store
não podem perder eventos.

## Decisão
- NATS server oficial (binário fixado com checksum, `/finger-sniffer/bin/nats-server`), em 127.0.0.1:4222,
  unit `finger-sniffer-nats.service`, config em `eventbus/nats/nats.conf`.
- Subjects `fs.v1.<origem>.<tipo>`; contrato em `eventbus/nats/asyncapi.yaml`.
- JetStream: stream `FS_EVENTS` (`fs.v1.>`), `max_age` 60 s, `max_bytes` 64 MiB, consumidor durável `store`.
  (Armazenamento e tamanho do stream substituídos pela ADR 0016: em memória, 32 MiB. Subjects do stream
  substituídos pela ADR 0017: lista explícita de eventos, request/reply fora.)
- Produtores: se o NATS cair, buffer em memória até 30 s / 16 MiB, depois descartam e contam `dropped_events_total`.

## Alternativas consideradas
- Socket Unix direto ao store (recomendado: zero dependência, menos RAM) — rejeitado pelo usuário.
- Valkey streams; NATS embutido no store; pacote Debian 2.10.27; NATS sem JetStream.

## Consequências
- Mais uma unit para operar (~20–60 MB RAM).
- Novos consumidores podem assinar sem mudar produtores.
