# 0016 — Stream FS_EVENTS em memória e mais memória para o NATS

Status: aceita
Data: 2026-11-07

## Contexto
O spike de carga (task 006, `docs/dev/spike-carga.md`) mostrou, a 50 conexões novas/s na vps602:
- com o stream `FS_EVENTS` em arquivo (ADR 0003), travamentos de disco de ~2 s (iowait até 98%) entre o NATS e o
  store, com ingestão p95 de 1,0–1,8 s — acima da meta de 1 s (spec 000 RNF-02);
- com o stream em memória e todo o resto igual, ingestão p95 de 178 ms, p99 de 203 ms, iowait ~1%;
- commits do SQLite curtos em ambos os casos (máx. 36 ms): o gargalo era o file store do JetStream;
- RSS do nats-server de 118–124 MiB nas duas configurações, colado no `MemoryMax=128M` da unit.

## Decisão
- O stream `FS_EVENTS` (`fs.v1.>`) usa **`MemoryStorage`**, `max_bytes` **32 MiB**, `max_age` 60 s, `DiscardOld`,
  consumidor durável `store`. Substitui, na ADR 0003, os 64 MiB e o armazenamento implícito em arquivo.
  (Subjects do stream substituídos pela ADR 0017: lista explícita de eventos, request/reply fora.)
- `nats.conf`: `max_memory_store` 64 MB (folga sobre os 32 MiB do stream); `max_file_store` mantido para uso futuro.
- Unit `finger-sniffer-nats`: `MemoryMax` **192M** e `GOMEMLIMIT` 170MiB (substitui os 128M da ADR 0005 e da spec 016).
- O resto das ADRs 0003, 0004 e 0005 continua valendo.

## Alternativas consideradas
- Manter arquivo e ajustar `sync_interval`/disco separado — a VPS tem um só disco; o travamento vinha da própria
  escrita do file store.
- Stream em memória de 64 MiB — mais folga se o store parar, mas exigiria ainda mais `MemoryMax` no NATS.
- Tirar o JetStream e usar NATS core — perde a retenção durante reinícios do store.

## Consequências
- Reiniciar o store continua sem perda (o stream segue no NATS).
- Reiniciar o próprio NATS perde até 60 s de eventos ainda não consumidos; o buffer de 30 s dos produtores (ADR 0003)
  cobre a queda do NATS. Aceitável com retenção de 10 min num servidor de testes.
- 32 MiB a ~1,8 MB/s de pacotes (50/s) dão ~17 s de folga com o store parado; depois o NATS descarta os mais antigos.
- O NATS passa a poder usar até 192M dos 967 MiB da VPS.
