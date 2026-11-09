# 0020 — Tempo real em memória, sem replay, com descarte por cliente

Status: aceita
Data: 2026-11-09

## Contexto
A F4 liga `GET /api/v1/stream` (SSE) e `GET /api/v1/ws` (WebSocket) da spec 004 RF-08 e a página do htdocs mostra o
feed global. A API é aberta (ADR 0007) e o store roda num 1 vCPU com `MemoryMax=384M`; o ingest não pode esperar
por cliente lento, e o evento ao vivo tem de chegar em < 1 s (spec 004 RNF-01).

## Decisão
- O store publica eventos ao vivo **depois do commit** de cada lote do ingest (o que aparece no feed já está na
  consulta), num hub em memória; nada é persistido para o feed.
- **Sem replay**: o cliente recebe só eventos posteriores à conexão; sem `Last-Event-ID`. Para o passado, a API de
  consulta.
- Fila por cliente de `FS_LIVE_BUFFER` eventos (padrão 1024). Fila cheia: o evento é **descartado para aquele
  cliente** (o ingest nunca bloqueia), a contagem acumula e, quando houver espaço, o cliente recebe um
  `stream.dropped` com `dropped`. Métrica `fs_store_live_dropped_total`.
- Até `FS_LIVE_MAX_CLIENTS` (padrão 64) clientes simultâneos, SSE + WS; acima disso, 503.
- `connection.updated` é agregado: no máximo um por conexão a cada 250 ms (o último estado vale).
- Filtros (`probe`, `src_ip`, `dst_port`, `kind`) aplicados no store antes de enfileirar.
- WebSocket com `coder/websocket` (ADR 0009); SSE com `net/http`.

## Alternativas consideradas
- Consumidor JetStream por cliente: replay de graça, mas um consumidor por visitante no NATS de 192M e eventos
  crus (não o resumo da conexão).
- Bloquear o ingest até o cliente ler: um visitante lento travaria o espelho.
- Desconectar o cliente lento: pior para a página, que perderia tudo em vez de alguns eventos.

## Consequências
- O feed é "melhor esforço": sob carga, clientes lentos veem lacunas sinalizadas.
- Memória do hub limitada a `FS_LIVE_MAX_CLIENTS × FS_LIVE_BUFFER` resumos (~64 × 1024 × ~1 KiB = 64 MiB no pior
  caso; o hub guarda o JSON já serializado, uma vez por evento, compartilhado entre clientes).
