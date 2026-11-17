Janela 2026-11-17T06:12:30Z → 2026-11-17T06:13:47Z, 94253 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 15400 | 0 | 15400 | 0 | 0.43 / 0.60 / 0.77 / 3.9 |
| consulta GET /verdict | 1552 | 0 | 0 | 0 | 0.21 / 0.30 / 0.41 / 1.6 |
| feed (todas as requisições) | 15400 | 0 | 53547 | 0 | 0.44 / 0.61 / 0.76 / 3.9 |
| feed (primeira requisição da conexão) | 3579 | 0 | 3579 | 0 | 0.44 / 0.61 / 0.76 / 2.6 |
| ingest (flag = registros) | 1540 | 0 | 19285 | 0 | 1.32 / 2.01 / 2.49 / 7.1 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 60361 | 0 | 3536 | 0 | 52.23 / 267.60 / 327.33 / 418.2 |
| feed global do store, sem o connection.updated do raw | 56825 | 0 | 0 | 0 | 52.96 / 272.52 / 329.06 / 418.2 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 06:12 | 6000 | 0 | 6000 | 0.59 / 0.76 / 3.3 |
| 06:13 | 9400 | 0 | 9400 | 0.60 / 0.77 / 3.9 |

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-pre-hostil.json → tmp/load/raw/f8/main/ha-pre-hostil.json):

```json
{
  "auth": 15000,
  "auth_ja4h": {
    "header": 15000,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9501900380076015,
  "auth_p99_ms": 0.9901980396079216,
  "auth_le_10ms": 1,
  "auth_le_50ms": 1,
  "wait_p95_ms": 0.95,
  "wait_p99_ms": 0.99,
  "wait_sum_ms": 135.31637999998526,
  "auth_sum_ms": 1998.5400639996983,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 0,
    "count": 0
  },
  "index_bytes_after": 34030029,
  "ingest_records": 18783,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 40717
}
```

bot_auth_ja4h_total{source="header"} Δ 15000 contra 15400 forwardAuth 200 do cliente na janela das amostras.
