Janela 2026-11-17T06:13:47Z → 2026-11-17T06:15:49Z, 149128 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 24400 | 0 | 24400 | 0 | 0.45 / 1.84 / 44.84 / 86.1 |
| consulta GET /verdict | 2461 | 0 | 0 | 0 | 0.22 / 0.38 / 0.91 / 77.9 |
| feed (todas as requisições) | 24400 | 0 | 73374 | 0 | 0.45 / 1.85 / 44.97 / 87.0 |
| feed (primeira requisição da conexão) | 5927 | 0 | 5927 | 0 | 0.45 / 1.36 / 39.92 / 73.6 |
| ingest (flag = registros) | 2426 | 0 | 30497 | 0 | 1.49 / 5.47 / 69.92 / 77.3 |
| ingest hostil (flag = aceitos) | 239 | 0 | 162520 | 0 | 93.14 / 230.31 / 240.97 / 253.9 |
| feed global do store no finger-01 | 95202 | 0 | 5422 | 0 | 53.60 / 269.59 / 330.86 / 579.3 |
| feed global do store, sem o connection.updated do raw | 89780 | 0 | 0 | 0 | 54.24 / 274.12 / 331.97 / 579.3 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 06:13 | 2600 | 0 | 2600 | 0.70 / 1.25 / 4.7 |
| 06:14 | 12000 | 0 | 12000 | 0.88 / 26.41 / 80.3 |
| 06:15 | 9800 | 0 | 9800 | 19.20 / 55.35 / 86.1 |

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-hostile.json → tmp/load/raw/f8/main/ha-hostile.json):

```json
{
  "auth": 24000,
  "auth_ja4h": {
    "header": 24000,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9648751586965721,
  "auth_p99_ms": 2.0891089108910825,
  "auth_le_10ms": 0.995875,
  "auth_le_50ms": 0.999,
  "wait_p95_ms": 0.955894683883951,
  "wait_p99_ms": 0.9961428811001175,
  "wait_sum_ms": 2634.9314959999783,
  "auth_sum_ms": 7940.29522700054,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 27173,
    "count": 0
  },
  "index_bytes_after": 402592820,
  "ingest_records": 192520,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 65392
}
```

bot_auth_ja4h_total{source="header"} Δ 24000 contra 24400 forwardAuth 200 do cliente na janela das amostras.
