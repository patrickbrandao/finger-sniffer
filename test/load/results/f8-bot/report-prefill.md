Janela 2026-11-17T05:39:40Z → 2026-11-17T05:48:18Z, 632206 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 103600 | 0 | 103600 | 0 | 0.43 / 0.63 / 0.96 / 79.3 |
| consulta GET /verdict | 10515 | 0 | 0 | 0 | 0.21 / 0.30 / 0.43 / 14.1 |
| feed (todas as requisições) | 103600 | 0 | 319674 | 0 | 0.43 / 0.62 / 0.95 / 79.4 |
| feed (primeira requisição da conexão) | 25716 | 0 | 25716 | 0 | 0.43 / 0.63 / 0.95 / 69.0 |
| ingest (flag = registros) | 10360 | 0 | 129501 | 0 | 1.38 / 2.00 / 2.65 / 72.8 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 404131 | 0 | 23162 | 0 | 52.46 / 267.84 / 327.96 / 598.1 |
| feed global do store, sem o connection.updated do raw | 380969 | 0 | 0 | 0 | 53.18 / 272.90 / 329.14 / 598.1 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 05:39 | 4000 | 0 | 4000 | 0.69 / 0.95 / 16.8 |
| 05:40 | 12000 | 0 | 12000 | 0.68 / 1.04 / 14.5 |
| 05:41 | 12000 | 0 | 12000 | 0.60 / 0.93 / 14.4 |
| 05:42 | 12000 | 0 | 12000 | 0.62 / 0.92 / 13.4 |
| 05:43 | 12000 | 0 | 12000 | 0.62 / 0.84 / 6.3 |
| 05:44 | 12000 | 0 | 12000 | 0.63 / 0.87 / 14.3 |
| 05:45 | 12000 | 0 | 12000 | 0.62 / 0.88 / 54.4 |
| 05:46 | 12000 | 0 | 12000 | 0.64 / 5.37 / 79.3 |
| 05:47 | 12000 | 0 | 12000 | 0.60 / 0.87 / 54.3 |
| 05:48 | 3600 | 0 | 3600 | 0.60 / 0.98 / 45.5 |

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-prefill.json → tmp/load/raw/f8/main/ha-prefill.json):

```json
{
  "auth": 103000,
  "auth_ja4h": {
    "header": 103000,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9509879194891782,
  "auth_p99_ms": 0.9910295160992487,
  "auth_le_10ms": 0.9998932038834951,
  "auth_le_50ms": 0.9999902912621359,
  "wait_p95_ms": 0.950119918047909,
  "wait_p99_ms": 0.9901249672288736,
  "wait_sum_ms": 1098.0162959999973,
  "auth_sum_ms": 14605.486505000234,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 0,
    "count": 0
  },
  "index_bytes_after": 219399722,
  "ingest_records": 128751,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 278035
}
```

bot_auth_ja4h_total{source="header"} Δ 103000 contra 103600 forwardAuth 200 do cliente na janela das amostras.
