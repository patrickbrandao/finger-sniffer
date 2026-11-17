Janela 2026-11-17T06:15:49Z → 2026-11-17T06:18:22Z, 186972 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 30600 | 0 | 30600 | 0 | 0.44 / 0.74 / 39.21 / 191.4 |
| consulta GET /verdict | 2990 | 0 | 0 | 0 | 0.22 / 0.33 / 0.62 / 73.6 |
| feed (todas as requisições) | 30600 | 0 | 89421 | 0 | 0.45 / 0.73 / 39.24 / 191.4 |
| feed (primeira requisição da conexão) | 7637 | 0 | 7637 | 0 | 0.45 / 0.80 / 39.76 / 117.4 |
| ingest (flag = registros) | 3042 | 0 | 38288 | 0 | 1.41 / 2.42 / 25.53 / 192.9 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 119740 | 0 | 6919 | 0 | 51.88 / 266.90 / 326.84 / 592.0 |
| feed global do store, sem o connection.updated do raw | 112821 | 0 | 0 | 0 | 52.57 / 271.72 / 328.25 / 592.0 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 06:15 | 2200 | 0 | 2200 | 0.70 / 36.13 / 86.8 |
| 06:16 | 12000 | 0 | 12000 | 0.68 / 32.02 / 171.4 |
| 06:17 | 12000 | 0 | 12000 | 0.96 / 48.88 / 191.4 |
| 06:18 | 4400 | 0 | 4400 | 0.70 / 30.96 / 86.4 |

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-pos-hostil.json → tmp/load/raw/f8/main/ha-pos-hostil.json):

```json
{
  "auth": 31000,
  "auth_ja4h": {
    "header": 31000,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9588461288011981,
  "auth_p99_ms": 0.9992185973823012,
  "auth_le_10ms": 0.9939354838709678,
  "auth_le_50ms": 0.9981290322580645,
  "wait_p95_ms": 0.9501225964640598,
  "wait_p99_ms": 0.9901277584204414,
  "wait_sum_ms": 462.60606199995726,
  "auth_sum_ms": 12723.079813999966,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 1984,
    "count": 0
  },
  "index_bytes_after": 402625919,
  "ingest_records": 38700,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 83212
}
```

bot_auth_ja4h_total{source="header"} Δ 31000 contra 30600 forwardAuth 200 do cliente na janela das amostras.
