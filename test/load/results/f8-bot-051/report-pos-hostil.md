Janela 2026-11-18T23:20:10Z → 2026-11-18T23:28:09Z, 138920 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 35964 | 0 | 35958 | 0 | 0.44 / 0.78 / 41.73 / 105.1 |
| consulta GET /verdict | 3580 | 0 | 0 | 0 | 0.21 / 0.32 / 0.53 / 45.7 |
| feed (todas as requisições) | 35964 | 0 | 122449 | 0 | 0.44 / 0.78 / 41.81 / 105.3 |
| feed (primeira requisição da conexão) | 7659 | 0 | 7659 | 0 | 0.45 / 1.74 / 47.52 / 101.4 |
| ingest (flag = registros) | 3576 | 0 | 43441 | 0 | 1.50 / 2.96 / 62.61 / 96.0 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 59836; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 23:20 | 10000 | 0 | 9998 | 0.77 / 36.57 / 101.4 |
| 23:21 | 12000 | 0 | 11996 | 1.11 / 46.54 / 100.9 |
| 23:22 | 12000 | 0 | 12000 | 0.73 / 42.24 / 105.1 |
| 23:23 | 1948 | 0 | 1948 | 0.57 / 8.46 / 67.3 |
| 23:25 | 16 | 0 | 16 | 0.71 / 0.71 / 0.7 |

Métricas do bot (heartbeat, ha-hostile.json → ha-recovery.json):

```json
{
  "auth": 35196,
  "auth_ja4h": {
    "header": 35196,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 0,
    "h2/ingest": 35196,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 6,
    "tcp/store": 35190,
    "tls/header": 0,
    "tls/ingest": 35196,
    "tls/none": 0,
    "tls/store": 0
  },
  "ingest_fingerprint_mismatch": {
    "akamai": 0,
    "ja3": 0,
    "ja3n": 0,
    "ja4": 0,
    "ja4o": 0,
    "ja4r": 0,
    "ja4t": 0
  },
  "auth_p95_ms": 0.9579475131790053,
  "auth_p99_ms": 0.9982821453128582,
  "auth_le_10ms": 0.9958518013410614,
  "auth_le_50ms": 0.9997727014433458,
  "wait_p95_ms": 0.9504860992665871,
  "wait_p99_ms": 0.9905065666041275,
  "wait_sum_ms": 1662.3951130001942,
  "auth_sum_ms": 9362.863913000965,
  "view_wait": {
    "fork": 0,
    "tcp": 6
  },
  "evicted": {
    "bytes": 1951,
    "count": 0
  },
  "index_bytes_after": 402591067,
  "ingest_records": 42477,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 84293
}
```

bot_auth_ja4h_total{source="header"} Δ 35196 contra 35964 forwardAuth 200 do cliente na janela das amostras.
