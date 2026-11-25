Janela 2026-11-25T02:12:51Z → 2026-11-25T02:14:51Z, 52769 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 24000 | 0 | 24000 | 0 | 0.46 / 1.11 / 37.00 / 91.8 |
| consulta GET /verdict | 2370 | 0 | 0 | 0 | 0.21 / 0.41 / 0.90 / 59.8 |
| feed (todas as requisições) | 24000 | 0 | 73303 | 0 | 0.46 / 1.13 / 37.19 / 91.8 |
| feed (primeira requisição da conexão) | 5851 | 0 | 5851 | 0 | 0.47 / 1.21 / 41.73 / 76.8 |
| ingest (flag = registros) | 2399 | 0 | 29996 | 0 | 1.76 / 3.73 / 43.73 / 96.4 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 02:12 | 1800 | 0 | 1800 | 0.77 / 3.06 / 35.3 |
| 02:13 | 12000 | 0 | 12000 | 0.90 / 30.47 / 81.1 |
| 02:14 | 10200 | 0 | 10200 | 5.99 / 46.78 / 91.8 |

Métricas do bot (heartbeat, b320-hb.json → b320-ha.json):

```json
{
  "auth": 26000,
  "auth_ja4h": {
    "header": 26000,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 0,
    "h2/ingest": 26000,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 0,
    "tcp/store": 26000,
    "tls/header": 0,
    "tls/ingest": 26000,
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
  "auth_p95_ms": 0.9633761067124302,
  "auth_p99_ms": 1.8145161290322582,
  "auth_le_10ms": 0.995423076923077,
  "auth_le_50ms": 0.9993461538461539,
  "wait_p95_ms": 0.9547369641683738,
  "wait_p99_ms": 0.9949364152912529,
  "wait_sum_ms": 2958.0323159999875,
  "auth_sum_ms": 8759.4945320001,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 31927,
    "count": 0
  },
  "index_bytes_after": 335518408,
  "ingest_records": 195699,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 70112
}
```

bot_auth_ja4h_total{source="header"} Δ 26000 contra 24000 forwardAuth 200 do cliente na janela das amostras.
