Janela 2026-11-18T23:18:11Z → 2026-11-18T23:20:10Z, 52328 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 23800 | 0 | 23799 | 0 | 0.46 / 11.41 / 52.47 / 149.6 |
| consulta GET /verdict | 2371 | 0 | 0 | 0 | 0.22 / 0.45 / 1.20 / 57.2 |
| feed (todas as requisições) | 23800 | 0 | 71068 | 0 | 0.46 / 11.46 / 52.47 / 149.6 |
| feed (primeira requisição da conexão) | 5809 | 0 | 5809 | 0 | 0.46 / 11.41 / 52.50 / 92.3 |
| ingest (flag = registros) | 2357 | 0 | 29744 | 0 | 1.75 / 12.68 / 65.62 / 167.7 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 23:18 | 9800 | 0 | 9800 | 0.81 / 21.80 / 71.7 |
| 23:19 | 12000 | 0 | 11999 | 21.39 / 57.12 / 100.5 |
| 23:20 | 2000 | 0 | 2000 | 41.24 / 73.36 / 149.6 |

Métricas do bot (heartbeat, hb-hostile.json → ha-hostile.json):

```json
{
  "auth": 25000,
  "auth_ja4h": {
    "header": 25000,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 0,
    "h2/ingest": 25000,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 1,
    "tcp/store": 24999,
    "tls/header": 0,
    "tls/ingest": 25000,
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
  "auth_p95_ms": 0.968557562905265,
  "auth_p99_ms": 3.4765625,
  "auth_le_10ms": 0.9946,
  "auth_le_50ms": 0.99804,
  "wait_p95_ms": 0.9585502683940752,
  "wait_p99_ms": 0.9989102796948783,
  "wait_sum_ms": 4368.47679999979,
  "auth_sum_ms": 11037.021976999797,
  "view_wait": {
    "fork": 0,
    "tcp": 1
  },
  "evicted": {
    "bytes": 27859,
    "count": 0
  },
  "index_bytes_after": 402580608,
  "ingest_records": 193762,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 71127
}
```

bot_auth_ja4h_total{source="header"} Δ 25000 contra 23800 forwardAuth 200 do cliente na janela das amostras.
