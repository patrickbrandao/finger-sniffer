Janela 2026-11-25T02:42:06Z → 2026-11-25T02:44:06Z, 52788 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 24000 | 0 | 23996 | 0 | 0.45 / 9.23 / 53.99 / 146.7 |
| consulta GET /verdict | 2412 | 0 | 0 | 0 | 0.20 / 0.40 / 1.25 / 83.1 |
| feed (todas as requisições) | 24000 | 0 | 72391 | 0 | 0.45 / 9.26 / 54.05 / 146.8 |
| feed (primeira requisição da conexão) | 5862 | 0 | 5862 | 0 | 0.45 / 11.09 / 49.63 / 100.4 |
| ingest (flag = registros) | 2376 | 0 | 30001 | 0 | 1.76 / 19.26 / 70.72 / 86.1 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 02:42 | 10800 | 0 | 10800 | 1.03 / 29.77 / 84.7 |
| 02:43 | 12000 | 0 | 11996 | 18.53 / 60.11 / 146.7 |
| 02:44 | 1200 | 0 | 1200 | 36.08 / 65.35 / 95.9 |

Métricas do bot (heartbeat, e320g50-hb.json → e320g50-ha.json):

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
    "tcp/none": 4,
    "tcp/store": 24996,
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
  "auth_p95_ms": 0.9721255781588966,
  "auth_p99_ms": 10.23529411764706,
  "auth_le_10ms": 0.98992,
  "auth_le_50ms": 0.99684,
  "wait_p95_ms": 0.959440898440656,
  "wait_p99_ms": 0.9998384099539467,
  "wait_sum_ms": 7128.674018000016,
  "auth_sum_ms": 15138.566996000103,
  "view_wait": {
    "fork": 0,
    "tcp": 4
  },
  "evicted": {
    "bytes": 32164,
    "count": 0
  },
  "index_bytes_after": 335514508,
  "ingest_records": 193775,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 65492
}
```

bot_auth_ja4h_total{source="header"} Δ 25000 contra 24000 forwardAuth 200 do cliente na janela das amostras.
