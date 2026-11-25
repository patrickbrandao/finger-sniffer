Janela 2026-11-25T02:03:28Z → 2026-11-25T02:05:27Z, 52420 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 23800 | 0 | 23800 | 0 | 0.46 / 2.48 / 43.16 / 99.9 |
| consulta GET /verdict | 2467 | 0 | 0 | 0 | 0.21 / 0.41 / 0.90 / 99.4 |
| feed (todas as requisições) | 23800 | 0 | 71766 | 0 | 0.45 / 2.48 / 43.35 / 100.0 |
| feed (primeira requisição da conexão) | 5845 | 0 | 5845 | 0 | 0.46 / 6.88 / 47.46 / 100.0 |
| ingest (flag = registros) | 2353 | 0 | 29750 | 0 | 1.77 / 4.09 / 54.65 / 64.1 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 02:03 | 6400 | 0 | 6400 | 0.70 / 3.49 / 86.6 |
| 02:04 | 12000 | 0 | 12000 | 2.31 / 38.41 / 99.9 |
| 02:05 | 5400 | 0 | 5400 | 23.08 / 62.15 / 99.0 |

Métricas do bot (heartbeat, a384-hb.json → a384-ha.json):

```json
{
  "auth": 23991,
  "auth_ja4h": {
    "header": 23991,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 0,
    "h2/ingest": 23991,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 0,
    "tcp/store": 23991,
    "tls/header": 0,
    "tls/ingest": 23991,
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
  "auth_p95_ms": 0.9626393816523061,
  "auth_p99_ms": 1.6645132743362845,
  "auth_le_10ms": 0.996873827685382,
  "auth_le_50ms": 0.9989996248593223,
  "wait_p95_ms": 0.9544957701650055,
  "wait_p99_ms": 0.9946850657509005,
  "wait_sum_ms": 2724.9861980000005,
  "auth_sum_ms": 7803.182409000011,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 28691,
    "count": 0
  },
  "index_bytes_after": 402580787,
  "ingest_records": 187052,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 63495
}
```

bot_auth_ja4h_total{source="header"} Δ 23991 contra 23800 forwardAuth 200 do cliente na janela das amostras.
