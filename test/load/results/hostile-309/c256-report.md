Janela 2026-11-25T02:22:28Z → 2026-11-25T02:24:28Z, 52860 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 24000 | 0 | 23996 | 0 | 0.45 / 0.84 / 26.97 / 101.4 |
| consulta GET /verdict | 2461 | 0 | 0 | 0 | 0.21 / 0.38 / 0.74 / 25.9 |
| feed (todas as requisições) | 24000 | 0 | 70057 | 0 | 0.45 / 0.82 / 27.04 / 101.4 |
| feed (primeira requisição da conexão) | 5899 | 0 | 5899 | 0 | 0.45 / 0.82 / 26.82 / 101.4 |
| ingest (flag = registros) | 2399 | 0 | 30003 | 0 | 1.74 / 3.40 / 42.51 / 94.4 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 02:22 | 6400 | 0 | 6400 | 0.72 / 6.18 / 73.1 |
| 02:23 | 11999 | 0 | 11995 | 0.86 / 26.64 / 101.4 |
| 02:24 | 5601 | 0 | 5601 | 1.61 / 41.21 / 80.0 |

Métricas do bot (heartbeat, c256-hb.json → c256-ha.json):

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
    "tcp/none": 5,
    "tcp/store": 24995,
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
  "auth_p95_ms": 0.9604496926560984,
  "auth_p99_ms": 1.2650602409638554,
  "auth_le_10ms": 0.9968,
  "auth_le_50ms": 0.99952,
  "wait_p95_ms": 0.9520564419145354,
  "wait_p99_ms": 0.9921430289425159,
  "wait_sum_ms": 1970.6698330000227,
  "auth_sum_ms": 7305.055029999977,
  "view_wait": {
    "fork": 0,
    "tcp": 5
  },
  "evicted": {
    "bytes": 34147,
    "count": 0
  },
  "index_bytes_after": 268387202,
  "ingest_records": 194454,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 67667
}
```

bot_auth_ja4h_total{source="header"} Δ 25000 contra 24000 forwardAuth 200 do cliente na janela das amostras.
