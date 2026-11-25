Janela 2026-11-25T02:31:57Z → 2026-11-25T02:33:57Z, 52806 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 24000 | 0 | 23708 | 0 | 0.46 / 3.51 / 100.50 / 169.0 |
| consulta GET /verdict | 2407 | 5 | 0 | 0 | 0.21 / 0.41 / 0.89 / 65.2 |
| feed (todas as requisições) | 24000 | 0 | 73061 | 0 | 0.46 / 3.53 / 100.50 / 169.0 |
| feed (primeira requisição da conexão) | 5886 | 0 | 5886 | 0 | 0.46 / 4.44 / 57.98 / 133.2 |
| ingest (flag = registros) | 2399 | 0 | 29999 | 0 | 1.78 / 4.44 / 30.87 / 81.2 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 02:31 | 600 | 0 | 600 | 0.74 / 3.27 / 33.5 |
| 02:32 | 12000 | 0 | 11857 | 1.55 / 100.49 / 153.0 |
| 02:33 | 11400 | 0 | 11251 | 9.60 / 100.56 / 169.0 |

Métricas do bot (heartbeat, d192-hb.json → d192-ha.json):

```json
{
  "auth": 24998,
  "auth_ja4h": {
    "header": 25003,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 53,
    "h2/ingest": 24950,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 292,
    "tcp/store": 24711,
    "tls/header": 53,
    "tls/ingest": 24950,
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
  "auth_p95_ms": 0.9755216891225763,
  "auth_p99_ms": 114.39041095890425,
  "auth_le_10ms": 0.9833986718937515,
  "auth_le_50ms": 0.9877590207216578,
  "wait_p95_ms": 0.9656839622641508,
  "wait_p99_ms": 114.39041095890425,
  "wait_sum_ms": 33161.79906899996,
  "auth_sum_ms": 38647.33512599996,
  "view_wait": {
    "fork": 0,
    "tcp": 292
  },
  "evicted": {
    "bytes": 36662,
    "count": 0
  },
  "index_bytes_after": 201259623,
  "ingest_records": 194440,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 67788
}
```

bot_auth_ja4h_total{source="header"} Δ 25003 contra 24000 forwardAuth 200 do cliente na janela das amostras.
