Janela 2026-11-18T22:50:22Z → 2026-11-18T22:59:22Z, 237791 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 108000 | 0 | 107935 | 0 | 0.45 / 0.66 / 4.01 / 137.5 |
| consulta GET /verdict | 10993 | 0 | 0 | 0 | 0.21 / 0.31 / 0.50 / 45.6 |
| feed (todas as requisições) | 108000 | 0 | 319925 | 0 | 0.45 / 0.65 / 4.21 / 137.5 |
| feed (primeira requisição da conexão) | 26546 | 0 | 26546 | 0 | 0.45 / 0.65 / 8.48 / 132.5 |
| ingest (flag = registros) | 10798 | 0 | 134951 | 0 | 1.57 / 2.32 / 3.27 / 94.9 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 22:50 | 7600 | 0 | 7598 | 0.62 / 1.18 / 101.1 |
| 22:51 | 12000 | 0 | 11998 | 0.65 / 1.92 / 101.4 |
| 22:52 | 12000 | 0 | 12000 | 0.66 / 7.53 / 83.0 |
| 22:53 | 12000 | 0 | 12000 | 0.65 / 6.78 / 80.8 |
| 22:54 | 12000 | 0 | 12000 | 0.66 / 2.50 / 77.4 |
| 22:55 | 12000 | 0 | 12000 | 0.67 / 3.44 / 79.2 |
| 22:56 | 12000 | 0 | 11993 | 0.65 / 4.63 / 101.5 |
| 22:57 | 12000 | 0 | 11980 | 0.65 / 5.40 / 137.5 |
| 22:58 | 12000 | 0 | 11977 | 0.66 / 4.10 / 101.3 |
| 22:59 | 4400 | 0 | 4389 | 0.68 / 6.79 / 101.5 |

Métricas do bot (heartbeat, hb-official.json → ha-official.json):

```json
{
  "auth": 109000,
  "auth_ja4h": {
    "header": 109001,
    "ingest": 0,
    "none": 0
  },
  "auth_fingerprint": {
    "h2/header": 0,
    "h2/ingest": 109001,
    "h2/none": 0,
    "h2/store": 0,
    "tcp/header": 0,
    "tcp/ingest": 0,
    "tcp/none": 66,
    "tcp/store": 108935,
    "tls/header": 0,
    "tls/ingest": 109001,
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
  "auth_p95_ms": 0.9511256441109203,
  "auth_p99_ms": 0.9911730396524328,
  "auth_le_10ms": 0.9993302752293578,
  "auth_le_50ms": 0.9993761467889908,
  "wait_p95_ms": 0.9507763219509507,
  "wait_p99_ms": 0.9908090091909907,
  "wait_sum_ms": 9625.641640999589,
  "auth_sum_ms": 23810.52576200216,
  "view_wait": {
    "fork": 0,
    "tcp": 66
  },
  "evicted": {
    "bytes": 0,
    "count": 0
  },
  "index_bytes_after": 246250150,
  "ingest_records": 136142,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 302813
}
```

bot_auth_ja4h_total{source="header"} Δ 109001 contra 108000 forwardAuth 200 do cliente na janela das amostras.
