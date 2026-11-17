Janela 2026-11-17T05:52:59Z → 2026-11-17T06:01:59Z, 658955 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 108000 | 0 | 108000 | 0 | 0.43 / 0.62 / 1.62 / 84.4 |
| consulta GET /verdict | 10873 | 0 | 0 | 0 | 0.21 / 0.31 / 0.45 / 42.8 |
| feed (todas as requisições) | 108000 | 0 | 329060 | 0 | 0.43 / 0.62 / 1.65 / 86.1 |
| feed (primeira requisição da conexão) | 26439 | 0 | 26439 | 0 | 0.43 / 0.62 / 1.27 / 79.5 |
| ingest (flag = registros) | 10793 | 0 | 134997 | 0 | 1.36 / 2.01 / 5.22 / 76.0 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 421289 | 0 | 24078 | 0 | 52.12 / 266.76 / 327.05 / 586.5 |
| feed global do store, sem o connection.updated do raw | 397211 | 0 | 0 | 0 | 52.85 / 271.51 / 328.24 / 586.5 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 05:52 | 200 | 0 | 200 | 0.54 / 0.65 / 5.1 |
| 05:53 | 12000 | 0 | 12000 | 0.61 / 1.16 / 84.4 |
| 05:54 | 12000 | 0 | 12000 | 0.60 / 1.06 / 54.6 |
| 05:55 | 12000 | 0 | 12000 | 0.61 / 1.03 / 64.0 |
| 05:56 | 12000 | 0 | 12000 | 0.62 / 4.28 / 69.8 |
| 05:57 | 12000 | 0 | 12000 | 0.61 / 1.81 / 76.5 |
| 05:58 | 12000 | 0 | 12000 | 0.61 / 1.58 / 68.7 |
| 05:59 | 12000 | 0 | 12000 | 0.60 / 8.48 / 79.2 |
| 06:00 | 12000 | 0 | 12000 | 0.66 / 1.00 / 69.6 |
| 06:01 | 11800 | 0 | 11800 | 0.61 / 3.19 / 71.5 |

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-official.json → tmp/load/raw/f8/main/ha-official.json):

```json
{
  "auth": 108000,
  "auth_ja4h": {
    "header": 108000,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9505016536505378,
  "auth_p99_ms": 0.9905227759095079,
  "auth_le_10ms": 0.9999537037037037,
  "auth_le_50ms": 0.9999814814814815,
  "wait_p95_ms": 0.9500439835177555,
  "wait_p99_ms": 0.9900458354553453,
  "wait_sum_ms": 1046.047665000039,
  "auth_sum_ms": 14731.392292999808,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 0,
    "count": 0
  },
  "index_bytes_after": 246153105,
  "ingest_records": 134996,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 291568
}
```

bot_auth_ja4h_total{source="header"} Δ 108000 contra 108000 forwardAuth 200 do cliente na janela das amostras.
