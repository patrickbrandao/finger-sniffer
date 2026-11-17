Janela (tudo) → (tudo), 2064709 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 318217 | 0 | 318217 | 0 | 0.43 / 0.64 / 6.46 / 191.4 |
| consulta GET /verdict | 32042 | 0 | 0 | 0 | 0.21 / 0.31 / 0.47 / 77.9 |
| feed (todas as requisições) | 318217 | 0 | 1056496 | 0 | 0.43 / 0.64 / 6.31 / 191.4 |
| feed (primeira requisição da conexão) | 73632 | 0 | 73632 | 0 | 0.44 / 0.64 / 8.23 / 117.4 |
| ingest (flag = registros) | 31824 | 0 | 393341 | 0 | 1.35 / 2.12 / 19.16 / 192.9 |
| ingest hostil (flag = aceitos) | 239 | 0 | 162520 | 0 | 93.14 / 230.31 / 240.97 / 253.9 |
| feed global do store no finger-01 | 1172861 | 0 | 67175 | 0 | 52.40 / 267.50 / 327.86 / 611.7 |
| feed global do store, sem o connection.updated do raw | 1105686 | 0 | 0 | 0 | 53.11 / 272.41 / 329.12 / 611.7 |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 191309; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

Métricas do bot (heartbeat, tmp/load/raw/f8/main/hb-total.json → tmp/load/raw/f8/main/ha-total.json):

```json
{
  "auth": 318217,
  "auth_ja4h": {
    "header": 318217,
    "ingest": 0,
    "none": 0
  },
  "auth_p95_ms": 0.9526284194504928,
  "auth_p99_ms": 0.9927390897431453,
  "auth_le_10ms": 0.9989849693762433,
  "auth_le_50ms": 0.9997328866779588,
  "wait_p95_ms": 0.950525718382221,
  "wait_p99_ms": 0.9905478538930516,
  "wait_sum_ms": 5717.410771999961,
  "auth_sum_ms": 57029.64404100056,
  "view_wait": {
    "fork": 0,
    "tcp": 0
  },
  "evicted": {
    "bytes": 29243,
    "count": 0
  },
  "index_bytes_after": 402621034,
  "ingest_records": 555861,
  "ingest_dropped": 0,
  "rate_limited": 0,
  "agg_dropped": 0,
  "store_feed_messages": 810927
}
```

bot_auth_ja4h_total{source="header"} Δ 318217 contra 318217 forwardAuth 200 do cliente na janela das amostras.
