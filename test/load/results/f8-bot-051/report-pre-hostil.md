Janela 2026-11-18T23:16:50Z → 2026-11-18T23:18:11Z, 35596 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 16200 | 0 | 16200 | 0 | 0.46 / 0.67 / 0.89 / 3.9 |
| consulta GET /verdict | 1576 | 0 | 0 | 0 | 0.21 / 0.32 / 0.45 / 1.0 |
| feed (todas as requisições) | 16200 | 0 | 63212 | 0 | 0.46 / 0.66 / 0.88 / 3.9 |
| feed (primeira requisição da conexão) | 3980 | 0 | 3980 | 0 | 0.47 / 0.65 / 0.87 / 3.1 |
| ingest (flag = registros) | 1620 | 0 | 20246 | 0 | 1.59 / 2.38 / 3.00 / 4.9 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.
