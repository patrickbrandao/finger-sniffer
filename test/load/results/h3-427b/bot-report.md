Janela 2026-11-25T04:59:48Z → 2026-11-25T05:04:18Z, 118813 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 54000 | 0 | 53997 | 0 | 0.54 / 0.93 / 23.57 / 189.8 |
| consulta GET /verdict | 5437 | 0 | 0 | 0 | 0.23 / 0.37 / 0.60 / 73.4 |
| feed (todas as requisições) | 54000 | 0 | 170138 | 0 | 0.55 / 0.92 / 23.71 / 189.9 |
| feed (primeira requisição da conexão) | 12853 | 0 | 12853 | 0 | 0.55 / 0.92 / 24.72 / 100.9 |
| ingest (flag = registros) | 5376 | 0 | 67501 | 0 | 1.83 / 3.14 / 49.26 / 98.6 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 0; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.

| Minuto (UTC) | forwardAuth | erro | view.tcp | p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- |
| 04:59 | 2400 | 0 | 2400 | 0.59 / 3.35 / 43.8 |
| 05:00 | 12000 | 0 | 11997 | 0.72 / 14.26 / 100.9 |
| 05:01 | 12000 | 0 | 12000 | 0.87 / 17.25 / 84.5 |
| 05:02 | 12000 | 0 | 12000 | 1.07 / 29.02 / 189.8 |
| 05:03 | 12000 | 0 | 12000 | 0.98 / 33.87 / 85.6 |
| 05:04 | 3600 | 0 | 3600 | 0.83 / 23.79 / 88.3 |
botload: open hb.json: no such file or directory
