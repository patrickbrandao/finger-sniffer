Janela 2026-11-18T22:15:14Z → 2026-11-18T22:49:22Z, 697428 amostras.

| Tipo | n | erro | flag | > 1 s | p50 / p95 / p99 / máx (ms) |
| --- | --- | --- | --- | --- | --- |
| forwardAuth (flag = view.tcp) | 239871 | 0 | 239693 | 0 | 0.45 / 0.64 / 1.04 / 146.7 |
| consulta GET /verdict | 23955 | 0 | 0 | 0 | 0.21 / 0.31 / 0.47 / 81.8 |
| feed (todas as requisições) | 239871 | 0 | 770328 | 0 | 0.45 / 0.64 / 1.03 / 146.7 |
| feed (primeira requisição da conexão) | 55931 | 0 | 55931 | 0 | 0.45 / 0.64 / 1.01 / 101.3 |
| ingest (flag = registros) | 24002 | 0 | 296673 | 0 | 1.51 / 2.33 / 3.24 / 47.9 |
| ingest hostil (flag = aceitos) | 0 | 0 | 0 | 0 | — |
| feed global do store no finger-01 | 0 | 0 | 0 | 0 | — |
| feed global do store, sem o connection.updated do raw | 0 | 0 | 0 | 0 | — |

Sem veredito no feed: 0; stream.dropped: 0 eventos (0 perdidos); puladas sem conexão: 169729; puladas em voo: 0.
Feed global do store no finger-01: stream.dropped 0 avisos, 0 eventos perdidos.
