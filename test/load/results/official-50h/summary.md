Commit `v0.1.0-12-g90c86d8`, início 2026-11-09T22:59:51Z, 50 novas/s, até 200 simultâneas (máx. visto 196), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 113 / p95 327 / p99 394 / máx 631 ms (n=202254) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 113 / p95 330 / p99 395 / máx 631 ms (n=194145) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 117 / p95 330 / p99 397 / máx 635 ms (n=202254) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 117 / p95 333 / p99 398 / máx 635 ms (n=194145) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 14.1 / p95 32.6 / p99 46.1 / máx 89.4 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 13.9 / p95 32.3 / p99 42.3 / máx 74.2 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 136 / p95 198 / p99 222 / máx 500 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 196 / p95 264 / p99 291 / máx 546 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 27 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-12-g90c86d8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (41)/96, raw 12 (21)/96, dns 7 (12)/96, store 76 (384)/384, nats 88 (164)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 56 / 62 / 69 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 631 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.5 | 16 | 10 | 96 |
| web | 15.9 | 17.0 | 18.0 | 41 | 30 | 96 |
| raw | 2.1 | 2.4 | 2.7 | 21 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 12 | 7 | 96 |
| store | 29.5 | 33.8 | 38.9 | 384 | 76 | 384 |
| nats | 5.0 | 5.6 | 6.4 | 164 | 88 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 1.8 | 5.6 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 2.2 | 7.0 |
| cliente /ws (ts → chegada) | 112.8 | 326.7 | 394.4 |
| ingest_lag (ts → commit) | 95.0 | 157.2 | 305.3 |
| live_delay (ts → envio ao cliente) | 107.6 | 331.5 | 571.1 |
| record_ready{close} (fim → gravado) | 111.0 | 247.6 | 302.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 189.7 | 303.7 | 313.8 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 194145 | 113 | 330 | 395 | 631 |
| connection.closed | 27080 | 132 | 227 | 258 | 350 |
| connection.opened | 27287 | 115 | 174 | 196 | 306 |
| connection.updated | 90542 | 114 | 371 | 411 | 631 |
| connection.updated/http1.0 | 1 | 71 | 71 | 71 | 71 |
| connection.updated/http1.1 | 12181 | 99 | 162 | 186 | 291 |
| connection.updated/quic/h3 | 27003 | 116 | 394 | 429 | 533 |
| connection.updated/raw | 8105 | 104 | 163 | 186 | 251 |
| connection.updated/raw/unknown | 2 | 84 | 116 | 116 | 116 |
| connection.updated/tcp | 4 | 20 | 26 | 26 | 26 |
| connection.updated/tls | 9470 | 101 | 152 | 170 | 398 |
| connection.updated/tls/h2 | 21617 | 123 | 370 | 400 | 631 |
| connection.updated/tls/http1.1 | 12157 | 139 | 387 | 410 | 470 |
| connection.updated/tls/raw | 2 | 59 | 121 | 121 | 121 |
| dns.query | 1 | 140 | 140 | 140 | 140 |
| http.request | 56724 | 102 | 162 | 185 | 291 |
| packet.stray | 620 | 17 | 160 | 194 | 241 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 189 | 257 | 282 | 350 |
| tcp | 21752 | 120 | 180 | 203 | 339 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 3 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 6 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 6 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 3 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 4 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 5 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 818880
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 43
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 73
- `store_stray_total`: 642

Relógio: vps602 − local -4.44937ms no início, -2.375655ms no fim (ida e volta do ssh 15.431875ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -4.44937ms a -1.783277ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
