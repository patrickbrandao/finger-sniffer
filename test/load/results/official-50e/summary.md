Commit `899ade1`, início 2026-11-09T15:01:24Z, 50 novas/s, até 200 simultâneas (máx. visto 195), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 108 / p95 324 / p99 389 / máx 576 ms (n=202105) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 108 / p95 327 / p99 390 / máx 576 ms (n=193990) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 109 / p95 324 / p99 388 / máx 576 ms (n=202105) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 109 / p95 326 / p99 389 / máx 576 ms (n=193990) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 13.5 / p95 28.5 / p99 37.0 / máx 84.5 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 13.7 / p95 30.6 / p99 42.1 / máx 92.9 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 129 / p95 193 / p99 225 / máx 515 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 191 / p95 250 / p99 282 / máx 472 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | 899ade1 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/96, web 30 (43)/96, raw 10 (12)/96, dns 4 (5)/96, store 75 (384)/384, nats 90 (99)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 52 / 58 / 83 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 620 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.7 | 2.0 | 2.3 | 10 | 9 | 96 |
| web | 14.6 | 15.6 | 16.6 | 43 | 30 | 96 |
| raw | 1.9 | 2.1 | 2.4 | 12 | 10 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 5 | 4 | 96 |
| store | 28.1 | 32.9 | 41.5 | 384 | 75 | 384 |
| nats | 4.6 | 5.2 | 5.7 | 99 | 90 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.3 | 2.6 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.8 | 6.0 |
| cliente /ws (ts → chegada) | 107.6 | 324.2 | 388.6 |
| ingest_lag (ts → commit) | 91.9 | 155.4 | 298.0 |
| live_delay (ts → envio ao cliente) | 104.3 | 325.8 | 569.9 |
| record_ready{close} (fim → gravado) | 105.6 | 211.9 | 295.7 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 189.3 | 303.7 | 313.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193990 | 108 | 327 | 390 | 576 |
| connection.closed | 27047 | 127 | 220 | 246 | 363 |
| connection.opened | 27218 | 110 | 169 | 192 | 316 |
| connection.updated | 90495 | 109 | 366 | 405 | 576 |
| connection.updated/http1.1 | 12159 | 96 | 157 | 177 | 273 |
| connection.updated/quic/h3 | 27003 | 110 | 384 | 421 | 576 |
| connection.updated/raw | 8111 | 101 | 158 | 181 | 271 |
| connection.updated/raw/unknown | 4 | 30 | 72 | 72 | 72 |
| connection.updated/tcp | 2 | 14 | 20 | 20 | 20 |
| connection.updated/tls | 9454 | 98 | 148 | 176 | 241 |
| connection.updated/tls/h2 | 21607 | 118 | 369 | 399 | 505 |
| connection.updated/tls/http1.1 | 12155 | 132 | 382 | 414 | 479 |
| http.request | 56703 | 97 | 155 | 175 | 314 |
| packet.stray | 642 | 46 | 155 | 174 | 207 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 184 | 243 | 273 | 363 |
| tcp | 21752 | 112 | 175 | 210 | 344 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 819219
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 15
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 58
- `store_stray_total`: 650

Relógio: vps602 − local 6.309112ms no início, 2.960984ms no fim (ida e volta do ssh 12.168792ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): 1.24664ms a 6.309112ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Todas as metas passaram.**
