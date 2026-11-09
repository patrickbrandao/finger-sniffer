Commit `efcb465`, início 2026-11-09T13:35:38Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 107 / p95 324 / p99 388 / máx 599 ms (n=202092) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 107 / p95 327 / p99 389 / máx 599 ms (n=193979) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 106 / p95 324 / p99 388 / máx 599 ms (n=202092) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 106 / p95 327 / p99 389 / máx 599 ms (n=193979) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 16.5 / p95 30.9 / p99 39.3 / máx 117.5 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 16.6 / p95 31.4 / p99 42.1 / máx 118.3 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 129 / p95 188 / p99 214 / máx 386 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 198 / p95 256 / p99 276 / máx 362 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 3309 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | efcb465 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/96, web 30 (44)/96, raw 11 (13)/96, dns 6 (7)/96, store 71 (384)/384, nats 90 (166)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 50 / 58 / 95 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 605 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.7 | 2.0 | 2.3 | 11 | 10 | 96 |
| web | 14.4 | 15.3 | 17.1 | 44 | 30 | 96 |
| raw | 1.9 | 2.2 | 2.6 | 13 | 11 | 96 |
| dns | 0.0 | 0.1 | 0.3 | 7 | 6 | 96 |
| store | 27.0 | 30.0 | 42.6 | 384 | 71 | 384 |
| nats | 4.6 | 5.3 | 5.8 | 166 | 90 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.4 | 3.4 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.8 | 3.9 |
| cliente /ws (ts → chegada) | 107.1 | 323.7 | 388.0 |
| ingest_lag (ts → commit) | 90.1 | 154.9 | 295.0 |
| live_delay (ts → envio ao cliente) | 103.6 | 391.6 | 1318.8 |
| record_ready{close} (fim → gravado) | 104.0 | 184.5 | 290.2 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 190.4 | 303.8 | 313.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193979 | 107 | 327 | 389 | 599 |
| connection.closed | 27057 | 126 | 223 | 251 | 363 |
| connection.opened | 27192 | 110 | 169 | 191 | 306 |
| connection.updated | 90554 | 109 | 366 | 404 | 599 |
| connection.updated/http1.0 | 3 | 49 | 76 | 76 | 76 |
| connection.updated/http1.1 | 12163 | 95 | 159 | 186 | 275 |
| connection.updated/quic/h3 | 26996 | 108 | 386 | 420 | 528 |
| connection.updated/raw | 8109 | 102 | 159 | 180 | 276 |
| connection.updated/raw/unknown | 4 | 27 | 136 | 136 | 136 |
| connection.updated/tls | 9478 | 98 | 146 | 166 | 308 |
| connection.updated/tls/h2 | 21646 | 119 | 366 | 394 | 599 |
| connection.updated/tls/http1.1 | 12155 | 132 | 381 | 405 | 544 |
| dns.query | 24 | 124 | 150 | 170 | 170 |
| http.request | 56745 | 96 | 156 | 179 | 297 |
| packet.stray | 520 | 110 | 170 | 200 | 222 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 191 | 248 | 268 | 356 |
| tcp | 21752 | 112 | 171 | 195 | 363 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 498 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 500 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 662 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 662 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 392 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 333 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 262 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 820011
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 3348
- `fs_store_live_dropped_total`: 3388
- `store_late_packets_total`: 58
- `store_stray_total`: 534

Relógio: vps602 − local 3.586091ms no início, -678.789µs no fim (ida e volta do ssh 12.108166ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -678.789µs a 3.586091ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
