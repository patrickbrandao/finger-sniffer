Commit `6facb2c`, início 2026-11-09T11:46:47Z, 50 novas/s, até 200 simultâneas (máx. visto 199), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 107 / p95 383 / p99 3941 / máx 120076 ms (n=202804) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 104 / p95 318 / p99 384 / máx 30163 ms (n=194634) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 105 / p95 384 / p99 3939 / máx 120076 ms (n=202804) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 103 / p95 319 / p99 384 / máx 30163 ms (n=194634) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 22.4 / p95 38.9 / p99 47.9 / máx 181.8 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 22.4 / p95 37.6 / p99 49.4 / máx 178.0 ms (n=2701) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 146 / p95 227 / p99 257 / máx 484 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 202 / p95 262 / p99 279 / máx 530 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 9986 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | 6facb2c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/96, web 28 (29)/96, raw 13 (14)/96, dns 4 (5)/96, store 60 (345)/384, nats 122 (127)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 43 / 48 / 66 (steal médio 0.0) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 632 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.6 | 1.9 | 2.2 | 9 | 8 | 96 |
| web | 13.6 | 14.5 | 16.7 | 29 | 28 | 96 |
| raw | 2.0 | 2.4 | 2.8 | 14 | 13 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 5 | 4 | 96 |
| store | 21.3 | 24.7 | 43.5 | 345 | 60 | 384 |
| nats | 4.5 | 5.1 | 5.3 | 127 | 122 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.2 | 3.2 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.6 | 3.4 |
| cliente /ws (ts → chegada) | 107.0 | 383.4 | 3940.6 |
| ingest_lag (ts → commit) | 84.4 | 153.4 | 284.9 |
| live_delay (ts → envio ao cliente) | 98.9 | 557.7 | 4392.6 |
| record_ready{close} (fim → gravado) | 97.9 | 155.7 | 262.4 |
| record_ready{idle} (fim → gravado) | 92.6 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 188.5 | 303.6 | 313.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 194634 | 104 | 318 | 384 | 30163 |
| connection.closed | 27094 | 122 | 226 | 251 | 30163 |
| connection.opened | 27224 | 108 | 166 | 184 | 458 |
| connection.updated | 91247 | 113 | 3905 | 3956 | 120076 |
| connection.updated/http1.1 | 12261 | 94 | 152 | 168 | 416 |
| connection.updated/quic/h3 | 27000 | 107 | 389 | 421 | 625 |
| connection.updated/raw | 8166 | 3912 | 3967 | 3990 | 120076 |
| connection.updated/raw/unknown | 4 | 113 | 140 | 140 | 140 |
| connection.updated/tls | 9496 | 95 | 145 | 162 | 385 |
| connection.updated/tls/h2 | 21984 | 119 | 349 | 375 | 634 |
| connection.updated/tls/http1.1 | 12336 | 120 | 370 | 393 | 623 |
| dns.query | 1 | 164 | 164 | 164 | 164 |
| http.request | 56818 | 93 | 152 | 169 | 450 |
| packet.stray | 420 | 111 | 173 | 190 | 30113 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 191 | 249 | 265 | 397 |
| tcp | 21752 | 109 | 166 | 188 | 385 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 1563 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 1612 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 2324 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 1837 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 1036 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 867 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 747 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 809399
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 7718
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 1285
- `store_stray_total`: 425

Relógio: vps602 − local 238.72912ms no início, 240.451688ms no fim (ida e volta do ssh 16.437542ms).

**Há metas que falharam.**
