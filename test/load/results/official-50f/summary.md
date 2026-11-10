Commit `v0.1.0-12-g90c86d8`, início 2026-11-09T22:27:43Z, 50 novas/s, até 200 simultâneas (máx. visto 195), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 106 / p95 322 / p99 389 / máx 477 ms (n=201626) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 106 / p95 326 / p99 390 / máx 477 ms (n=193490) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 103 / p95 322 / p99 388 / máx 725 ms (n=201626) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 104 / p95 325 / p99 389 / máx 725 ms (n=193490) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 16.8 / p95 36.1 / p99 49.5 / máx 75.0 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 16.7 / p95 29.2 / p99 38.7 / máx 69.1 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 128 / p95 186 / p99 204 / máx 295 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 192 / p95 254 / p99 279 / máx 338 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 29430 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-12-g90c86d8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (54)/96, raw 12 (20)/96, dns 7 (13)/96, store 72 (384)/384, nats 88 (96)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 49 / 54 / 61 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 732 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.6 | 16 | 10 | 96 |
| web | 16.0 | 17.0 | 18.4 | 54 | 30 | 96 |
| raw | 2.1 | 2.3 | 2.5 | 20 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.3 | 13 | 7 | 96 |
| store | 23.1 | 27.5 | 32.0 | 384 | 72 | 384 |
| nats | 5.0 | 5.7 | 6.2 | 96 | 88 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 1.8 | 3.7 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.9 | 3.8 |
| cliente /ws (ts → chegada) | 105.6 | 322.5 | 389.4 |
| ingest_lag (ts → commit) | 87.7 | 153.5 | 272.4 |
| live_delay (ts → envio ao cliente) | 97.9 | 311.9 | 566.0 |
| record_ready{close} (fim → gravado) | 99.6 | 156.6 | 271.2 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 179.8 | 302.6 | 313.5 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193490 | 106 | 326 | 390 | 477 |
| connection.closed | 27038 | 125 | 221 | 247 | 330 |
| connection.opened | 27164 | 108 | 164 | 181 | 241 |
| connection.updated | 90484 | 107 | 367 | 404 | 477 |
| connection.updated/http1.1 | 12150 | 93 | 152 | 169 | 229 |
| connection.updated/quic/h3 | 26998 | 108 | 388 | 419 | 477 |
| connection.updated/raw | 8135 | 97 | 152 | 173 | 224 |
| connection.updated/raw/unknown | 1 | 126 | 126 | 126 | 126 |
| connection.updated/tls | 9450 | 97 | 146 | 162 | 213 |
| connection.updated/tls/h2 | 21600 | 116 | 370 | 397 | 472 |
| connection.updated/tls/http1.1 | 12150 | 130 | 382 | 404 | 461 |
| http.request | 56699 | 95 | 151 | 166 | 229 |
| packet.stray | 241 | 104 | 169 | 207 | 207 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 185 | 247 | 272 | 330 |
| tcp | 21752 | 111 | 168 | 186 | 276 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 4395 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 4403 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 5862 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 5909 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 3531 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 2978 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 2352 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 815452
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 26996
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 24
- `store_stray_total`: 256

Relógio: vps602 − local -1.682484ms no início, -2.971574ms no fim (ida e volta do ssh 12.939167ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -4.750528ms a -1.556667ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
