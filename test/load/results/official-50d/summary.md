Commit `efcb465`, início 2026-11-09T13:48:22Z, 50 novas/s, até 200 simultâneas (máx. visto 197), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 107 / p95 323 / p99 389 / máx 30117 ms (n=201867) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 107 / p95 326 / p99 390 / máx 30117 ms (n=193760) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 112 / p95 326 / p99 392 / máx 30123 ms (n=201867) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 112 / p95 329 / p99 393 / máx 30123 ms (n=193760) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 13.6 / p95 31.0 / p99 46.5 / máx 76.4 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 13.7 / p95 30.6 / p99 42.3 / máx 58.4 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 128 / p95 191 / p99 224 / máx 491 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 195 / p95 252 / p99 284 / máx 408 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 6 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | efcb465 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/96, web 30 (44)/96, raw 11 (14)/96, dns 6 (7)/96, store 76 (384)/384, nats 90 (153)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 52 / 58 / 79 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 719 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.7 | 2.0 | 2.4 | 12 | 10 | 96 |
| web | 14.4 | 15.5 | 17.4 | 44 | 30 | 96 |
| raw | 1.9 | 2.2 | 2.5 | 14 | 11 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 7 | 6 | 96 |
| store | 27.8 | 32.4 | 40.9 | 384 | 76 | 384 |
| nats | 4.7 | 5.3 | 6.3 | 153 | 90 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.6 | 3.6 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.9 | 6.3 |
| cliente /ws (ts → chegada) | 106.8 | 322.7 | 389.2 |
| ingest_lag (ts → commit) | 90.8 | 155.0 | 295.3 |
| live_delay (ts → envio ao cliente) | 103.8 | 318.2 | 568.5 |
| record_ready{close} (fim → gravado) | 105.5 | 202.7 | 293.7 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 193.5 | 304.3 | 314.1 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193760 | 107 | 326 | 390 | 30117 |
| connection.closed | 27017 | 126 | 221 | 248 | 372 |
| connection.opened | 27131 | 109 | 168 | 188 | 281 |
| connection.updated | 90499 | 108 | 367 | 405 | 538 |
| connection.updated/http1.1 | 12157 | 95 | 156 | 170 | 266 |
| connection.updated/quic/h3 | 27000 | 109 | 387 | 418 | 538 |
| connection.updated/raw | 8107 | 101 | 156 | 172 | 264 |
| connection.updated/tls | 9455 | 96 | 147 | 170 | 275 |
| connection.updated/tls/h2 | 21617 | 118 | 369 | 398 | 484 |
| connection.updated/tls/http1.1 | 12163 | 130 | 379 | 404 | 482 |
| http.request | 56702 | 96 | 154 | 174 | 277 |
| packet.stray | 518 | 108 | 169 | 218 | 30117 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 188 | 245 | 276 | 372 |
| tcp | 21752 | 111 | 173 | 206 | 327 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 2 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 4 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 825596
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 6
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 74
- `store_stray_total`: 530

Relógio: vps602 − local 412.957µs no início, -1.476479ms no fim (ida e volta do ssh 12.764916ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -3.064291ms a 685.502µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
