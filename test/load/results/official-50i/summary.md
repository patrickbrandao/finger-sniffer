Commit `v0.1.0-12-g90c86d8`, início 2026-11-09T23:12:05Z, 50 novas/s, até 200 simultâneas (máx. visto 196), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 115 / p95 328 / p99 395 / máx 527 ms (n=201913) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 115 / p95 331 / p99 396 / máx 527 ms (n=193794) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 114 / p95 327 / p99 395 / máx 527 ms (n=201913) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 115 / p95 331 / p99 396 / máx 527 ms (n=193794) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 37.9 / p99 48.4 / máx 72.4 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 38.2 / p99 52.6 / máx 250.6 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 137 / p95 202 / p99 241 / máx 426 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 202 / p95 261 / p99 285 / máx 384 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 1 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-12-g90c86d8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (53)/96, raw 12 (23)/96, dns 7 (12)/96, store 82 (384)/384, nats 88 (155)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 58 / 66 / 87 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 689 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.6 | 16 | 10 | 96 |
| web | 15.8 | 16.8 | 19.3 | 53 | 30 | 96 |
| raw | 2.1 | 2.4 | 2.7 | 23 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.2 | 12 | 7 | 96 |
| store | 31.0 | 37.8 | 59.3 | 384 | 82 | 384 |
| nats | 5.0 | 5.6 | 6.2 | 155 | 88 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 2.2 | 7.1 |
| api GET /api/v1/probes/{id} (servidor) | 0.7 | 2.8 | 7.9 |
| cliente /ws (ts → chegada) | 114.8 | 327.6 | 395.3 |
| ingest_lag (ts → commit) | 95.9 | 157.8 | 306.7 |
| live_delay (ts → envio ao cliente) | 108.9 | 333.5 | 571.5 |
| record_ready{close} (fim → gravado) | 112.2 | 253.5 | 303.9 |
| record_ready{idle} (fim → gravado) |  |  |  |
| record_ready{quic_close} (fim → gravado) | 197.1 | 304.6 | 314.1 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193794 | 115 | 331 | 396 | 527 |
| connection.closed | 27037 | 134 | 230 | 256 | 404 |
| connection.opened | 27180 | 116 | 177 | 203 | 302 |
| connection.updated | 90539 | 116 | 372 | 411 | 527 |
| connection.updated/http1.1 | 12155 | 100 | 166 | 191 | 263 |
| connection.updated/quic/h3 | 27000 | 119 | 394 | 423 | 472 |
| connection.updated/raw | 8119 | 106 | 163 | 186 | 301 |
| connection.updated/tcp | 21 | 22 | 42 | 43 | 43 |
| connection.updated/tls | 9455 | 103 | 158 | 183 | 276 |
| connection.updated/tls/h2 | 21622 | 123 | 374 | 403 | 517 |
| connection.updated/tls/http1.1 | 12167 | 141 | 386 | 410 | 527 |
| http.request | 56702 | 104 | 164 | 189 | 288 |
| packet.stray | 455 | 19 | 162 | 180 | 223 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 195 | 254 | 279 | 376 |
| tcp | 21752 | 122 | 184 | 225 | 404 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 1 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 815718
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 5
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 147
- `store_stray_total`: 467

Relógio: vps602 − local -2.563568ms no início, 95.584µs no fim (ida e volta do ssh 12.905708ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -4.730113ms a 348.471µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
