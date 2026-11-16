Commit `v0.3.0-3-g38e4415`, início 2026-11-16T03:11:37Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 88 / p95 263 / p99 441 / máx 1400 ms (n=210934) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 89 / p95 270 / p99 445 / máx 1400 ms (n=199464) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 88 / p95 263 / p99 442 / máx 1400 ms (n=210934) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 89 / p95 270 / p99 446 / máx 1400 ms (n=199464) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 24.0 / p99 48.7 / máx 528.9 ms (n=2696) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 23.2 / p99 38.4 / máx 279.1 ms (n=2696) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 151 / p95 234 / p99 478 / máx 1011 ms (n=21754) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 184 / p95 236 / p99 525 / máx 29116 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-3-g38e4415 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 11 (11)/512, web 28 (30)/768, raw 13 (15)/256, dns 3 (3)/256, store 78 (1358)/2048, nats 180 (199)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 4.0 / 4.8 / 5.9 % do host (steal médio 0.0); 64 / 77 / 95 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 644 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2696 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.2 | 3.7 | 5.6 | 11 | 11 | 512 | 0 |
| web | 20.1 | 22.9 | 25.4 | 30 | 28 | 768 | 0 |
| raw | 3.6 | 4.1 | 5.8 | 15 | 13 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.2 | 3 | 3 | 256 | 0 |
| store | 24.3 | 28.3 | 39.5 | 1358 | 78 | 2048 | 0 |
| nats | 8.0 | 9.4 | 11.8 | 199 | 180 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 29.2 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 16.5 |
| cliente /ws (ts → chegada) | 87.8 | 263.3 | 441.2 |
| ingest_lag (ts → commit) | 80.6 | 156.3 | 776.2 |
| live_delay (ts → envio ao cliente) | 77.2 | 282.2 | 564.4 |
| record_ready{close} (fim → gravado) | 89.5 | 157.5 | 472.4 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 177.0 | 307.9 | 525.8 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 199464 | 89 | 270 | 445 | 1400 |
| connection.closed | 27085 | 122 | 216 | 467 | 1010 |
| connection.opened | 27199 | 94 | 150 | 437 | 993 |
| connection.updated | 99598 | 85 | 334 | 453 | 1400 |
| connection.updated/dns | 5 | 31 | 89 | 89 | 89 |
| connection.updated/http1.0 | 2 | 70 | 114 | 114 | 114 |
| connection.updated/http1.1 | 13844 | 73 | 133 | 366 | 978 |
| connection.updated/quic | 9 | 48 | 361 | 361 | 361 |
| connection.updated/quic/h3 | 27000 | 94 | 385 | 485 | 1174 |
| connection.updated/raw | 11466 | 58 | 130 | 323 | 890 |
| connection.updated/raw/unknown | 2 | 36 | 81 | 81 | 81 |
| connection.updated/tcp | 3 | 12 | 13 | 13 | 13 |
| connection.updated/tls | 9605 | 81 | 138 | 491 | 955 |
| connection.updated/tls/h2 | 23792 | 92 | 262 | 472 | 1400 |
| connection.updated/tls/http1.1 | 13868 | 96 | 265 | 484 | 1320 |
| connection.updated/tls/raw | 2 | 11 | 12 | 12 | 12 |
| dns.query | 5 | 90 | 108 | 108 | 108 |
| http.request | 56705 | 80 | 133 | 408 | 978 |
| packet.stray | 342 | 12 | 140 | 400 | 481 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 175 | 227 | 512 | 1010 |
| tcp | 21754 | 97 | 166 | 447 | 944 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic=1 quic/h3=5999 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 806030
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 15175
- `store_stray_total`: 356

Relógio: servidor − local 2.357851ms no início, 933.214µs no fim (ida e volta do ssh 16.880125ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): 494.553µs a 2.357851ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Todas as metas passaram.**
