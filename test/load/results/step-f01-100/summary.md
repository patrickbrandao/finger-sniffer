Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T20:52:04Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 20295 abertas, 705 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 315 / p95 2055 / p99 2705 / máx 3444 ms (n=134788) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 350 / p95 2073 / p99 2714 / máx 3444 ms (n=125298) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 314 / p95 2055 / p99 2704 / máx 3447 ms (n=134788) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 349 / p95 2073 / p99 2714 / máx 3447 ms (n=125298) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 33.0 / p99 56.8 / máx 169.2 ms (n=897) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.8 / p95 34.2 / p99 82.9 / máx 297.0 ms (n=898) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 453 / p95 2185 / p99 2730 / máx 3321 ms (n=14151) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 477 / p95 2219 / p99 2762 / máx 3291 ms (n=3533) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 20295 (feed ws 20295, sse 20295, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 20295 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 705 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 41 (44)/768, raw 18 (20)/256, dns 3 (3)/256, store 113 (1548)/2048, nats 311 (329)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.6 / 12.8 / 13.9 % do host (steal médio 0.0); 121 / 205 / 223 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 615 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 897 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.0 | 4.4 | 10 | 9 | 512 | 0 |
| web | 36.9 | 41.0 | 46.9 | 44 | 41 | 768 | 0 |
| raw | 6.5 | 7.4 | 7.8 | 20 | 18 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 3 | 3 | 256 | 0 |
| store | 49.0 | 114.0 | 142.4 | 1548 | 113 | 2048 | 0 |
| nats | 11.8 | 14.8 | 17.2 | 329 | 311 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 10.6 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 22.0 |
| cliente /ws (ts → chegada) | 314.6 | 2054.8 | 2705.2 |
| ingest_lag (ts → commit) | 410.4 | 2365.1 | 4252.1 |
| live_delay (ts → envio ao cliente) | 331.9 | 2308.1 | 3880.4 |
| record_ready{close} (fim → gravado) | 455.3 | 2340.0 | 3927.5 |
| record_ready{idle} (fim → gravado) |  |  |  |
| record_ready{quic_close} (fim → gravado) | 477.9 | 2359.1 | 4038.0 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 125298 | 350 | 2073 | 2714 | 3444 |
| connection.closed | 17326 | 428 | 2110 | 2728 | 3302 |
| connection.opened | 17391 | 384 | 2054 | 2694 | 3199 |
| connection.updated | 63732 | 256 | 2048 | 2712 | 3444 |
| connection.updated/http1.0 | 1 | 573 | 573 | 573 | 573 |
| connection.updated/http1.1 | 9161 | 123 | 1947 | 2651 | 3180 |
| connection.updated/quic/h3 | 15039 | 465 | 2162 | 2758 | 3444 |
| connection.updated/raw | 9490 | 52 | 1703 | 2514 | 3142 |
| connection.updated/tcp | 1 | 10 | 10 | 10 | 10 |
| connection.updated/tls | 7328 | 349 | 2037 | 2720 | 3178 |
| connection.updated/tls/h2 | 14383 | 253 | 2102 | 2751 | 3436 |
| connection.updated/tls/http1.1 | 8329 | 243 | 2097 | 2757 | 3412 |
| http.request | 35858 | 361 | 2051 | 2685 | 3180 |
| packet.stray | 481 | 93 | 1723 | 2075 | 2687 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 3533 | 469 | 2211 | 2753 | 3282 |
| tcp | 14151 | 449 | 2185 | 2726 | 3302 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 3000 | 3000 | 0 | http1.1=3000 |  |
| h1tls | 3055 | 3055 | 0 | tls/http1.1=3055 |  |
| h2 | 4091 | 4091 | 0 | tls/h2=4091 |  |
| h3 | 4055 | 4055 | 0 | quic/h3=4055 |  |
| raw-banner | 2440 | 2440 | 0 | raw=2440 |  |
| raw-echo | 2054 | 2054 | 0 | raw=2054 |  |
| raw-sink | 1600 | 1600 | 0 | raw=1600 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 524200
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 15720
- `store_stray_total`: 504

Relógio: servidor − local 3.772363ms no início, 4.406869ms no fim (ida e volta do ssh 16.286375ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 3.223665ms a 4.412361ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
