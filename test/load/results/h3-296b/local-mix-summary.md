Commit `v0.5.2-126-g5830de3`, início 2026-11-25T01:49:43Z, 100 novas/s, até 400 simultâneas (máx. visto 384), vida 3.8s, 3 trocas, 10m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem finger-01; 60000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 26 / p95 2139 / p99 2205 / máx 2385 ms (n=404565) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 35 / p95 2140 / p99 2207 / máx 2385 ms (n=387396) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 25 / p95 2139 / p99 2205 / máx 2387 ms (n=404565) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 35 / p95 2140 / p99 2206 / máx 2387 ms (n=387396) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.7 / p95 0.9 / p99 1.1 / máx 3.8 ms (n=2850) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 0.9 / p95 1.3 / p99 1.7 / máx 4.5 ms (n=2850) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 28773 / p95 30068 / p99 30136 / máx 30303 ms (n=44522) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 811 / p95 1250 / p99 1357 / máx 30151 ms (n=11475) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 60000 (feed ws 58552, sse 58552, só API 1448) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 60000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 46 (48)/768, raw 17 (19)/256, dns 5 (5)/256, store 256 (3399)/6144, nats 224 (227)/1024, bot 546 (549)/1024, slice 1097 (4319)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 71 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 11.0 / 12.7 / 14.2 % do host (steal médio 0.0); 177 / 202 / 227 % de um núcleo (16 vCPU) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 724 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2850 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 1.2 | 1.5 | 1.8 | 9 | 8 | 0 | 512 | 0 | 0 / 0 |
| web | 37.1 | 39.8 | 41.7 | 48 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.5 | 6.0 | 6.8 | 19 | 17 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 5 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 53.9 | 67.3 | 75.8 | 3399 | 256 | 3132 | 6144 | 0 | 0 / 0 |
| nats | 12.8 | 15.3 | 17.0 | 227 | 224 | 0 | 1024 | 0 | 0 / 0 |
| bot | 17.9 | 38.7 | 44.5 | 549 | 546 | 0 | 1024 | 71 | 0 / 0 |
| slice | 128.6 | 150.7 | 165.3 | 4319 | 1097 | 3172 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.8 |
| cliente /ws (ts → chegada) | 25.9 | 2139.4 | 2205.2 |
| ingest_lag (ts → commit) | 61.6 | 272.5 | 4262.1 |
| live_delay (ts → envio ao cliente) | 29.2 | 2309.8 | 2471.5 |
| record_ready{close} (fim → gravado) | 76.9 | 155.4 | 268.4 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 387396 | 35 | 2140 | 2207 | 2385 |
| connection.closed | 79654 | 17 | 27 | 37 | 229 |
| connection.opened | 79879 | 2106 | 2193 | 2261 | 2385 |
| connection.updated | 124896 | 4 | 9 | 13 | 284 |
| connection.updated/http1.1 | 17100 | 4 | 8 | 11 | 46 |
| connection.updated/quic | 11323 | 6 | 12 | 16 | 32 |
| connection.updated/quic/h3 | 27966 | 4 | 9 | 13 | 49 |
| connection.updated/raw | 17169 | 4 | 9 | 12 | 211 |
| connection.updated/tcp | 1 | 1 | 1 | 1 | 1 |
| connection.updated/tls | 26 | 38 | 107 | 284 | 284 |
| connection.updated/tls/h2 | 34211 | 4 | 9 | 12 | 104 |
| connection.updated/tls/http1.1 | 17100 | 4 | 9 | 12 | 89 |
| dns.query | 15 | 42 | 91 | 91 | 91 |
| http.request | 119700 | 858 | 2141 | 2193 | 2385 |
| packet.stray | 421 | 2 | 102 | 130 | 181 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 11475 | 2863 | 3352 | 3460 | 30151 |
| tcp | 44522 | 30056 | 30118 | 30193 | 30324 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=8733 |  |
| h1tls | 9000 | 9000 | 0 | tls/http1.1=8732 |  |
| h2 | 12000 | 12000 | 0 | tls/h2=11617 |  |
| h3 | 12000 | 12000 | 0 | quic/h3=11997 |  |
| raw-banner | 7200 | 7200 | 0 | raw=7015 |  |
| raw-echo | 6000 | 6000 | 0 | raw=5846 |  |
| raw-sink | 4800 | 4800 | 0 | raw=4677 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | não medido | **não** |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.09 s (114 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1548
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_flows_dropped_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 22
- `store_stray_total`: 436

Relógio: servidor − local 2.85µs no início, 2.57µs no fim (ida e volta do ssh 15.758µs).
Deslocamento acompanhado a cada 15 s (43 de 43 medições aceitas): -2.666µs a 4.737µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
