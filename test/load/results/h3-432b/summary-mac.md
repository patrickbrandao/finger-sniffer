Commit `v0.5.2-137-g7b95d4d`, início 2026-11-25T05:27:39Z, 100 novas/s, até 400 simultâneas (máx. visto 392), vida 3.8s, 3 trocas, 5m0s com 30s de aquecimento descartado, mix h3=1, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 91 / p95 348 / p99 395 / máx 2072 ms (n=270500) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 91 / p95 348 / p99 395 / máx 2072 ms (n=270463) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 91 / p95 348 / p99 395 / máx 2072 ms (n=270500) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 91 / p95 348 / p99 395 / máx 2072 ms (n=270463) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 18.5 / p99 33.1 / máx 152.0 ms (n=1350) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 19.3 / p99 33.7 / máx 157.3 ms (n=1350) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 170 / p95 215 / p99 222 / máx 29034 ms (n=27377) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 29997, sse 29997, só API 3) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 325 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-137-g7b95d4d, versions_match=false | **falhou** |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (11)/512, web 82 (84)/768, raw 8 (9)/256, dns 6 (6)/256, store 207 (2153)/6144, nats 299 (303)/1024, bot 319 (321)/1024, slice 929 (3433)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 1 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 12.9 / 14.4 / 15.6 % do host (steal médio 0.0); 206 / 231 / 250 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 717 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1350 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.8 | 4.9 | 6.3 | 11 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 72.7 | 79.1 | 105.7 | 84 | 82 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.7 | 9 | 8 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 6 | 0 | 256 | 0 | 0 / 0 |
| store | 55.0 | 64.8 | 74.2 | 2153 | 207 | 1939 | 6144 | 0 | 0 / 0 |
| nats | 17.3 | 19.6 | 22.3 | 303 | 299 | 0 | 1024 | 0 | 0 / 0 |
| bot | 49.6 | 55.6 | 58.7 | 321 | 319 | 0 | 1024 | 1 | 0 / 0 |
| slice | 198.5 | 220.3 | 255.6 | 3433 | 929 | 2321 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.4 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.7 | 1.9 |
| cliente /ws (ts → chegada) | 90.8 | 347.6 | 394.7 |
| ingest_lag (ts → commit) | 85.8 | 151.3 | 157.1 |
| live_delay (ts → envio ao cliente) | 83.9 | 429.6 | 590.7 |
| record_ready{close} (fim → gravado) | 78.6 | 156.6 | 276.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 151.2 | 298.7 | 312.7 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 270463 | 91 | 348 | 395 | 2072 |
| connection.closed | 27113 | 160 | 206 | 212 | 315 |
| connection.opened | 27115 | 91 | 134 | 143 | 2072 |
| connection.updated | 135044 | 89 | 375 | 404 | 1302 |
| connection.updated/quic/h3 | 135004 | 89 | 375 | 404 | 1302 |
| connection.updated/raw | 37 | 67 | 116 | 145 | 145 |
| connection.updated/tcp | 3 | 13 | 13 | 13 | 13 |
| dns.query | 4 | 64 | 117 | 117 | 117 |
| http.request | 81001 | 78 | 121 | 127 | 1302 |
| packet.stray | 223 | 11 | 133 | 140 | 141 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 27377 | 161 | 206 | 213 | 29576 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 30000 | 30000 | 0 | quic/h3=29997 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.09 s (54 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 886271
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
- `store_late_packets_total`: 5
- `store_stray_total`: 230

Relógio: servidor − local 2.086083ms no início, 2.618078ms no fim (ida e volta do ssh 16.377542ms).
Deslocamento acompanhado a cada 15 s (23 de 23 medições aceitas): 1.565171ms a 2.618078ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
