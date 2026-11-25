Commit `v0.5.2-135-gddd1620`, início 2026-11-25T04:36:24Z, 100 novas/s, até 400 simultâneas (máx. visto 381), vida 3.8s, 3 trocas, 4m0s com 30s de aquecimento descartado, mix h3=1, origem finger-01; 24000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 34 / p95 2136 / p99 2158 / máx 2299 ms (n=168036) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 34 / p95 2136 / p99 2158 / máx 2299 ms (n=168010) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 35 / p95 2137 / p99 2159 / máx 2299 ms (n=168036) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 34 / p95 2137 / p99 2159 / máx 2299 ms (n=168010) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.8 / p95 1.0 / p99 1.3 / máx 4.0 ms (n=1050) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 1.0 / p95 1.4 / p99 2.3 / máx 6.7 ms (n=1050) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 30077 / p95 30131 / p99 30178 / máx 30235 ms (n=19554) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 24000 (feed ws 22037, sse 22037, só API 1963) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 24000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-135-gddd1620 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 81 (83)/768, raw 6 (7)/256, dns 4 (5)/256, store 389 (3474)/6144, nats 293 (296)/1024, bot 402 (404)/1024, slice 1185 (4485)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 4 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 14.0 / 16.1 / 17.6 % do host (steal médio 0.0); 224 / 257 / 282 % de um núcleo (16 vCPU) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 632 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1503 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1050 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 1.3 | 1.7 | 2.1 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 70.3 | 74.5 | 77.8 | 83 | 81 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.6 | 7 | 6 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 55.4 | 64.4 | 67.0 | 3474 | 389 | 3075 | 6144 | 0 | 0 / 0 |
| nats | 14.3 | 16.1 | 17.2 | 296 | 293 | 0 | 1024 | 0 | 0 / 0 |
| bot | 33.7 | 45.4 | 48.5 | 404 | 402 | 0 | 1024 | 4 | 0 / 0 |
| slice | 175.1 | 194.6 | 204.7 | 4485 | 1185 | 3116 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.2 | 1.9 |
| cliente /ws (ts → chegada) | 33.9 | 2136.3 | 2158.0 |
| ingest_lag (ts → commit) | 88.7 | 151.7 | 157.3 |
| live_delay (ts → envio ao cliente) | 37.9 | 2259.2 | 2461.4 |
| record_ready{close} (fim → gravado) | 111.6 | 153.8 | 157.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 168010 | 34 | 2136 | 2158 | 2299 |
| connection.closed | 20736 | 25 | 31 | 36 | 153 |
| connection.opened | 21092 | 2105 | 2156 | 2183 | 2299 |
| connection.updated | 63037 | 9 | 15 | 18 | 134 |
| connection.updated/quic/h3 | 63011 | 9 | 15 | 18 | 26 |
| connection.updated/raw | 26 | 91 | 131 | 134 | 134 |
| dns.query | 5 | 83 | 131 | 131 | 131 |
| http.request | 63000 | 842 | 2143 | 2162 | 2299 |
| packet.stray | 166 | 2 | 118 | 143 | 146 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 19554 | 30077 | 30131 | 30178 | 30235 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 24000 | 24000 | 0 | quic/h3=22174 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | não medido | **não** |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.10 s (42 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 519
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
- `store_late_packets_total`: 0
- `store_stray_total`: 188

Relógio: servidor − local 1.38µs no início, 3.457µs no fim (ida e volta do ssh 18.454µs).
Deslocamento acompanhado a cada 15 s (19 de 19 medições aceitas): -3.933µs a 3.498µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
