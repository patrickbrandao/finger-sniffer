Commit `v0.5.2-126-g5830de3`, início 2026-11-25T02:30:29Z, 100 novas/s, até 400 simultâneas (máx. visto 396), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 261 / p99 335 / máx 814 ms (n=238257) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 61 / p95 268 / p99 335 / máx 814 ms (n=229203) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 261 / p99 335 / máx 814 ms (n=238257) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 61 / p95 268 / p99 335 / máx 814 ms (n=229203) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 20.7 / p99 22.8 / máx 154.0 ms (n=1500) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 21.1 / p99 25.8 / máx 153.7 ms (n=1500) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 92 / p95 130 / p99 162 / máx 640 ms (n=24302) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3690 / p95 166 / p99 182 / máx 360 ms (n=6078) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 36000 (feed ws 36000, sse 36000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 36000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 55 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 46 (49)/768, raw 18 (20)/256, dns 6 (6)/256, store 193 (2246)/6144, nats 312 (315)/1024, bot 664 (771)/1024, slice 1214 (3533)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 207 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 14.8 / 20.0 / 22.3 % do host (steal médio 0.0); 237 / 321 / 356 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 722 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1500 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.7 | 5.0 | 5.9 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 39.7 | 44.7 | 50.7 | 49 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.5 | 8.0 | 10.7 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.2 | 1.2 | 6 | 6 | 0 | 256 | 0 | 0 / 0 |
| store | 70.7 | 92.1 | 118.0 | 2246 | 193 | 2046 | 6144 | 0 | 0 / 0 |
| nats | 16.8 | 20.2 | 23.3 | 315 | 312 | 0 | 1024 | 0 | 0 / 0 |
| bot | 64.4 | 124.0 | 155.7 | 771 | 664 | 0 | 1024 | 207 | 0 / 0 |
| slice | 201.8 | 272.1 | 315.8 | 3533 | 1214 | 2085 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.7 | 2.0 |
| cliente /ws (ts → chegada) | 60.4 | 261.2 | 334.9 |
| ingest_lag (ts → commit) | 60.1 | 147.7 | 312.8 |
| live_delay (ts → envio ao cliente) | 52.9 | 206.3 | 423.7 |
| record_ready{close} (fim → gravado) | 64.5 | 145.8 | 157.6 |
| record_ready{idle} (fim → gravado) | 90.5 | 152.8 | 158.3 |
| record_ready{quic_close} (fim → gravado) | 119.2 | 249.0 | 303.1 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 229203 | 61 | 268 | 335 | 814 |
| connection.closed | 35331 | 74 | 154 | 176 | 615 |
| connection.opened | 35333 | 68 | 101 | 118 | 578 |
| connection.updated | 103405 | 57 | 314 | 346 | 814 |
| connection.updated/dns | 6 | 11 | 53 | 53 | 53 |
| connection.updated/http1.0 | 1 | 26 | 26 | 26 | 26 |
| connection.updated/http1.1 | 14214 | 57 | 99 | 229 | 511 |
| connection.updated/quic | 8023 | 48 | 228 | 250 | 291 |
| connection.updated/quic/h3 | 24005 | 49 | 230 | 349 | 788 |
| connection.updated/raw | 9042 | 55 | 85 | 98 | 552 |
| connection.updated/tcp | 4 | 11 | 12 | 12 | 12 |
| connection.updated/tls | 10527 | 58 | 90 | 104 | 564 |
| connection.updated/tls/h2 | 24036 | 64 | 332 | 354 | 806 |
| connection.updated/tls/http1.1 | 13535 | 66 | 335 | 361 | 814 |
| connection.updated/tls/raw | 12 | 26 | 67 | 67 | 67 |
| dns.query | 13 | 51 | 69 | 69 | 69 |
| http.request | 63947 | 55 | 87 | 101 | 571 |
| packet.stray | 228 | 10 | 88 | 109 | 119 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6078 | 97 | 161 | 178 | 616 |
| tcp | 24302 | 74 | 107 | 136 | 615 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5400 | 5400 | 0 | http1.1=5400 |  |
| h1tls | 5400 | 5400 | 0 | tls/http1.1=5400 |  |
| h2 | 7200 | 7200 | 0 | tls/h2=7200 |  |
| h3 | 7200 | 7200 | 0 | quic=133 quic/h3=7067 |  |
| raw-banner | 4320 | 4320 | 0 | raw=4320 |  |
| raw-echo | 3600 | 3600 | 0 | raw=3600 |  |
| raw-sink | 2880 | 2880 | 0 | raw=2880 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.07 s (60 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 918614
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
- `store_late_packets_total`: 20231
- `store_stray_total`: 237

Relógio: servidor − local 4.977114ms no início, 4.403895ms no fim (ida e volta do ssh 16.925708ms).
Deslocamento acompanhado a cada 15 s (27 de 27 medições aceitas): 4.107378ms a 5.116196ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
