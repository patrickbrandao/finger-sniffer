Commit `v0.5.2-126-g5830de3`, início 2026-11-25T02:11:25Z, 100 novas/s, até 400 simultâneas (máx. visto 394), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 247 / p99 334 / máx 809 ms (n=236832) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 264 / p99 336 / máx 809 ms (n=227796) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 247 / p99 334 / máx 809 ms (n=236832) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 264 / p99 336 / máx 809 ms (n=227796) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 20.4 / p99 22.5 / máx 153.0 ms (n=1500) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 22.2 / p99 33.2 / máx 39.2 ms (n=1500) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 92 / p95 128 / p99 145 / máx 628 ms (n=24302) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3690 / p95 165 / p99 184 / máx 689 ms (n=6078) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 36000 (feed ws 36000, sse 36000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 36000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 51 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 46 (49)/768, raw 17 (19)/256, dns 5 (6)/256, store 153 (2206)/6144, nats 309 (312)/1024, bot 731 (800)/1024, slice 1267 (3494)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 217 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.6 / 17.7 / 20.5 % do host (steal médio 0.0); 218 / 284 / 328 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 819 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1500 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.3 | 7.1 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 39.5 | 44.4 | 48.8 | 49 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.7 | 9.4 | 14.2 | 19 | 17 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 51.3 | 58.7 | 87.8 | 2206 | 153 | 2045 | 6144 | 0 | 0 / 0 |
| nats | 16.4 | 19.7 | 22.8 | 312 | 309 | 0 | 1024 | 0 | 0 / 0 |
| bot | 61.1 | 113.2 | 147.5 | 800 | 731 | 0 | 1024 | 217 | 0 / 0 |
| slice | 178.6 | 232.6 | 265.5 | 3494 | 1267 | 2085 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.7 | 1.9 |
| cliente /ws (ts → chegada) | 60.2 | 247.1 | 334.5 |
| ingest_lag (ts → commit) | 59.6 | 146.3 | 300.3 |
| live_delay (ts → envio ao cliente) | 52.8 | 201.0 | 422.1 |
| record_ready{close} (fim → gravado) | 64.1 | 144.4 | 156.4 |
| record_ready{idle} (fim → gravado) | 89.0 | 151.9 | 157.5 |
| record_ready{quic_close} (fim → gravado) | 124.2 | 280.9 | 310.7 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 227796 | 60 | 264 | 336 | 809 |
| connection.closed | 35313 | 73 | 162 | 180 | 680 |
| connection.opened | 35305 | 68 | 101 | 111 | 590 |
| connection.updated | 102939 | 57 | 315 | 348 | 809 |
| connection.updated/http1.1 | 13501 | 54 | 86 | 98 | 572 |
| connection.updated/quic | 9039 | 44 | 225 | 243 | 463 |
| connection.updated/quic/h3 | 23296 | 50 | 232 | 347 | 749 |
| connection.updated/raw | 9036 | 54 | 84 | 91 | 530 |
| connection.updated/tls | 10500 | 59 | 89 | 96 | 552 |
| connection.updated/tls/h2 | 24043 | 64 | 331 | 351 | 786 |
| connection.updated/tls/http1.1 | 13524 | 65 | 339 | 359 | 809 |
| http.request | 63000 | 55 | 87 | 96 | 586 |
| packet.stray | 275 | 10 | 84 | 93 | 94 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6078 | 97 | 161 | 179 | 680 |
| tcp | 24302 | 73 | 106 | 121 | 618 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5400 | 5400 | 0 | http1.1=5400 |  |
| h1tls | 5400 | 5400 | 0 | tls/http1.1=5400 |  |
| h2 | 7200 | 7200 | 0 | tls/h2=7200 |  |
| h3 | 7200 | 7200 | 0 | quic=132 quic/h3=7068 |  |
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
- `capture_kernel_packets_total`: 920064
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
- `store_late_packets_total`: 20934
- `store_stray_total`: 293

Relógio: servidor − local 5.727366ms no início, 5.686126ms no fim (ida e volta do ssh 16.858667ms).
Deslocamento acompanhado a cada 15 s (27 de 27 medições aceitas): 5.119634ms a 5.861568ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
