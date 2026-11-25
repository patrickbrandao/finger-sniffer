Commit `v0.5.2-126-g5830de3`, início 2026-11-25T02:02:01Z, 100 novas/s, até 400 simultâneas (máx. visto 393), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 237 / p99 332 / máx 2137 ms (n=236854) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 256 / p99 332 / máx 2137 ms (n=227811) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 237 / p99 332 / máx 2136 ms (n=236854) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 256 / p99 332 / máx 2136 ms (n=227811) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 20.4 / p99 22.4 / máx 151.8 ms (n=1500) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 21.3 / p99 33.7 / máx 153.3 ms (n=1500) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 91 / p95 129 / p99 144 / máx 464 ms (n=24302) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3691 / p95 165 / p99 181 / máx 28978 ms (n=6078) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 36000 (feed ws 36000, sse 36000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 36000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 49 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 46 (49)/768, raw 18 (19)/256, dns 5 (5)/256, store 153 (2264)/6144, nats 307 (311)/1024, bot 735 (790)/1024, slice 1270 (3477)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 261 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.2 / 17.0 / 19.9 % do host (steal médio 0.0); 211 / 272 / 318 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 719 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1500 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.4 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 38.1 | 40.8 | 45.3 | 49 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.1 | 6.8 | 8.0 | 19 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 5 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 50.0 | 58.5 | 68.0 | 2264 | 153 | 2105 | 6144 | 0 | 0 / 0 |
| nats | 15.9 | 18.7 | 21.3 | 311 | 307 | 0 | 1024 | 0 | 0 / 0 |
| bot | 61.6 | 111.4 | 144.8 | 790 | 735 | 0 | 1024 | 261 | 0 / 0 |
| slice | 175.3 | 222.6 | 260.5 | 3477 | 1270 | 2145 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.4 | 1.9 |
| cliente /ws (ts → chegada) | 60.0 | 236.6 | 331.8 |
| ingest_lag (ts → commit) | 59.5 | 145.5 | 280.6 |
| live_delay (ts → envio ao cliente) | 52.7 | 195.1 | 388.9 |
| record_ready{close} (fim → gravado) | 63.7 | 143.7 | 155.9 |
| record_ready{idle} (fim → gravado) | 87.9 | 151.5 | 157.1 |
| record_ready{quic_close} (fim → gravado) | 122.3 | 262.2 | 305.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 227811 | 60 | 256 | 332 | 2137 |
| connection.closed | 35263 | 73 | 157 | 175 | 299 |
| connection.opened | 35259 | 68 | 100 | 112 | 2137 |
| connection.updated | 103124 | 57 | 312 | 344 | 575 |
| connection.updated/http1.1 | 13504 | 55 | 85 | 99 | 212 |
| connection.updated/quic | 8698 | 50 | 229 | 244 | 305 |
| connection.updated/quic/h3 | 23821 | 49 | 231 | 347 | 471 |
| connection.updated/raw | 9043 | 55 | 85 | 94 | 211 |
| connection.updated/tcp | 1 | 11 | 11 | 11 | 11 |
| connection.updated/tls | 10501 | 57 | 89 | 98 | 171 |
| connection.updated/tls/h2 | 24024 | 64 | 330 | 352 | 409 |
| connection.updated/tls/http1.1 | 13532 | 67 | 334 | 353 | 575 |
| http.request | 63000 | 55 | 86 | 96 | 216 |
| packet.stray | 208 | 11 | 90 | 105 | 112 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6078 | 96 | 158 | 173 | 299 |
| tcp | 24302 | 73 | 106 | 120 | 237 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5400 | 5400 | 0 | http1.1=5400 |  |
| h1tls | 5400 | 5400 | 0 | tls/http1.1=5400 |  |
| h2 | 7200 | 7200 | 0 | tls/h2=7200 |  |
| h3 | 7200 | 7200 | 0 | quic=147 quic/h3=7053 |  |
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
- `capture_kernel_packets_total`: 911468
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
- `store_late_packets_total`: 21424
- `store_stray_total`: 220

Relógio: servidor − local 5.499214ms no início, 5.776248ms no fim (ida e volta do ssh 16.377959ms).
Deslocamento acompanhado a cada 15 s (27 de 27 medições aceitas): 5.041084ms a 5.835915ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
