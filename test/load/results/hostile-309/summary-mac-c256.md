Commit `v0.5.2-126-g5830de3`, início 2026-11-25T02:21:01Z, 100 novas/s, até 400 simultâneas (máx. visto 394), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 237 / p99 332 / máx 736 ms (n=238645) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 259 / p99 334 / máx 736 ms (n=229601) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 236 / p99 332 / máx 736 ms (n=238645) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 258 / p99 334 / máx 736 ms (n=229601) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 19.9 / p99 22.1 / máx 31.3 ms (n=1500) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.4 / p95 20.6 / p99 33.7 / máx 152.5 ms (n=1500) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 91 / p95 128 / p99 143 / máx 566 ms (n=24302) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3692 / p95 161 / p99 183 / máx 29017 ms (n=6078) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 36000 (feed ws 36000, sse 36000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 36000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 53 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 46 (49)/768, raw 18 (19)/256, dns 5 (6)/256, store 181 (2232)/6144, nats 337 (340)/1024, bot 747 (834)/1024, slice 1329 (3600)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 172 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.5 / 17.5 / 19.5 % do host (steal médio 0.0); 216 / 281 / 312 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 613 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1500 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.0 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 38.3 | 40.9 | 43.1 | 49 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.2 | 6.7 | 7.3 | 19 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 54.7 | 71.0 | 88.9 | 2232 | 181 | 2045 | 6144 | 0 | 0 / 0 |
| nats | 16.2 | 19.2 | 21.1 | 340 | 337 | 0 | 1024 | 0 | 0 / 0 |
| bot | 61.4 | 116.8 | 155.1 | 834 | 747 | 0 | 1024 | 172 | 0 / 0 |
| slice | 180.2 | 231.3 | 269.7 | 3600 | 1329 | 2085 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.3 | 1.9 |
| cliente /ws (ts → chegada) | 59.9 | 236.5 | 332.5 |
| ingest_lag (ts → commit) | 59.3 | 145.8 | 294.9 |
| live_delay (ts → envio ao cliente) | 52.3 | 204.9 | 410.8 |
| record_ready{close} (fim → gravado) | 63.7 | 144.0 | 156.3 |
| record_ready{idle} (fim → gravado) | 88.5 | 152.3 | 157.9 |
| record_ready{quic_close} (fim → gravado) | 126.6 | 284.6 | 310.1 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 229601 | 60 | 259 | 334 | 736 |
| connection.closed | 35423 | 72 | 164 | 181 | 543 |
| connection.opened | 35429 | 67 | 100 | 110 | 508 |
| connection.updated | 103807 | 57 | 314 | 347 | 736 |
| connection.updated/http1.1 | 14077 | 56 | 93 | 211 | 501 |
| connection.updated/quic | 9673 | 43 | 226 | 242 | 278 |
| connection.updated/quic/h3 | 22945 | 49 | 227 | 346 | 497 |
| connection.updated/raw | 9042 | 54 | 83 | 90 | 452 |
| connection.updated/raw/unknown | 2 | 10 | 65 | 65 | 65 |
| connection.updated/tcp | 6 | 11 | 13 | 13 | 13 |
| connection.updated/tls | 10504 | 58 | 89 | 97 | 481 |
| connection.updated/tls/h2 | 24036 | 63 | 329 | 350 | 719 |
| connection.updated/tls/http1.1 | 13522 | 64 | 339 | 358 | 736 |
| dns.query | 13 | 58 | 73 | 73 | 73 |
| http.request | 63761 | 54 | 86 | 95 | 501 |
| packet.stray | 212 | 10 | 93 | 103 | 103 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6078 | 96 | 160 | 179 | 560 |
| tcp | 24302 | 73 | 106 | 119 | 543 |

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
- `capture_kernel_packets_total`: 910959
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
- `store_late_packets_total`: 23019
- `store_stray_total`: 227

Relógio: servidor − local 5.432657ms no início, 5.3412ms no fim (ida e volta do ssh 16.905ms).
Deslocamento acompanhado a cada 15 s (27 de 27 medições aceitas): 4.894394ms a 5.669796ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
