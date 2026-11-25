Commit `v0.5.2-126-g5830de3`, início 2026-11-25T02:40:38Z, 100 novas/s, até 400 simultâneas (máx. visto 393), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 61 / p95 275 / p99 344 / máx 1090 ms (n=237668) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 61 / p95 279 / p99 345 / máx 1090 ms (n=228620) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 61 / p95 275 / p99 344 / máx 1090 ms (n=237668) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 61 / p95 279 / p99 345 / máx 1090 ms (n=228620) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 21.5 / p99 23.2 / máx 153.5 ms (n=1500) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 21.4 / p99 33.9 / máx 153.2 ms (n=1500) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 92 / p95 134 / p99 298 / máx 900 ms (n=24302) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3693 / p95 149 / p99 180 / máx 29002 ms (n=6078) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 36000 (feed ws 36000, sse 36000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 36000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 51 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 46 (49)/768, raw 18 (20)/256, dns 6 (6)/256, store 159 (2200)/6144, nats 310 (313)/1024, bot 714 (845)/1024, slice 1260 (3595)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 279 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.2 / 17.8 / 21.8 % do host (steal médio 0.0); 212 / 286 / 349 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 1220 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1500 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.2 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 38.0 | 40.5 | 42.4 | 49 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.1 | 6.7 | 7.1 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 6 | 6 | 0 | 256 | 0 | 0 / 0 |
| store | 50.3 | 56.9 | 73.1 | 2200 | 159 | 2030 | 6144 | 0 | 0 / 0 |
| nats | 15.8 | 18.5 | 19.4 | 313 | 310 | 0 | 1024 | 0 | 0 / 0 |
| bot | 64.6 | 120.3 | 193.3 | 845 | 714 | 0 | 1024 | 279 | 0 / 0 |
| slice | 178.3 | 237.1 | 310.6 | 3595 | 1260 | 2069 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.3 | 1.9 |
| cliente /ws (ts → chegada) | 60.8 | 275.0 | 343.8 |
| ingest_lag (ts → commit) | 60.0 | 150.3 | 554.6 |
| live_delay (ts → envio ao cliente) | 53.2 | 221.2 | 473.8 |
| record_ready{close} (fim → gravado) | 64.4 | 148.2 | 268.5 |
| record_ready{idle} (fim → gravado) | 90.3 | 153.7 | 275.4 |
| record_ready{quic_close} (fim → gravado) | 118.9 | 259.6 | 311.2 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 228620 | 61 | 279 | 345 | 1090 |
| connection.closed | 35611 | 73 | 163 | 251 | 889 |
| connection.opened | 35611 | 69 | 103 | 211 | 862 |
| connection.updated | 103221 | 58 | 317 | 352 | 1090 |
| connection.updated/http1.1 | 13513 | 56 | 89 | 197 | 845 |
| connection.updated/quic | 9565 | 50 | 236 | 248 | 821 |
| connection.updated/quic/h3 | 23010 | 49 | 227 | 347 | 828 |
| connection.updated/raw | 9046 | 55 | 85 | 202 | 806 |
| connection.updated/raw/unknown | 2 | 12 | 59 | 59 | 59 |
| connection.updated/tls | 10506 | 59 | 90 | 220 | 824 |
| connection.updated/tls/h2 | 24045 | 64 | 332 | 359 | 1071 |
| connection.updated/tls/http1.1 | 13534 | 67 | 339 | 367 | 1090 |
| dns.query | 4 | 32 | 63 | 63 | 63 |
| http.request | 63006 | 56 | 89 | 199 | 847 |
| packet.stray | 215 | 10 | 95 | 102 | 103 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6078 | 95 | 155 | 263 | 806 |
| tcp | 24302 | 74 | 111 | 268 | 889 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5400 | 5400 | 0 | http1.1=5400 |  |
| h1tls | 5400 | 5400 | 0 | tls/http1.1=5400 |  |
| h2 | 7200 | 7200 | 0 | tls/h2=7200 |  |
| h3 | 7200 | 7200 | 0 | quic=129 quic/h3=7071 |  |
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
- `capture_kernel_packets_total`: 912287
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
- `store_late_packets_total`: 23686
- `store_stray_total`: 222

Relógio: servidor − local 3.993609ms no início, 2.160226ms no fim (ida e volta do ssh 17.358625ms).
Deslocamento acompanhado a cada 15 s (27 de 27 medições aceitas): 2.160226ms a 4.130317ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
