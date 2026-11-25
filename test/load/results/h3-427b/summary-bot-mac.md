Commit `v0.5.2-135-gddd1620`, início 2026-11-25T04:59:18Z, 100 novas/s, até 400 simultâneas (máx. visto 387), vida 3.8s, 3 trocas, 5m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 62 / p95 301 / p99 346 / máx 585 ms (n=201681) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 63 / p95 304 / p99 347 / máx 585 ms (n=193528) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 62 / p95 301 / p99 346 / máx 585 ms (n=201681) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 63 / p95 304 / p99 347 / máx 585 ms (n=193528) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 21.0 / p99 25.4 / máx 153.6 ms (n=1350) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 20.7 / p99 33.3 / máx 40.1 ms (n=1350) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 93 / p95 128 / p99 146 / máx 372 ms (n=21902) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 159 / p95 187 / p99 206 / máx 28975 ms (n=5478) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-135-gddd1620 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 46 (48)/768, raw 16 (19)/256, dns 5 (6)/256, store 180 (3304)/6144, nats 310 (313)/1024, bot 534 (538)/1024, slice 1098 (4442)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 96 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 12.8 / 16.3 / 19.0 % do host (steal médio 0.0); 205 / 261 / 304 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 720 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1350 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 4.3 | 6.3 | 8.6 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 44.4 | 55.5 | 62.7 | 48 | 46 | 0 | 768 | 0 | 0 / 0 |
| raw | 7.6 | 10.2 | 12.2 | 19 | 16 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.2 | 3.5 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 49.8 | 60.0 | 64.4 | 3304 | 180 | 3115 | 6144 | 0 | 0 / 0 |
| nats | 18.5 | 23.7 | 28.2 | 313 | 310 | 0 | 1024 | 0 | 0 / 0 |
| bot | 49.3 | 77.0 | 102.0 | 538 | 534 | 0 | 1024 | 96 | 0 / 0 |
| slice | 174.0 | 213.4 | 266.3 | 4442 | 1098 | 3156 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.7 | 1.8 | 2.0 |
| cliente /ws (ts → chegada) | 62.3 | 301.4 | 346.3 |
| ingest_lag (ts → commit) | 60.1 | 147.3 | 290.1 |
| live_delay (ts → envio ao cliente) | 54.6 | 244.6 | 512.3 |
| record_ready{close} (fim → gravado) | 64.6 | 145.1 | 156.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 129.7 | 280.0 | 309.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193528 | 63 | 304 | 347 | 585 |
| connection.closed | 27108 | 82 | 165 | 181 | 381 |
| connection.opened | 27107 | 67 | 101 | 113 | 294 |
| connection.updated | 90568 | 60 | 329 | 357 | 585 |
| connection.updated/http1.1 | 12155 | 55 | 85 | 97 | 265 |
| connection.updated/quic/h3 | 27001 | 64 | 346 | 370 | 555 |
| connection.updated/raw | 8152 | 54 | 85 | 98 | 285 |
| connection.updated/tcp | 1 | 11 | 11 | 11 | 11 |
| connection.updated/tls | 9455 | 57 | 89 | 99 | 284 |
| connection.updated/tls/h2 | 21634 | 63 | 330 | 351 | 569 |
| connection.updated/tls/http1.1 | 12169 | 66 | 338 | 359 | 585 |
| connection.updated/tls/raw | 1 | 11 | 11 | 11 | 11 |
| dns.query | 5 | 37 | 75 | 75 | 75 |
| http.request | 56699 | 55 | 86 | 97 | 295 |
| packet.stray | 194 | 11 | 87 | 111 | 111 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5478 | 150 | 178 | 196 | 381 |
| tcp | 21902 | 74 | 107 | 124 | 347 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.07 s (54 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 814584
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
- `store_late_packets_total`: 123
- `store_stray_total`: 201

Relógio: servidor − local 1.034844ms no início, 1.019463ms no fim (ida e volta do ssh 16.840834ms).
Deslocamento acompanhado a cada 15 s (23 de 23 medições aceitas): 698.893µs a 1.344896ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
