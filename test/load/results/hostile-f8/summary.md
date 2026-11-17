Commit `v0.4.0-26-g8a4ca69`, início 2026-11-17T06:12:22Z, 100 novas/s, até 400 simultâneas (máx. visto 398), vida 3.8s, 3 trocas, 6m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 36000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 4730 / p95 7032 / p99 8277 / máx 9475 ms (n=81717) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 4731 / p95 7030 / p99 8277 / máx 9475 ms (n=76949) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 968 avisos, 190809 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 5024 / p95 7538 / p99 9283 / máx 12398 ms (n=76546) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 5024 / p95 7540 / p99 9286 / máx 12398 ms (n=71983) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 812 avisos, 195765 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 104.0 / p95 449.8 / p99 741.5 / máx 1000.7 ms (n=957) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 105.4 / p95 531.6 / p99 901.8 / máx 1796.5 ms (n=957) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 4876 / p95 7305 / p99 8826 / máx 12247 ms (n=12223) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 4923 / p95 7368 / p99 9053 / máx 11032 ms (n=2864) | **falhou** |
| RNF-01 | probes sem registro | 0 | 7024 de 35999 (feed ws 9224, sse 9409, só API 12788) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 1 de 36000 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 48 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.4.0-26-g8a4ca69 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 11 (12)/512, web 41 (44)/768, raw 20 (22)/256, dns 5 (6)/256, store 175 (1623)/6144, nats 309 (312)/1024, bot 733 (786)/1024, slice 1291 (2869)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 240 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.0 / 17.2 / 19.8 % do host (steal médio 0.0); 208 / 276 / 316 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 741 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 957 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 3.9 | 4.3 | 12 | 11 | 0 | 512 | 0 | 0 / 0 |
| web | 39.2 | 42.2 | 43.7 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.6 | 6.4 | 7.7 | 22 | 20 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 46.2 | 52.6 | 57.7 | 1623 | 175 | 1439 | 6144 | 0 | 0 / 0 |
| nats | 15.5 | 18.2 | 20.1 | 312 | 309 | 0 | 1024 | 0 | 0 / 0 |
| bot | 60.2 | 103.3 | 144.9 | 786 | 733 | 0 | 1024 | 240 | 0 / 0 |
| slice | 170.3 | 220.4 | 267.2 | 2869 | 1291 | 1479 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.6 |
| cliente /ws (ts → chegada) | 4730.1 | 7032.3 | 8277.4 |
| ingest_lag (ts → commit) | 59.6 | 142.8 | 157.7 |
| live_delay (ts → envio ao cliente) | 215.8 | 7336.9 | 9472.8 |
| record_ready{close} (fim → gravado) | 72.6 | 157.0 | 279.2 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 122.4 | 216.9 | 296.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 76949 | 4731 | 7030 | 8277 | 9475 |
| connection.closed | 8278 | 4798 | 7131 | 8397 | 9318 |
| connection.opened | 11247 | 4722 | 6993 | 8210 | 9277 |
| connection.updated | 39248 | 4733 | 7047 | 8290 | 9475 |
| connection.updated/http1.1 | 5290 | 4708 | 6997 | 8217 | 9267 |
| connection.updated/quic/h3 | 10568 | 4745 | 7049 | 8243 | 9464 |
| connection.updated/raw | 4767 | 4721 | 7058 | 8649 | 9372 |
| connection.updated/raw/unknown | 1 | 4660 | 4660 | 4660 | 4660 |
| connection.updated/tls | 4595 | 4700 | 7041 | 8268 | 9260 |
| connection.updated/tls/h2 | 8523 | 4747 | 7051 | 8291 | 9475 |
| connection.updated/tls/http1.0 | 2 | 3287 | 3543 | 3543 | 3543 |
| connection.updated/tls/http1.1 | 5502 | 4761 | 7099 | 8670 | 9455 |
| http.request | 22853 | 4704 | 6981 | 8199 | 9267 |
| packet.stray | 91 | 4698 | 8299 | 8954 | 8954 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 2864 | 4910 | 7357 | 9040 | 11020 |
| tcp | 12223 | 4865 | 7300 | 8795 | 12219 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5400 | 5399 | 0 | http1.1=2157 | 1× Get "http://ldr0bvtg90ozduob.finger-west-01.badblock.net.br:8080/p/ldr0bvtg90ozduob/": context deadline exceeded (Client |
| h1tls | 5400 | 5400 | 0 | tls/http1.1=2570 |  |
| h2 | 7200 | 7200 | 0 | tls/h2=3514 |  |
| h3 | 7200 | 7200 | 0 | quic/h3=3079 |  |
| raw-banner | 4320 | 4320 | 0 | raw=1960 |  |
| raw-echo | 3600 | 3600 | 0 | raw=1498 |  |
| raw-sink | 2880 | 2880 | 0 | raw=1409 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1125553
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 531205
- `store_late_packets_total`: 13138
- `store_stray_total`: 413

Relógio: servidor − local 2.004003ms no início, 947.673µs no fim (ida e volta do ssh 16.97975ms).
Deslocamento acompanhado a cada 15 s (64 de 66 medições aceitas): -5.519553ms a 3.54794ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
