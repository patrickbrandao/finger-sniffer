Commit `v0.5.2-135-gddd1620`, início 2026-11-25T04:41:39Z, 100 novas/s, até 400 simultâneas (máx. visto 385), vida 3.8s, 3 trocas, 10m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem finger-01; 60000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 21 / p95 2105 / p99 2125 / máx 2274 ms (n=354165) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 33 / p95 2106 / p99 2125 / máx 2274 ms (n=336996) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 21 / p95 2104 / p99 2125 / máx 2273 ms (n=354165) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 33 / p95 2105 / p99 2125 / máx 2273 ms (n=336996) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.7 / p95 0.9 / p99 1.2 / máx 6.6 ms (n=2850) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 0.9 / p95 1.2 / p99 1.5 / máx 5.1 ms (n=2850) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 28773 / p95 30064 / p99 30077 / máx 30224 ms (n=44533) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 30042 / p95 30082 / p99 30128 / máx 30224 ms (n=11099) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 60000 (feed ws 58156, sse 58156, só API 1844) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 60000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-135-gddd1620 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 45 (48)/768, raw 16 (19)/256, dns 5 (6)/256, store 250 (3332)/6144, nats 222 (225)/1024, bot 379 (381)/1024, slice 924 (4165)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 37 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 9.6 / 11.0 / 12.3 % do host (steal médio 0.0); 154 / 176 / 196 % de um núcleo (16 vCPU) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 722 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1503 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2850 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 1.2 | 1.5 | 2.0 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 36.7 | 39.2 | 41.5 | 48 | 45 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.4 | 5.9 | 6.5 | 19 | 16 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 47.9 | 56.4 | 62.4 | 3332 | 250 | 3075 | 6144 | 0 | 0 / 0 |
| nats | 12.6 | 15.2 | 16.4 | 225 | 222 | 0 | 1024 | 0 | 0 / 0 |
| bot | 17.3 | 33.4 | 36.4 | 381 | 379 | 0 | 1024 | 37 | 0 / 0 |
| slice | 121.2 | 139.8 | 156.2 | 4165 | 924 | 3116 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.4 |
| cliente /ws (ts → chegada) | 21.2 | 2104.6 | 2125.0 |
| ingest_lag (ts → commit) | 59.4 | 255.3 | 4278.3 |
| live_delay (ts → envio ao cliente) | 20.2 | 2282.0 | 2465.9 |
| record_ready{close} (fim → gravado) | 66.6 | 146.6 | 156.1 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 336996 | 33 | 2106 | 2125 | 2274 |
| connection.closed | 57006 | 15 | 20 | 23 | 142 |
| connection.opened | 57219 | 2076 | 2123 | 2144 | 2274 |
| connection.updated | 119777 | 4 | 7 | 9 | 121 |
| connection.updated/http1.1 | 17100 | 4 | 7 | 9 | 58 |
| connection.updated/quic/h3 | 34201 | 4 | 7 | 8 | 58 |
| connection.updated/raw | 17169 | 4 | 7 | 9 | 121 |
| connection.updated/tcp | 4 | 3 | 7 | 7 | 7 |
| connection.updated/tls/h2 | 34202 | 4 | 7 | 9 | 57 |
| connection.updated/tls/http1.1 | 17101 | 4 | 7 | 9 | 56 |
| dns.query | 18 | 43 | 105 | 105 | 105 |
| http.request | 119700 | 813 | 2110 | 2126 | 2269 |
| packet.stray | 445 | 2 | 101 | 113 | 131 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 11099 | 30042 | 30082 | 30128 | 30223 |
| tcp | 44533 | 30054 | 30086 | 30128 | 30226 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=8735 |  |
| h1tls | 9000 | 9000 | 0 | tls/http1.1=8734 |  |
| h2 | 12000 | 12000 | 0 | tls/h2=11620 |  |
| h3 | 12000 | 12000 | 0 | quic/h3=11621 |  |
| raw-banner | 7200 | 7200 | 0 | raw=7017 |  |
| raw-echo | 6000 | 6000 | 0 | raw=5847 |  |
| raw-sink | 4800 | 4800 | 0 | raw=4678 |  |

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
- `capture_kernel_packets_total`: 1447
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
- `store_late_packets_total`: 6
- `store_stray_total`: 461

Relógio: servidor − local 2.781µs no início, 3.902µs no fim (ida e volta do ssh 16.621µs).
Deslocamento acompanhado a cada 15 s (43 de 43 medições aceitas): -3.827µs a 4.273µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
