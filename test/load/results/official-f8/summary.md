Commit `v0.4.0-26-g8a4ca69`, início 2026-11-17T05:51:59Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 59991 abertas, 9 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 4798 / p95 7066 / p99 7934 / máx 9624 ms (n=138369) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 4799 / p95 7067 / p99 7933 / máx 9624 ms (n=130419) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 907 avisos, 313601 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 5147 / p95 7294 / p99 8193 / máx 9483 ms (n=126302) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 5147 / p95 7298 / p99 8194 / máx 9483 ms (n=118959) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 1693 avisos, 323036 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 100.5 / p95 511.3 / p99 873.2 / máx 2340.9 ms (n=1566) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 106.8 / p95 509.6 / p99 864.9 / máx 1290.1 ms (n=1566) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 4955 / p95 7166 / p99 8112 / máx 9511 ms (n=21270) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 5001 / p95 7291 / p99 8272 / máx 37604 ms (n=5193) | **falhou** |
| RNF-01 | probes sem registro | 0 | 30798 de 59991 (feed ws 18773, sse 14936, só API 0) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 59991 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 9 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.4.0-26-g8a4ca69 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 11 (12)/512, web 41 (44)/768, raw 21 (22)/256, dns 5 (6)/256, store 179 (2560)/6144, nats 307 (310)/1024, bot 537 (542)/1024, slice 1099 (3561)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 146 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 11.4 / 13.3 / 15.8 % do host (steal médio 0.0); 183 / 212 / 253 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 735 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1566 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 4.0 | 4.5 | 12 | 11 | 0 | 512 | 0 | 0 / 0 |
| web | 39.0 | 41.8 | 47.7 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.7 | 6.3 | 7.1 | 22 | 21 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 45.0 | 48.9 | 56.1 | 2560 | 179 | 2370 | 6144 | 0 | 0 / 0 |
| nats | 15.6 | 18.2 | 20.4 | 310 | 307 | 0 | 1024 | 0 | 0 / 0 |
| bot | 42.3 | 61.2 | 73.6 | 542 | 537 | 0 | 1024 | 146 | 0 / 0 |
| slice | 151.2 | 172.0 | 187.2 | 3561 | 1099 | 2410 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.5 |
| cliente /ws (ts → chegada) | 4798.2 | 7066.2 | 7933.5 |
| ingest_lag (ts → commit) | 59.0 | 141.7 | 157.4 |
| live_delay (ts → envio ao cliente) | 220.3 | 7333.1 | 9466.6 |
| record_ready{close} (fim → gravado) | 72.8 | 155.6 | 272.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 121.2 | 166.1 | 286.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 130419 | 4799 | 7067 | 7933 | 9624 |
| connection.closed | 16892 | 4876 | 7118 | 7987 | 9498 |
| connection.opened | 18111 | 4769 | 7035 | 7848 | 9237 |
| connection.updated | 65936 | 4807 | 7077 | 7951 | 9624 |
| connection.updated/http1.1 | 8342 | 4752 | 7038 | 7881 | 9360 |
| connection.updated/quic/h3 | 17915 | 4822 | 7097 | 7970 | 9624 |
| connection.updated/raw | 7950 | 4790 | 7054 | 7951 | 9258 |
| connection.updated/tcp | 1 | 5316 | 5316 | 5316 | 5316 |
| connection.updated/tls | 7160 | 4745 | 7004 | 7772 | 9174 |
| connection.updated/tls/h2 | 14924 | 4830 | 7135 | 8033 | 9048 |
| connection.updated/tls/http1.1 | 9644 | 4843 | 7156 | 7978 | 8991 |
| http.request | 37249 | 4764 | 7032 | 7918 | 9360 |
| packet.stray | 181 | 4744 | 7104 | 8256 | 8359 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5193 | 4988 | 7268 | 8229 | 9414 |
| tcp | 21270 | 4941 | 7157 | 8085 | 9498 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=4043 |  |
| h1tls | 9000 | 9000 | 0 | tls/http1.1=4533 |  |
| h2 | 11996 | 11996 | 0 | tls/h2=6222 |  |
| h3 | 11995 | 11995 | 0 | quic/h3=5699 |  |
| raw-banner | 7200 | 7200 | 0 | raw=3462 |  |
| raw-echo | 6000 | 6000 | 0 | raw=2752 |  |
| raw-sink | 4800 | 4800 | 0 | raw=2482 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1836733
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 861246
- `store_late_packets_total`: 21678
- `store_stray_total`: 589

Relógio: servidor − local 3.05894ms no início, 1.916682ms no fim (ida e volta do ssh 16.659542ms).
Deslocamento acompanhado a cada 15 s (79 de 82 medições aceitas): -4.913599ms a 4.091837ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
