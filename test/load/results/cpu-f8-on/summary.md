Commit `v0.4.0-26-g8a4ca69`, início 2026-11-17T05:27:16Z, 100 novas/s, até 400 simultâneas (máx. visto 397), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 21000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 4527 / p95 7456 / p99 8553 / máx 9070 ms (n=44079) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 4528 / p95 7454 / p99 8555 / máx 9070 ms (n=41520) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 569 avisos, 111284 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 4840 / p95 7415 / p99 8638 / máx 9799 ms (n=42813) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 4842 / p95 7416 / p99 8638 / máx 9799 ms (n=40304) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 604 avisos, 111098 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 102.8 / p95 502.1 / p99 808.9 / máx 1248.5 ms (n=539) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 107.0 / p95 461.4 / p99 787.4 / máx 1390.3 ms (n=539) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 4676 / p95 7483 / p99 8600 / máx 9102 ms (n=6707) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 4713 / p95 7397 / p99 8656 / máx 9072 ms (n=1594) | **falhou** |
| RNF-01 | probes sem registro | 0 | 1 de 21000 (feed ws 5553, sse 5433, só API 11510) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 21000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.4.0-26-g8a4ca69 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 11 (12)/512, web 41 (44)/768, raw 19 (21)/256, dns 4 (5)/256, store 169 (1036)/6144, nats 307 (310)/1024, bot 122 (124)/1024, slice 673 (1610)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 0 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 9.2 / 10.4 / 11.2 % do host (steal médio 0.0); 148 / 167 / 180 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 737 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 539 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.7 | 3.9 | 12 | 11 | 0 | 512 | 0 | 0 / 0 |
| web | 38.4 | 40.6 | 42.7 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.5 | 6.3 | 9.5 | 21 | 19 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 44.0 | 48.5 | 54.9 | 1036 | 169 | 866 | 6144 | 0 | 0 / 0 |
| nats | 15.2 | 17.9 | 19.8 | 310 | 307 | 0 | 1024 | 0 | 0 / 0 |
| bot | 27.8 | 30.3 | 31.9 | 124 | 122 | 0 | 1024 | 0 | 0 / 0 |
| slice | 134.4 | 142.7 | 146.6 | 1610 | 673 | 906 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.4 |
| cliente /ws (ts → chegada) | 4527.5 | 7456.5 | 8553.4 |
| ingest_lag (ts → commit) | 58.7 | 141.6 | 157.5 |
| live_delay (ts → envio ao cliente) | 368.2 | 7289.2 | 9457.8 |
| record_ready{close} (fim → gravado) | 72.2 | 155.4 | 270.9 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 122.7 | 224.7 | 297.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 41520 | 4528 | 7454 | 8555 | 9070 |
| connection.closed | 4571 | 4596 | 7447 | 8629 | 8922 |
| connection.opened | 6002 | 4521 | 7426 | 8535 | 8907 |
| connection.updated | 21121 | 4535 | 7495 | 8557 | 9070 |
| connection.updated/http1.1 | 2857 | 4521 | 7406 | 8489 | 8886 |
| connection.updated/quic/h3 | 5688 | 4549 | 7517 | 8583 | 9054 |
| connection.updated/raw | 2554 | 4506 | 7483 | 8544 | 8975 |
| connection.updated/tls | 2418 | 4460 | 7415 | 8544 | 8892 |
| connection.updated/tls/h2 | 4621 | 4553 | 7502 | 8567 | 9070 |
| connection.updated/tls/http1.1 | 2978 | 4592 | 7509 | 8563 | 8899 |
| connection.updated/tls/raw | 5 | 4897 | 4898 | 4898 | 4898 |
| http.request | 12334 | 4497 | 7404 | 8520 | 8906 |
| packet.stray | 51 | 4843 | 6936 | 7703 | 7703 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 1594 | 4700 | 7385 | 8644 | 9062 |
| tcp | 6707 | 4653 | 7447 | 8586 | 9091 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 3150 | 3150 | 0 | http1.1=1238 |  |
| h1tls | 3150 | 3150 | 0 | tls/http1.1=1514 |  |
| h2 | 4200 | 4200 | 0 | tls/h2=2100 |  |
| h3 | 4200 | 4200 | 0 | quic/h3=1789 |  |
| raw-banner | 2520 | 2520 | 0 | raw=1167 |  |
| raw-echo | 2100 | 2100 | 0 | raw=859 |  |
| raw-sink | 1680 | 1680 | 0 | raw=822 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 630203
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 290008
- `store_late_packets_total`: 7227
- `store_stray_total`: 184

Relógio: servidor − local -489.622µs no início, -1.880643ms no fim (ida e volta do ssh 17.192542ms).
Deslocamento acompanhado a cada 15 s (43 de 44 medições aceitas): -6.409481ms a 374.5µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
