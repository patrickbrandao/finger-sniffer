Commit `v0.4.0-26-g8a4ca69`, início 2026-11-17T05:16:11Z, 100 novas/s, até 400 simultâneas (máx. visto 397), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 21000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 4493 / p95 6433 / p99 6750 / máx 7187 ms (n=47253) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 4494 / p95 6432 / p99 6748 / máx 7187 ms (n=44459) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 607 avisos, 105902 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 5589 / p95 7953 / p99 8736 / máx 9449 ms (n=39827) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 5593 / p95 7954 / p99 8739 / máx 9449 ms (n=37503) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 324 avisos, 115017 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 100.6 / p95 468.5 / p99 766.8 / máx 2677.5 ms (n=506) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 104.7 / p95 526.8 / p99 950.3 / máx 1665.3 ms (n=506) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 4861 / p95 7233 / p99 8418 / máx 9341 ms (n=6985) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 4948 / p95 7403 / p99 8507 / máx 34473 ms (n=1760) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 21000 (feed ws 5914, sse 5796, só API 11082) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 21000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 47 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.4.0-26-g8a4ca69 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 11 (12)/512, web 41 (43)/768, raw 17 (19)/256, dns 4 (4)/256, store 167 (1163)/6144, nats 308 (311)/1024, bot 0 (0)/1024, slice 547 (1619)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 0 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.8 / 8.9 / 9.6 % do host (steal médio 0.0); 124 / 143 / 154 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 735 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 506 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.9 | 5.6 | 8.5 | 12 | 11 | 0 | 512 | 0 | 0 / 0 |
| web | 40.9 | 45.8 | 48.8 | 43 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.2 | 8.5 | 10.3 | 19 | 17 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 45.3 | 52.1 | 57.3 | 1163 | 167 | 992 | 6144 | 0 | 0 / 0 |
| nats | 15.3 | 18.0 | 21.8 | 311 | 308 | 0 | 1024 | 0 | 0 / 0 |
| bot | 0.0 | 0.0 | 0.0 | 0 | 0 | 0 | 1024 (tabela) | 0 | 0 / 0 |
| slice | 111.7 | 124.1 | 139.5 | 1619 | 547 | 1032 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.1 | 1.8 |
| cliente /ws (ts → chegada) | 4492.6 | 6433.2 | 6750.1 |
| ingest_lag (ts → commit) | 59.7 | 142.7 | 157.5 |
| live_delay (ts → envio ao cliente) | 381.9 | 7617.3 | 9523.5 |
| record_ready{close} (fim → gravado) | 73.5 | 155.7 | 272.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 122.0 | 206.4 | 294.3 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 44459 | 4494 | 6432 | 6748 | 7187 |
| connection.closed | 4808 | 4561 | 6486 | 6782 | 7028 |
| connection.opened | 6482 | 4474 | 6435 | 6743 | 6954 |
| connection.updated | 22785 | 4496 | 6445 | 6759 | 7187 |
| connection.updated/http1.1 | 3040 | 4451 | 6433 | 6725 | 6910 |
| connection.updated/quic/h3 | 6019 | 4501 | 6440 | 6769 | 7187 |
| connection.updated/raw | 2794 | 4462 | 6458 | 6764 | 7034 |
| connection.updated/tcp | 1 | 4553 | 4553 | 4553 | 4553 |
| connection.updated/tls | 2680 | 4451 | 6450 | 6707 | 6812 |
| connection.updated/tls/h2 | 4961 | 4517 | 6410 | 6775 | 7155 |
| connection.updated/tls/http1.1 | 3290 | 4529 | 6491 | 6840 | 7103 |
| dns.query | 1 | 4277 | 4277 | 4277 | 4277 |
| http.request | 13113 | 4466 | 6375 | 6723 | 6938 |
| packet.stray | 64 | 4811 | 6787 | 6801 | 6801 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 1760 | 4931 | 7290 | 8292 | 9057 |
| tcp | 6985 | 4849 | 7241 | 8403 | 9321 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 3150 | 3150 | 0 | http1.1=1354 |  |
| h1tls | 3150 | 3150 | 0 | tls/http1.1=1527 |  |
| h2 | 4200 | 4200 | 0 | tls/h2=2137 |  |
| h3 | 4200 | 4200 | 0 | quic/h3=1994 |  |
| raw-banner | 2520 | 2520 | 0 | raw=1168 |  |
| raw-echo | 2100 | 2100 | 0 | raw=905 |  |
| raw-sink | 1680 | 1680 | 0 | raw=833 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 630583
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 289782
- `store_late_packets_total`: 7471
- `store_stray_total`: 211

Relógio: servidor − local 505.28µs no início, -250.836µs no fim (ida e volta do ssh 16.85975ms).
Deslocamento acompanhado a cada 15 s (43 de 43 medições aceitas): -7.547441ms a 932.774µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
