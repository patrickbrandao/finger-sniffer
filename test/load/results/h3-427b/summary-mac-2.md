Commit `v0.5.2-135-gddd1620`, início 2026-11-25T04:53:00Z, 100 novas/s, até 400 simultâneas (máx. visto 393), vida 3.8s, 3 trocas, 5m0s com 30s de aquecimento descartado, mix h3=1, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 91 / p95 351 / p99 392 / máx 477 ms (n=270478) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 91 / p95 351 / p99 392 / máx 477 ms (n=270445) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 90 / p95 351 / p99 392 / máx 477 ms (n=270478) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 90 / p95 351 / p99 392 / máx 477 ms (n=270445) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 17.8 / p99 19.1 / máx 151.4 ms (n=1350) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 19.0 / p99 33.7 / máx 74.5 ms (n=1351) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 170 / p95 215 / p99 224 / máx 28987 ms (n=27380) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-135-gddd1620 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 82 (84)/768, raw 16 (17)/256, dns 5 (5)/256, store 232 (3121)/6144, nats 302 (306)/1024, bot 437 (440)/1024, slice 1075 (4179)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 139 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.4 / 15.6 / 17.5 % do host (steal médio 0.0); 215 / 250 / 279 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 689 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1350 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 4.1 | 6.0 | 10 | 9 | 0 | 512 | 0 | 0 / 0 |
| web | 70.5 | 77.7 | 83.2 | 84 | 82 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.6 | 17 | 16 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 2.1 | 5 | 5 | 0 | 256 | 0 | 0 / 0 |
| store | 55.6 | 64.0 | 76.2 | 3121 | 232 | 2879 | 6144 | 0 | 0 / 0 |
| nats | 16.6 | 18.9 | 21.7 | 306 | 302 | 0 | 1024 | 0 | 0 / 0 |
| bot | 52.4 | 66.3 | 75.5 | 440 | 437 | 0 | 1024 | 139 | 0 / 0 |
| slice | 198.8 | 223.7 | 254.4 | 4179 | 1075 | 2920 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.6 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.8 | 2.0 |
| cliente /ws (ts → chegada) | 90.6 | 350.6 | 392.0 |
| ingest_lag (ts → commit) | 85.3 | 151.2 | 157.0 |
| live_delay (ts → envio ao cliente) | 83.6 | 410.8 | 586.9 |
| record_ready{close} (fim → gravado) | 99.9 | 157.9 | 281.5 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 151.9 | 298.9 | 312.8 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 270445 | 91 | 351 | 392 | 477 |
| connection.closed | 27110 | 161 | 206 | 212 | 272 |
| connection.opened | 27107 | 91 | 134 | 142 | 210 |
| connection.updated | 135045 | 88 | 372 | 402 | 477 |
| connection.updated/http1.1 | 2 | 12 | 31 | 31 | 31 |
| connection.updated/quic/h3 | 135000 | 88 | 372 | 402 | 477 |
| connection.updated/raw | 33 | 73 | 116 | 118 | 118 |
| connection.updated/tcp | 3 | 13 | 14 | 14 | 14 |
| connection.updated/tls | 3 | 78 | 123 | 123 | 123 |
| connection.updated/tls/h2 | 2 | 12 | 156 | 156 | 156 |
| connection.updated/tls/http1.1 | 2 | 12 | 112 | 112 | 112 |
| dns.query | 2 | 60 | 64 | 64 | 64 |
| http.request | 81003 | 78 | 120 | 127 | 193 |
| packet.stray | 211 | 11 | 135 | 142 | 144 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 27380 | 161 | 206 | 214 | 19218 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 30000 | 30000 | 0 | quic/h3=30000 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.10 s (55 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 891481
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
- `store_late_packets_total`: 22
- `store_stray_total`: 226

Relógio: servidor − local -613.599µs no início, 1.146268ms no fim (ida e volta do ssh 16.57075ms).
Deslocamento acompanhado a cada 15 s (23 de 23 medições aceitas): -1.09667ms a 1.146268ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
