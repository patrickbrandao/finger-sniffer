Commit `v0.5.2-126-g5830de3`, início 2026-11-25T01:37:48Z, 100 novas/s, até 400 simultâneas (máx. visto 390), vida 3.8s, 3 trocas, 4m0s com 30s de aquecimento descartado, mix h3=1, origem mac; 24000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 86 / p95 202 / p99 369 / máx 2160 ms (n=247271) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 86 / p95 202 / p99 369 / máx 2160 ms (n=247246) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 86 / p95 201 / p99 369 / máx 2160 ms (n=247271) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 86 / p95 201 / p99 369 / máx 2160 ms (n=247246) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 17.8 / p99 21.2 / máx 152.3 ms (n=1050) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.6 / p95 19.0 / p99 33.6 / máx 151.8 ms (n=1050) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 -3642 / p95 198 / p99 218 / máx 28966 ms (n=21380) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 24000 (feed ws 24000, sse 24000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 24000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 82 (84)/768, raw 4 (5)/256, dns 4 (5)/256, store 108 (2278)/6144, nats 301 (304)/1024, bot 305 (307)/1024, slice 803 (3061)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 0 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.1 / 14.7 / 15.5 % do host (steal médio 0.0); 210 / 235 / 248 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 720 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1503 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1050 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 3.9 | 4.1 | 9 | 8 | 0 | 512 | 0 | 0 / 0 |
| web | 71.4 | 76.0 | 78.7 | 84 | 82 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.6 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 72.2 | 76.4 | 78.8 | 2278 | 108 | 2174 | 6144 | 0 | 0 / 0 |
| nats | 16.5 | 18.2 | 19.1 | 304 | 301 | 0 | 1024 | 0 | 0 / 0 |
| bot | 38.8 | 44.1 | 48.6 | 307 | 305 | 0 | 1024 | 0 | 0 / 0 |
| slice | 202.5 | 213.5 | 219.5 | 3061 | 803 | 2214 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.6 | 1.9 |
| cliente /ws (ts → chegada) | 86.5 | 201.6 | 369.1 |
| ingest_lag (ts → commit) | 94.0 | 152.4 | 157.6 |
| live_delay (ts → envio ao cliente) | 77.7 | 255.8 | 481.5 |
| record_ready{close} (fim → gravado) | 105.2 | 153.2 | 157.4 |
| record_ready{idle} (fim → gravado) | 117.7 | 235.2 | 300.0 |
| record_ready{quic_close} (fim → gravado) | 150.0 | 298.5 | 312.7 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 247246 | 86 | 202 | 369 | 2160 |
| connection.closed | 36654 | 120 | 207 | 226 | 312 |
| connection.opened | 36659 | 102 | 149 | 160 | 2160 |
| connection.updated | 110794 | 74 | 318 | 391 | 451 |
| connection.updated/quic | 26170 | 48 | 209 | 220 | 310 |
| connection.updated/quic/h3 | 84598 | 81 | 340 | 399 | 451 |
| connection.updated/raw | 25 | 86 | 126 | 128 | 128 |
| connection.updated/tcp | 1 | 12 | 12 | 12 | 12 |
| dns.query | 4 | 92 | 134 | 134 | 134 |
| http.request | 63000 | 88 | 134 | 144 | 227 |
| packet.stray | 160 | 10 | 145 | 154 | 154 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 21380 | 135 | 194 | 213 | 312 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 24000 | 24000 | 0 | quic=657 quic/h3=23343 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.10 s (42 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 690830
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
- `store_late_packets_total`: 63630
- `store_stray_total`: 168

Relógio: servidor − local 2.203096ms no início, 2.173551ms no fim (ida e volta do ssh 16.548375ms).
Deslocamento acompanhado a cada 15 s (19 de 19 medições aceitas): 1.725093ms a 2.291233ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
