> Nota: esta rodada saiu sem o `loadmon sample`; o `cgroup.csv` do relatório foi montado com uma amostra de 4 s repetida, então as linhas de CPU/RAM por unit e `nr_throttled` não valem. Só a cobertura dos probes e os contadores do `/metrics` contam.

Commit `v0.5.2-126-g5830de3`, início 2026-11-25T01:43:18Z, 100 novas/s, até 400 simultâneas (máx. visto 382), vida 3.8s, 3 trocas, 4m0s com 30s de aquecimento descartado, mix h3=1, origem finger-01; 24000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 48 / p95 2167 / p99 2230 / máx 2298 ms (n=260961) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 48 / p95 2167 / p99 2230 / máx 2298 ms (n=260934) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 49 / p95 2169 / p99 2230 / máx 2302 ms (n=260961) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 49 / p95 2169 / p99 2230 / máx 2302 ms (n=260934) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.8 / p95 1.0 / p99 1.2 / máx 4.5 ms (n=1050) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 1.1 / p95 1.5 / p99 2.5 / máx 6.4 ms (n=1050) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 823 / p95 1280 / p99 1418 / máx 30236 ms (n=21359) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 24000 (feed ws 23979, sse 23979, só API 21) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 24000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-126-g5830de3 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 81 (82)/768, raw 6 (7)/256, dns 4 (5)/256, store 107 (3249)/6144, nats 298 (300)/1024, bot 599 (602)/1024, slice 1104 (4323)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 0 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 0.0 / 0.0 / 0.0 % do host (steal médio 0.0); 0 / 0 / 0 % de um núcleo (16 vCPU) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 615 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1503 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1050 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 0.0 | 0.0 | 0.0 | 9 | 8 | 0 | 512 | 0 | 0 / 0 |
| web | 0.0 | 0.0 | 0.0 | 82 | 81 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.0 | 0.0 | 0.0 | 7 | 6 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.0 | 0.0 | 0.0 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 0.0 | 0.0 | 0.0 | 3249 | 107 | 3132 | 6144 | 0 | 0 / 0 |
| nats | 0.0 | 0.0 | 0.0 | 300 | 298 | 0 | 1024 | 0 | 0 / 0 |
| bot | 0.0 | 0.0 | 0.0 | 602 | 599 | 0 | 1024 | 0 | 0 / 0 |
| slice | 0.0 | 0.0 | 0.0 | 4323 | 1104 | 3172 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.6 | 1.9 |
| cliente /ws (ts → chegada) | 47.6 | 2166.7 | 2229.6 |
| ingest_lag (ts → commit) | 84.2 | 152.5 | 162.7 |
| live_delay (ts → envio ao cliente) | 49.1 | 2338.4 | 2477.2 |
| record_ready{close} (fim → gravado) | 94.3 | 197.9 | 292.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 260934 | 48 | 2167 | 2230 | 2298 |
| connection.closed | 62337 | 27 | 63 | 76 | 162 |
| connection.opened | 62673 | 2105 | 2215 | 2254 | 2298 |
| connection.updated | 72787 | 9 | 21 | 29 | 136 |
| connection.updated/http1.1 | 2 | 8 | 126 | 126 | 126 |
| connection.updated/quic | 20815 | 9 | 24 | 31 | 51 |
| connection.updated/quic/h3 | 51942 | 8 | 18 | 28 | 51 |
| connection.updated/raw | 27 | 77 | 130 | 136 | 136 |
| connection.updated/tcp | 1 | 5 | 5 | 5 | 5 |
| dns.query | 4 | 66 | 129 | 129 | 129 |
| http.request | 63001 | 2040 | 2182 | 2230 | 2298 |
| packet.stray | 159 | 2 | 141 | 164 | 184 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 21359 | 2874 | 3346 | 3482 | 30235 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 24000 | 24000 | 0 | quic/h3=23979 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | não medido | **não** |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.11 s (42 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 514
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
- `store_late_packets_total`: 4
- `store_stray_total`: 168

Relógio: servidor − local -179ns no início, -261ns no fim (ida e volta do ssh 20.478µs).
Deslocamento acompanhado a cada 15 s (19 de 19 medições aceitas): -1.122µs a 4.82µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
