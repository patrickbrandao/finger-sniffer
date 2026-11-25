Commit `v0.5.2-137-g7b95d4d`, início 2026-11-25T05:33:13Z, 100 novas/s, até 400 simultâneas (máx. visto 383), vida 3.8s, 3 trocas, 5m0s com 30s de aquecimento descartado, mix h3=1, origem finger-01; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 35 / p95 2136 / p99 2156 / máx 2285 ms (n=216021) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 35 / p95 2136 / p99 2156 / máx 2285 ms (n=215985) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 35 / p95 2137 / p99 2157 / máx 2285 ms (n=216021) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 35 / p95 2137 / p99 2157 / máx 2285 ms (n=215985) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.8 / p95 1.1 / p99 1.5 / máx 4.8 ms (n=1350) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 1.0 / p95 1.3 / p99 1.8 / máx 5.4 ms (n=1350) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 30077 / p95 30131 / p99 30210 / máx 30288 ms (n=25557) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 28027, sse 28027, só API 1973) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 325 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-137-g7b95d4d, versions_match=false | **falhou** |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 81 (83)/768, raw 7 (9)/256, dns 6 (6)/256, store 400 (3184)/6144, nats 293 (296)/1024, bot 504 (506)/1024, slice 1300 (4643)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 36 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 14.2 / 16.0 / 17.0 % do host (steal médio 0.0); 228 / 255 / 272 % de um núcleo (16 vCPU) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 690 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 1350 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 1.2 | 1.6 | 2.0 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 69.8 | 73.9 | 78.1 | 83 | 81 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.6 | 9 | 7 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 6 | 6 | 0 | 256 | 0 | 0 / 0 |
| store | 56.9 | 66.7 | 68.8 | 3184 | 400 | 2775 | 6144 | 0 | 0 / 0 |
| nats | 14.3 | 16.1 | 16.7 | 296 | 293 | 0 | 1024 | 0 | 0 / 0 |
| bot | 33.8 | 49.5 | 53.5 | 506 | 504 | 0 | 1024 | 36 | 0 / 0 |
| slice | 176.2 | 198.6 | 211.4 | 4643 | 1300 | 3157 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.1 | 1.9 |
| cliente /ws (ts → chegada) | 34.6 | 2136.0 | 2156.1 |
| ingest_lag (ts → commit) | 89.2 | 151.7 | 157.3 |
| live_delay (ts → envio ao cliente) | 38.2 | 2259.7 | 2461.4 |
| record_ready{close} (fim → gravado) | 114.4 | 238.9 | 300.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 215985 | 35 | 2136 | 2156 | 2285 |
| connection.closed | 26730 | 26 | 31 | 36 | 213 |
| connection.opened | 27100 | 2104 | 2155 | 2169 | 2285 |
| connection.updated | 81021 | 10 | 16 | 19 | 215 |
| connection.updated/http1.1 | 4 | 12 | 120 | 120 | 120 |
| connection.updated/quic/h3 | 80973 | 10 | 16 | 19 | 38 |
| connection.updated/raw | 34 | 76 | 127 | 142 | 142 |
| connection.updated/tcp | 4 | 5 | 12 | 12 | 12 |
| connection.updated/tls | 4 | 127 | 215 | 215 | 215 |
| connection.updated/tls/raw | 2 | 4 | 14 | 14 | 14 |
| dns.query | 8 | 70 | 136 | 136 | 136 |
| http.request | 81002 | 842 | 2143 | 2158 | 2284 |
| packet.stray | 160 | 2 | 148 | 153 | 155 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 25557 | 30077 | 30131 | 30209 | 30288 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 30000 | 30000 | 0 | quic/h3=28177 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | não medido | **não** |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.10 s (54 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 680
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
- `store_late_packets_total`: 8
- `store_stray_total`: 166

Relógio: servidor − local -283ns no início, -2.286µs no fim (ida e volta do ssh 21.39µs).
Deslocamento acompanhado a cada 15 s (23 de 23 medições aceitas): -2.286µs a 4.069µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
