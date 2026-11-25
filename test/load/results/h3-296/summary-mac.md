Commit `v0.5.2-115-gfc8dd3e`, início 2026-11-24T23:45:24Z, 100 novas/s, até 400 simultâneas (máx. visto 394), vida 3.8s, 3 trocas, 4m0s com 30s de aquecimento descartado, mix h3=1, origem mac; 24000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 91 / p95 348 / p99 394 / máx 540 ms (n=210233) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 91 / p95 348 / p99 394 / máx 540 ms (n=210206) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 90 / p95 348 / p99 394 / máx 540 ms (n=210233) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 90 / p95 348 / p99 394 / máx 540 ms (n=210206) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.0 / p95 0.0 / p99 0.0 / máx 0.0 ms (n=0) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 0.0 / p95 0.0 / p99 0.0 / máx 0.0 ms (n=0) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 0 / p95 0 / p99 0 / máx 0 ms (n=0) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 171 / p95 217 / p99 245 / máx 28996 ms (n=21374) | passou |
| RNF-01 | probes sem registro | 0 | 6 de 24000 (feed ws 23994, sse 23994, só API 0) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 24000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-115-gfc8dd3e | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/512, web 81 (83)/768, raw 8 (9)/256, dns 4 (4)/256, store 224 (2164)/6144, nats 300 (304)/1024, bot 235 (236)/1024, slice 862 (2877)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 0 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.0 / 14.5 / 15.1 % do host (steal médio 0.0); 209 / 232 / 242 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 710 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 0 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.7 | 4.1 | 4.5 | 12 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 71.2 | 76.4 | 77.6 | 83 | 81 | 0 | 768 | 0 | 0 / 0 |
| raw | 0.1 | 0.4 | 0.6 | 9 | 8 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 54.3 | 65.5 | 77.5 | 2164 | 224 | 1933 | 6144 | 0 | 0 / 0 |
| nats | 17.0 | 18.7 | 19.7 | 304 | 300 | 0 | 1024 | 0 | 0 / 0 |
| bot | 48.3 | 53.0 | 55.3 | 236 | 235 | 0 | 1024 | 0 | 0 / 0 |
| slice | 194.6 | 208.7 | 222.9 | 2877 | 862 | 1973 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) |  |  |  |
| api GET /api/v1/probes/{id} (servidor) |  |  |  |
| cliente /ws (ts → chegada) | 90.9 | 348.3 | 393.6 |
| ingest_lag (ts → commit) | 85.7 | 151.9 | 157.8 |
| live_delay (ts → envio ao cliente) | 84.2 | 421.8 | 589.1 |
| record_ready{close} (fim → gravado) | 79.4 | 154.5 | 256.3 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 152.3 | 299.1 | 312.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 210206 | 91 | 348 | 394 | 540 |
| connection.closed | 21087 | 161 | 208 | 233 | 352 |
| connection.opened | 21084 | 91 | 136 | 153 | 255 |
| connection.updated | 104898 | 89 | 375 | 403 | 540 |
| connection.updated/http1.1 | 6 | 13 | 106 | 106 | 106 |
| connection.updated/quic/h3 | 104865 | 89 | 375 | 403 | 540 |
| connection.updated/raw | 27 | 50 | 119 | 121 | 121 |
| dns.query | 4 | 73 | 104 | 104 | 104 |
| http.request | 63003 | 78 | 122 | 139 | 252 |
| packet.stray | 157 | 11 | 122 | 137 | 147 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 21374 | 162 | 208 | 234 | 352 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h3 | 24000 | 24000 | 0 | quic/h3=23994 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 686291
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 14
- `store_stray_total`: 166

Relógio: servidor − local 2.630922ms no início, 3.745202ms no fim (ida e volta do ssh 16.765667ms).
Deslocamento acompanhado a cada 15 s (19 de 19 medições aceitas): 2.29811ms a 3.745202ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
