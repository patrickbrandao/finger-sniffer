Commit `v0.5.2-115-gfc8dd3e`, início 2026-11-25T00:06:54Z, 100 novas/s, até 400 simultâneas (máx. visto 384), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem finger-01; 60000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 29 / p95 2113 / p99 2240 / máx 2612 ms (n=334337) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 41 / p95 2115 / p99 2252 / máx 2612 ms (n=318073) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 29 / p95 2114 / p99 2240 / máx 2613 ms (n=334337) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 41 / p95 2115 / p99 2252 / máx 2613 ms (n=318073) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 0.7 / p95 0.9 / p99 1.2 / máx 5.0 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 0.9 / p95 1.2 / p99 1.5 / máx 7.1 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 28784 / p95 30078 / p99 52210 / máx 81653 ms (n=41058) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 30051 / p95 30260 / p99 51211 / máx 81874 ms (n=10273) | **falhou** |
| RNF-01 | probes sem registro | 0 | 1543 de 60000 (feed ws 56713, sse 56713, só API 1744) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 60000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-115-gfc8dd3e | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 45 (48)/768, raw 18 (20)/256, dns 4 (5)/256, store 265 (2946)/6144, nats 223 (226)/1024, bot 339 (341)/1024, slice 888 (3635)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 4 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 11.7 / 13.6 / 15.9 % do host (steal médio 0.0); 187 / 218 / 254 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 761 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |
| ADR 0046 | falhas do gerador (erro no cliente, puladas) pelo critério do item 2 | sem falha ou falha do cliente aceita | sem falha do gerador | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 1.3 | 1.6 | 1.9 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 37.7 | 40.3 | 43.2 | 48 | 45 | 0 | 768 | 0 | 0 / 0 |
| raw | 5.6 | 6.2 | 6.9 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 64.3 | 98.8 | 114.4 | 2946 | 265 | 2681 | 6144 | 0 | 0 / 0 |
| nats | 12.8 | 15.4 | 16.6 | 226 | 223 | 0 | 1024 | 0 | 0 / 0 |
| bot | 17.7 | 29.7 | 36.6 | 341 | 339 | 0 | 1024 | 4 | 0 / 0 |
| slice | 139.4 | 169.2 | 195.5 | 3635 | 888 | 2720 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.6 |
| cliente /ws (ts → chegada) | 29.1 | 2113.4 | 2239.5 |
| ingest_lag (ts → commit) | 67.9 | 414.5 | 4277.5 |
| live_delay (ts → envio ao cliente) | 36.3 | 2279.0 | 2468.5 |
| record_ready{close} (fim → gravado) | 78.9 | 217.6 | 541.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) |  |  |  |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 318073 | 41 | 2115 | 2252 | 2612 |
| connection.closed | 52738 | 22 | 27 | 33 | 536 |
| connection.opened | 52805 | 2083 | 2167 | 2454 | 2612 |
| connection.updated | 115000 | 4 | 8 | 14 | 516 |
| connection.updated/http1.0 | 2 | 43 | 69 | 69 | 69 |
| connection.updated/http1.1 | 16199 | 4 | 8 | 16 | 173 |
| connection.updated/quic/h3 | 32653 | 4 | 7 | 13 | 237 |
| connection.updated/raw | 16262 | 4 | 8 | 10 | 516 |
| connection.updated/raw/unknown | 2 | 6 | 65 | 65 | 65 |
| connection.updated/tcp | 4 | 3 | 4 | 4 | 4 |
| connection.updated/tls | 27 | 54 | 329 | 334 | 334 |
| connection.updated/tls/h2 | 34027 | 4 | 8 | 17 | 264 |
| connection.updated/tls/http1.1 | 15824 | 4 | 8 | 52 | 252 |
| dns.query | 8 | 47 | 86 | 86 | 86 |
| http.request | 113402 | 814 | 2118 | 2290 | 2607 |
| packet.stray | 384 | 1 | 107 | 132 | 207 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 10273 | 30050 | 30141 | 30405 | 30517 |
| tcp | 41058 | 30062 | 30136 | 30417 | 30542 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=8754 |  |
| h1tls | 9000 | 9000 | 0 | tls/h2=235 tls/http1.1=7951 |  |
| h2 | 12000 | 12000 | 0 | tls/h2=10942 |  |
| h3 | 12000 | 12000 | 0 | quic/h3=11376 |  |
| raw-banner | 7200 | 7200 | 0 | raw=7032 |  |
| raw-echo | 6000 | 6000 | 0 | raw=5860 |  |
| raw-sink | 4800 | 4800 | 0 | raw=4688 |  |

Falhas do gerador (ADR 0046 item 2): 0 conexões com erro no cliente, 0 puladas pelo teto → **sem falha do gerador**.

| Condição | Medido | Atende |
| --- | --- | --- |
| modo degradado desligado (degraded 0) | 0 | sim |
| kernel_drops sem crescer | 0 | sim |
| flows_dropped sem crescer | 0 | sim |
| conntrack -S drop/insert_failed/early_drop sem crescer | 0 / 0 / 0 | sim |
| nr_throttled sem crescer (units do espelho) | 0 em todas | sim |
| backlog do ingest < 1 s | máx 0.09 s (108 amostras) | sim |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1477
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
- `store_late_packets_total`: 19
- `store_stray_total`: 396

Relógio: servidor − local 127ns no início, 3.294µs no fim (ida e volta do ssh 22.156µs).
Deslocamento acompanhado a cada 15 s (43 de 43 medições aceitas): -999ns a 5.441µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
