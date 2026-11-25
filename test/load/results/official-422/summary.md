Commit `v0.5.2-115-gfc8dd3e`, início 2026-11-24T23:24:04Z, 100 novas/s, até 400 simultâneas (máx. visto 393), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 60000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 301 / p99 344 / máx 573 ms (n=403303) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 302 / p99 344 / máx 573 ms (n=387018) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 301 / p99 344 / máx 573 ms (n=403303) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 302 / p99 344 / máx 573 ms (n=387018) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 20.3 / p99 22.9 / máx 154.6 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 20.5 / p99 33.4 / máx 36.9 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 88 / p95 123 / p99 137 / máx 444 ms (n=43502) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 156 / p95 181 / p99 189 / máx 29006 ms (n=10878) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 60000 (feed ws 60000, sse 60000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 60000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-115-gfc8dd3e | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 41 (43)/768, raw 17 (19)/256, dns 3 (4)/256, store 154 (2472)/6144, nats 307 (310)/1024, bot 339 (341)/1024, slice 869 (3265)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 118 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 9.6 / 11.2 / 13.3 % do host (steal médio 0.0); 153 / 179 / 212 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 723 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.1 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 38.0 | 40.7 | 43.9 | 43 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.1 | 6.8 | 7.5 | 19 | 17 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 3 | 0 | 256 | 0 | 0 / 0 |
| store | 44.2 | 48.0 | 54.3 | 2472 | 154 | 2312 | 6144 | 0 | 0 / 0 |
| nats | 15.9 | 18.7 | 20.5 | 310 | 307 | 0 | 1024 | 0 | 0 / 0 |
| bot | 29.0 | 43.8 | 49.0 | 341 | 339 | 0 | 1024 | 118 | 0 / 0 |
| slice | 136.8 | 155.3 | 169.2 | 3265 | 869 | 2351 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.3 | 1.9 |
| cliente /ws (ts → chegada) | 60.2 | 300.6 | 343.6 |
| ingest_lag (ts → commit) | 57.7 | 143.2 | 275.5 |
| live_delay (ts → envio ao cliente) | 52.3 | 242.4 | 508.4 |
| record_ready{close} (fim → gravado) | 60.8 | 139.3 | 154.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 126.1 | 264.6 | 305.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 387018 | 60 | 302 | 344 | 573 |
| connection.closed | 54201 | 77 | 161 | 172 | 304 |
| connection.opened | 54201 | 65 | 98 | 108 | 183 |
| connection.updated | 181103 | 59 | 329 | 354 | 573 |
| connection.updated/http1.1 | 24305 | 53 | 82 | 94 | 169 |
| connection.updated/quic/h3 | 53980 | 62 | 342 | 364 | 409 |
| connection.updated/raw | 16285 | 53 | 83 | 88 | 212 |
| connection.updated/tcp | 1 | 11 | 11 | 11 | 11 |
| connection.updated/tls | 18903 | 56 | 87 | 94 | 167 |
| connection.updated/tls/h2 | 43258 | 61 | 329 | 350 | 570 |
| connection.updated/tls/http1.1 | 24371 | 62 | 334 | 353 | 573 |
| http.request | 113402 | 52 | 84 | 92 | 176 |
| packet.stray | 396 | 11 | 92 | 102 | 105 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 10878 | 148 | 173 | 180 | 307 |
| tcp | 43502 | 70 | 102 | 112 | 224 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=9000 |  |
| h1tls | 9000 | 9000 | 0 | tls/http1.1=9000 |  |
| h2 | 12000 | 12000 | 0 | tls/h2=12000 |  |
| h3 | 12000 | 12000 | 0 | quic/h3=12000 |  |
| raw-banner | 7200 | 7200 | 0 | raw=7200 |  |
| raw-echo | 6000 | 6000 | 0 | raw=6000 |  |
| raw-sink | 4800 | 4800 | 0 | raw=4800 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1643268
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
- `store_late_packets_total`: 252
- `store_stray_total`: 404

Relógio: servidor − local 1.325196ms no início, 1.500686ms no fim (ida e volta do ssh 16.732209ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): 725.907µs a 1.527005ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Todas as metas passaram.**
