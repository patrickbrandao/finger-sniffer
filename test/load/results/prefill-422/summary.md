Commit `v0.5.2-115-gfc8dd3e`, início 2026-11-24T23:14:35Z, 100 novas/s, até 400 simultâneas (máx. visto 394), vida 3.8s, 3 trocas, 9m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 54000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 60 / p95 300 / p99 344 / máx 2108 ms (n=380918) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 302 / p99 345 / máx 2108 ms (n=365553) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 60 / p95 300 / p99 344 / máx 2108 ms (n=380918) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 60 / p95 302 / p99 345 / máx 2108 ms (n=365553) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 21.1 / p99 25.5 / máx 40.6 ms (n=2550) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 20.9 / p99 33.6 / máx 153.1 ms (n=2550) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 88 / p95 122 / p99 135 / máx 642 ms (n=41102) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 156 / p95 181 / p99 188 / máx 29003 ms (n=10278) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 54000 (feed ws 54000, sse 54000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 54000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.2-115-gfc8dd3e | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 40 (43)/768, raw 17 (19)/256, dns 3 (4)/256, store 142 (2228)/6144, nats 307 (310)/1024, bot 302 (303)/1024, slice 821 (2982)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 2 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 9.7 / 10.9 / 11.9 % do host (steal médio 0.0); 154 / 174 / 190 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 720 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2550 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 3.8 | 4.4 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 38.1 | 40.6 | 42.0 | 43 | 40 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.1 | 6.8 | 7.4 | 19 | 17 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 3 | 0 | 256 | 0 | 0 / 0 |
| store | 42.1 | 47.2 | 53.1 | 2228 | 142 | 2079 | 6144 | 0 | 0 / 0 |
| nats | 16.0 | 18.8 | 20.9 | 310 | 307 | 0 | 1024 | 0 | 0 / 0 |
| bot | 28.2 | 37.2 | 43.2 | 303 | 302 | 0 | 1024 | 2 | 0 / 0 |
| slice | 134.1 | 145.4 | 153.4 | 2982 | 821 | 2118 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.4 | 1.9 |
| cliente /ws (ts → chegada) | 59.7 | 299.6 | 344.4 |
| ingest_lag (ts → commit) | 57.4 | 142.8 | 275.0 |
| live_delay (ts → envio ao cliente) | 52.1 | 242.8 | 510.7 |
| record_ready{close} (fim → gravado) | 60.7 | 138.9 | 154.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 125.7 | 262.1 | 305.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 365553 | 60 | 302 | 345 | 2108 |
| connection.closed | 51209 | 77 | 160 | 172 | 263 |
| connection.opened | 51213 | 65 | 97 | 106 | 2108 |
| connection.updated | 171013 | 58 | 328 | 355 | 588 |
| connection.updated/http1.1 | 22956 | 53 | 81 | 92 | 222 |
| connection.updated/quic/h3 | 50983 | 61 | 344 | 366 | 403 |
| connection.updated/raw | 15365 | 52 | 82 | 88 | 237 |
| connection.updated/tcp | 3 | 10 | 10 | 10 | 10 |
| connection.updated/tls | 17851 | 55 | 86 | 92 | 249 |
| connection.updated/tls/h2 | 40853 | 61 | 329 | 350 | 539 |
| connection.updated/tls/http1.1 | 23002 | 62 | 336 | 353 | 588 |
| dns.query | 5 | 47 | 53 | 53 | 53 |
| http.request | 107102 | 52 | 83 | 90 | 1900 |
| packet.stray | 376 | 10 | 86 | 96 | 113 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 10278 | 147 | 172 | 179 | 292 |
| tcp | 41102 | 70 | 101 | 110 | 212 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 8100 | 8100 | 0 | http1.1=8100 |  |
| h1tls | 8100 | 8100 | 0 | tls/http1.1=8100 |  |
| h2 | 10800 | 10800 | 0 | tls/h2=10800 |  |
| h3 | 10800 | 10800 | 0 | quic/h3=10800 |  |
| raw-banner | 6480 | 6480 | 0 | raw=6480 |  |
| raw-echo | 5400 | 5400 | 0 | raw=5400 |  |
| raw-sink | 4320 | 4320 | 0 | raw=4320 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1557603
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
- `store_late_packets_total`: 193
- `store_stray_total`: 389

Relógio: servidor − local 117.241µs no início, 1.317692ms no fim (ida e volta do ssh 16.475667ms).
Deslocamento acompanhado a cada 15 s (39 de 39 medições aceitas): -169.608µs a 1.392884ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
