Commit `v0.3.0-3-g38e4415`, início 2026-11-16T03:02:10Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 9m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 27000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 86 / p95 236 / p99 379 / máx 1027 ms (n=198827) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 88 / p95 242 / p99 380 / máx 1027 ms (n=188188) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 86 / p95 236 / p99 379 / máx 1027 ms (n=198827) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 88 / p95 242 / p99 380 / máx 1027 ms (n=188188) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 20.8 / p99 33.6 / máx 156.2 ms (n=2550) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.4 / p95 22.3 / p99 45.2 / máx 172.2 ms (n=2550) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 149 / p95 231 / p99 282 / máx 713 ms (n=20554) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 183 / p95 232 / p99 336 / máx 29001 ms (n=5137) | passou |
| RNF-01 | probes sem registro | 0 | 1 de 27000 (feed ws 26999, sse 26999, só API 0) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 27000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-3-g38e4415 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 28 (30)/768, raw 13 (14)/256, dns 3 (3)/256, store 75 (1254)/2048, nats 179 (198)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 3.8 / 4.6 / 5.5 % do host (steal médio 0.0); 61 / 74 / 88 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 674 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1503 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2550 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.1 | 3.5 | 4.0 | 11 | 10 | 512 | 0 |
| web | 20.0 | 22.0 | 25.1 | 30 | 28 | 768 | 0 |
| raw | 3.5 | 3.9 | 7.1 | 14 | 13 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 3 | 3 | 256 | 0 |
| store | 22.8 | 25.5 | 31.3 | 1254 | 75 | 2048 | 0 |
| nats | 8.0 | 9.3 | 10.8 | 198 | 179 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.5 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 25.3 |
| cliente /ws (ts → chegada) | 86.4 | 236.5 | 378.6 |
| ingest_lag (ts → commit) | 78.7 | 153.8 | 499.3 |
| live_delay (ts → envio ao cliente) | 75.5 | 257.0 | 504.2 |
| record_ready{close} (fim → gravado) | 86.9 | 154.1 | 270.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 172.4 | 304.2 | 315.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 188188 | 88 | 242 | 380 | 1027 |
| connection.closed | 25549 | 117 | 207 | 255 | 845 |
| connection.opened | 25696 | 93 | 145 | 219 | 763 |
| connection.updated | 93604 | 84 | 318 | 396 | 1027 |
| connection.updated/http1.0 | 4 | 55 | 120 | 120 | 120 |
| connection.updated/http1.1 | 12940 | 71 | 130 | 179 | 663 |
| connection.updated/quic/h3 | 25507 | 92 | 379 | 413 | 911 |
| connection.updated/raw | 10639 | 57 | 128 | 165 | 650 |
| connection.updated/tcp | 10 | 11 | 15 | 15 | 15 |
| connection.updated/tls | 9081 | 80 | 129 | 277 | 736 |
| connection.updated/tls/h2 | 22408 | 91 | 256 | 310 | 1027 |
| connection.updated/tls/http1.1 | 13015 | 96 | 262 | 347 | 868 |
| dns.query | 1 | 53 | 53 | 53 | 53 |
| http.request | 53555 | 79 | 130 | 199 | 750 |
| packet.stray | 422 | 12 | 125 | 154 | 389 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5137 | 174 | 224 | 314 | 845 |
| tcp | 20554 | 95 | 158 | 240 | 705 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4050 | 4050 | 0 | http1.1=4050 |  |
| h1tls | 4050 | 4050 | 0 | tls/http1.1=4050 |  |
| h2 | 5400 | 5400 | 0 | tls/h2=5400 |  |
| h3 | 5400 | 5400 | 0 | quic/h3=5399 |  |
| raw-banner | 3240 | 3240 | 0 | raw=3240 |  |
| raw-echo | 2700 | 2700 | 0 | raw=2700 |  |
| raw-sink | 2160 | 2160 | 0 | raw=2160 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 757139
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 13308
- `store_stray_total`: 437

Relógio: servidor − local 1.292721ms no início, 2.272923ms no fim (ida e volta do ssh 16.915042ms).
Deslocamento acompanhado a cada 15 s (39 de 39 medições aceitas): 389.703µs a 2.545021ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
