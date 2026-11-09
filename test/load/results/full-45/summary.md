Commit `6facb2c`, início 2026-11-09T11:58:32Z, 45 novas/s, até 200 simultâneas (máx. visto 179), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 27001 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 120 / p95 709 / p99 3950 / máx 30134 ms (n=183176) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 117 / p95 417 / p99 721 / máx 30134 ms (n=175782) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 123 / p95 712 / p99 3952 / máx 30134 ms (n=183176) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 119 / p95 419 / p99 725 / máx 30134 ms (n=175782) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 22.5 / p95 41.5 / p99 52.9 / máx 175.6 ms (n=2699) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 23.1 / p95 42.3 / p99 54.6 / máx 462.9 ms (n=2699) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 160 / p95 423 / p99 709 / máx 1203 ms (n=19579) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 205 / p95 434 / p99 745 / máx 1126 ms (n=4895) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 27001 (feed ws 27001, sse 27001, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 15 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 27001 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | 6facb2c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (10)/96, web 28 (40)/96, raw 13 (18)/96, dns 4 (5)/96, store 69 (384)/384, nats 120 (189)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 46 / 82 / 87 (steal médio 0.0) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 727 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2699 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.7 | 2.0 | 2.2 | 10 | 8 | 96 |
| web | 12.3 | 13.4 | 14.6 | 40 | 28 | 96 |
| raw | 1.8 | 2.1 | 2.8 | 18 | 13 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 5 | 4 | 96 |
| store | 26.2 | 59.2 | 63.7 | 384 | 69 | 384 |
| nats | 4.0 | 4.7 | 5.1 | 189 | 120 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.2 | 2.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.9 | 3.9 |
| cliente /ws (ts → chegada) | 119.8 | 708.7 | 3949.9 |
| ingest_lag (ts → commit) | 97.9 | 413.3 | 1147.3 |
| live_delay (ts → envio ao cliente) | 112.8 | 839.5 | 4388.8 |
| record_ready{close} (fim → gravado) | 108.8 | 375.7 | 769.9 |
| record_ready{idle} (fim → gravado) | 99.2 | 552.3 | 615.2 |
| record_ready{quic_close} (fim → gravado) | 201.0 | 394.4 | 848.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 175782 | 117 | 417 | 721 | 30134 |
| connection.closed | 24348 | 135 | 401 | 689 | 1192 |
| connection.opened | 24502 | 117 | 382 | 686 | 1200 |
| connection.updated | 82779 | 128 | 3905 | 3976 | 11157 |
| connection.updated/http1.1 | 10995 | 105 | 353 | 653 | 1159 |
| connection.updated/quic/h3 | 24343 | 127 | 447 | 778 | 1447 |
| connection.updated/raw | 7390 | 3913 | 4200 | 4506 | 11157 |
| connection.updated/raw/unknown | 2 | 16 | 41 | 41 | 41 |
| connection.updated/tcp | 7 | 22 | 871 | 871 | 871 |
| connection.updated/tls | 8564 | 107 | 406 | 681 | 1123 |
| connection.updated/tls/h2 | 20201 | 124 | 438 | 782 | 1359 |
| connection.updated/tls/http1.1 | 11275 | 131 | 423 | 826 | 1343 |
| connection.updated/tls/raw | 2 | 51 | 5438 | 5438 | 5438 |
| http.request | 51031 | 106 | 374 | 667 | 1159 |
| packet.stray | 516 | 118 | 488 | 1189 | 30134 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 4895 | 191 | 417 | 731 | 1113 |
| tcp | 19579 | 121 | 394 | 676 | 1192 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4051 | 4051 | 4 | http1.1=4051 |  |
| h1tls | 4050 | 4050 | 4 | tls=1 tls/http1.1=4049 |  |
| h2 | 5400 | 5400 | 0 | tls/h2=5400 |  |
| h3 | 5400 | 5400 | 3 | quic/h3=5400 |  |
| raw-banner | 3240 | 3240 | 2 | raw=3240 |  |
| raw-echo | 2700 | 2700 | 1 | raw=2700 |  |
| raw-sink | 2160 | 2160 | 1 | raw=2160 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 725631
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 15
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 2037
- `store_stray_total`: 523

Relógio: vps602 − local 241.270876ms no início, 244.996645ms no fim (ida e volta do ssh 17.47975ms).

**Há metas que falharam.**
