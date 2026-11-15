Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T21:44:10Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 9m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 26993 abertas, 7 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 95 / p95 433 / p99 881 / máx 1784 ms (n=198984) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 96 / p95 439 / p99 885 / máx 1784 ms (n=188233) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 95 / p95 433 / p99 880 / máx 1784 ms (n=198984) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 96 / p95 439 / p99 884 / máx 1784 ms (n=188233) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 20.9 / p99 33.7 / máx 383.0 ms (n=2547) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.4 / p95 23.5 / p99 48.1 / máx 337.5 ms (n=2548) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 158 / p95 494 / p99 973 / máx 1692 ms (n=20547) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 191 / p95 548 / p99 1027 / máx 29057 ms (n=5138) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 26993 (feed ws 26993, sse 26993, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 26993 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 7 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 28 (31)/768, raw 14 (16)/256, dns 4 (4)/256, store 79 (1197)/2048, nats 179 (198)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 4.1 / 5.0 / 5.9 % do host (steal médio 0.0); 66 / 80 / 95 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 660 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2547 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.3 | 3.7 | 4.4 | 10 | 9 | 512 | 0 |
| web | 20.3 | 21.8 | 23.8 | 31 | 28 | 768 | 0 |
| raw | 3.7 | 4.3 | 4.9 | 16 | 14 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 4 | 256 | 0 |
| store | 26.7 | 32.7 | 43.6 | 1197 | 79 | 2048 | 0 |
| nats | 8.0 | 9.5 | 11.2 | 198 | 179 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 7.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.2 | 28.5 |
| cliente /ws (ts → chegada) | 94.9 | 432.7 | 880.6 |
| ingest_lag (ts → commit) | 90.4 | 490.6 | 1233.6 |
| live_delay (ts → envio ao cliente) | 87.6 | 495.6 | 1037.9 |
| record_ready{close} (fim → gravado) | 99.8 | 458.3 | 1069.5 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 194.1 | 524.7 | 1122.5 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 188233 | 96 | 439 | 885 | 1784 |
| connection.closed | 25539 | 127 | 481 | 946 | 1784 |
| connection.opened | 25641 | 101 | 430 | 874 | 1651 |
| connection.updated | 93927 | 92 | 432 | 879 | 1641 |
| connection.updated/http1.0 | 4 | 63 | 128 | 128 | 128 |
| connection.updated/http1.1 | 13047 | 78 | 376 | 839 | 1605 |
| connection.updated/quic/h3 | 25487 | 101 | 469 | 913 | 1641 |
| connection.updated/raw | 10750 | 60 | 302 | 799 | 1591 |
| connection.updated/tcp | 4 | 11 | 15 | 15 | 15 |
| connection.updated/tls | 9172 | 89 | 498 | 917 | 1629 |
| connection.updated/tls/h2 | 22449 | 101 | 435 | 876 | 1637 |
| connection.updated/tls/http1.1 | 13013 | 105 | 441 | 870 | 1560 |
| connection.updated/tls/raw | 1 | 12 | 12 | 12 | 12 |
| dns.query | 2 | 30 | 65 | 65 | 65 |
| http.request | 53533 | 87 | 416 | 856 | 1637 |
| packet.stray | 342 | 14 | 142 | 845 | 1014 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5138 | 183 | 538 | 1001 | 1784 |
| tcp | 20547 | 107 | 465 | 933 | 1683 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4048 | 4048 | 0 | http1.1=4048 |  |
| h1tls | 4048 | 4048 | 0 | tls/http1.1=4048 |  |
| h2 | 5397 | 5397 | 0 | tls/h2=5397 |  |
| h3 | 5400 | 5400 | 0 | quic/h3=5400 |  |
| raw-banner | 3240 | 3240 | 0 | raw=3240 |  |
| raw-echo | 2700 | 2700 | 0 | raw=2700 |  |
| raw-sink | 2160 | 2160 | 0 | raw=2160 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 760387
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 14021
- `store_stray_total`: 349

Relógio: servidor − local 1.244ms no início, 2.008071ms no fim (ida e volta do ssh 16.639791ms).
Deslocamento acompanhado a cada 15 s (39 de 39 medições aceitas): 537.356µs a 2.540375ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
