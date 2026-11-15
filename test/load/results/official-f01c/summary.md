Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T21:53:37Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 29999 abertas, 1 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 108 / p95 1340 / p99 1908 / máx 2613 ms (n=208563) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 110 / p95 1345 / p99 1912 / máx 2613 ms (n=197234) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 108 / p95 1340 / p99 1908 / máx 2613 ms (n=208563) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 110 / p95 1345 / p99 1911 / máx 2613 ms (n=197234) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 21.3 / p99 63.0 / máx 544.5 ms (n=2696) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 21.0 / p99 35.4 / máx 167.7 ms (n=2697) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 180 / p95 1465 / p99 2017 / máx 2663 ms (n=21753) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 205 / p95 1490 / p99 2065 / máx 2623 ms (n=5438) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 29999 (feed ws 29999, sse 29999, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 29999 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 1 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 28 (31)/768, raw 14 (16)/256, dns 4 (4)/256, store 81 (1319)/2048, nats 180 (199)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 4.3 / 6.0 / 7.8 % do host (steal médio 0.0); 69 / 96 / 125 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 677 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2696 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.3 | 11 | 10 | 512 | 0 |
| web | 20.5 | 23.4 | 25.9 | 31 | 28 | 768 | 0 |
| raw | 3.7 | 4.2 | 4.6 | 16 | 14 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 4 | 256 | 0 |
| store | 27.6 | 50.5 | 67.3 | 1319 | 81 | 2048 | 0 |
| nats | 7.9 | 9.7 | 10.9 | 199 | 180 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 28.1 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 7.0 |
| cliente /ws (ts → chegada) | 108.3 | 1340.2 | 1908.4 |
| ingest_lag (ts → commit) | 107.7 | 1653.0 | 2469.4 |
| live_delay (ts → envio ao cliente) | 107.0 | 1421.8 | 2295.6 |
| record_ready{close} (fim → gravado) | 115.2 | 1594.4 | 2333.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 224.1 | 1687.8 | 2354.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 197234 | 110 | 1345 | 1912 | 2613 |
| connection.closed | 27038 | 140 | 1435 | 2002 | 2613 |
| connection.opened | 27163 | 114 | 1381 | 1927 | 2542 |
| connection.updated | 97251 | 105 | 1283 | 1869 | 2535 |
| connection.updated/http1.0 | 3 | 58 | 137 | 137 | 137 |
| connection.updated/http1.1 | 13783 | 89 | 1314 | 1883 | 2527 |
| connection.updated/quic/h3 | 26207 | 116 | 1298 | 1866 | 2535 |
| connection.updated/raw | 11328 | 69 | 1216 | 1856 | 2527 |
| connection.updated/tcp | 4 | 11 | 12 | 12 | 12 |
| connection.updated/tls | 9723 | 100 | 1421 | 1990 | 2521 |
| connection.updated/tls/h2 | 22903 | 113 | 1227 | 1845 | 2501 |
| connection.updated/tls/http1.1 | 13299 | 123 | 1161 | 1805 | 2521 |
| connection.updated/tls/raw | 1 | 10 | 10 | 10 | 10 |
| dns.query | 3 | 113 | 1376 | 1376 | 1376 |
| http.request | 56700 | 99 | 1364 | 1914 | 2535 |
| packet.stray | 408 | 12 | 756 | 1576 | 2119 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 197 | 1482 | 2057 | 2613 |
| tcp | 21753 | 125 | 1422 | 1987 | 2558 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4499 | 4499 | 0 | http1.1=4499 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 801089
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 14577
- `store_stray_total`: 427

Relógio: servidor − local 2.175504ms no início, 1.314854ms no fim (ida e volta do ssh 16.580083ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): 898.678µs a 2.175504ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
