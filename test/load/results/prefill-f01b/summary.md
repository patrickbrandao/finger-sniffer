Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T20:58:51Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 9m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 53997 abertas, 3 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 25888 / p95 54450 / p99 55035 / máx 160196 ms (n=394444) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 27501 / p95 54474 / p99 55041 / máx 160196 ms (n=368959) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 25888 / p95 54450 / p99 55036 / máx 160196 ms (n=394444) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 27501 / p95 54474 / p99 55041 / máx 160196 ms (n=368959) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.0 / p95 18.9 / p99 33.2 / máx 109.6 ms (n=2549) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 19.1 / p99 36.3 / máx 226.3 ms (n=2550) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 33494 / p95 55214 / p99 64064 / máx 67472 ms (n=39796) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 34665 / p95 61479 / p99 64691 / máx 73171 ms (n=10271) | **falhou** |
| RNF-01 | probes sem registro | 0 | 1060 de 53997 (feed ws 52678, sse 52678, só API 259) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 53997 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 3 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 92 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 9 (10)/512, web 42 (44)/768, raw 18 (20)/256, dns 3 (3)/256, store 120 (2026)/2048, nats 312 (331)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.3 / 13.6 / 15.7 % do host (steal médio 0.0); 117 / 218 / 252 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 700 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2549 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.2 | 5.5 | 10 | 9 | 512 | 0 |
| web | 39.1 | 43.1 | 48.3 | 44 | 42 | 768 | 0 |
| raw | 6.7 | 7.6 | 8.5 | 20 | 18 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.2 | 3 | 3 | 256 | 0 |
| store | 44.3 | 129.3 | 142.9 | 2026 | 120 | 2048 | 0 |
| nats | 11.4 | 15.3 | 19.2 | 331 | 312 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 3.8 |
| cliente /ws (ts → chegada) | 25888.2 | 54449.7 | 55034.9 |
| ingest_lag (ts → commit) | 10000.0 | 10000.0 | 10000.0 |
| live_delay (ts → envio ao cliente) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{close} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 368959 | 27501 | 54474 | 55041 | 160196 |
| connection.closed | 51039 | 26877 | 54376 | 55063 | 58717 |
| connection.opened | 52249 | 35307 | 54830 | 55113 | 160196 |
| connection.updated | 186172 | 18242 | 54310 | 54996 | 56939 |
| connection.updated/h2 | 1101 | 53013 | 55239 | 55480 | 56698 |
| connection.updated/h2c | 1022 | 54345 | 54996 | 55093 | 55184 |
| connection.updated/http1.0 | 6 | 38710 | 52341 | 52341 | 52341 |
| connection.updated/http1.1 | 26346 | 22405 | 54477 | 54996 | 56699 |
| connection.updated/quic/h3 | 47610 | 30668 | 54420 | 55027 | 56710 |
| connection.updated/raw | 25483 | 1452 | 53717 | 54855 | 56519 |
| connection.updated/raw/unknown | 2 | 11 | 48123 | 48123 | 48123 |
| connection.updated/tcp | 116 | 55043 | 55144 | 55219 | 55229 |
| connection.updated/tls | 17631 | 31883 | 54343 | 54985 | 56694 |
| connection.updated/tls/h2 | 42439 | 15021 | 54061 | 54945 | 56920 |
| connection.updated/tls/http1.1 | 24416 | 14845 | 53992 | 54958 | 56939 |
| dns.query | 5 | 46413 | 52922 | 52922 | 52922 |
| http.request | 100578 | 31106 | 54359 | 54969 | 56699 |
| packet.stray | 4401 | 13 | 130 | 41429 | 55036 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 10271 | 34648 | 63059 | 65800 | 68584 |
| tcp | 39796 | 33473 | 55118 | 64758 | 68609 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 8100 | 8100 | 0 | http1.1=8081 |  |
| h1tls | 8100 | 8100 | 0 | http1.1=491 tls=6 tls/http1.1=7586 |  |
| h2 | 10800 | 10800 | 0 | h2=592 h2c=96 tls/h2=10112 |  |
| h3 | 10797 | 10797 | 0 | quic/h3=10793 |  |
| raw-banner | 6480 | 6480 | 0 | raw=5963 |  |
| raw-echo | 5400 | 5400 | 0 | raw=4982 |  |
| raw-sink | 4320 | 4320 | 0 | raw=3976 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1520129
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 43032
- `store_stray_total`: 4413

Relógio: servidor − local 4.651076ms no início, 5.256439ms no fim (ida e volta do ssh 16.488959ms).
Deslocamento acompanhado a cada 15 s (40 de 40 medições aceitas): 4.295082ms a 5.256439ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
