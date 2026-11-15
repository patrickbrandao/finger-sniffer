Commit `v0.2.1-75-g1f83ec0`, início 2026-11-15T18:38:47Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 60000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 29 / p95 59477 / p99 60127 / máx 69626 ms (n=507090) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 29 / p95 59492 / p99 60133 / máx 69626 ms (n=502644) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 29 / p95 59477 / p99 60127 / máx 69625 ms (n=507090) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 29 / p95 59492 / p99 60133 / máx 69625 ms (n=502644) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 16.9 / p95 20.3 / p99 42.0 / máx 285.9 ms (n=2696) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 20.4 / p99 34.6 / máx 437.3 ms (n=2695) | passou |
| RNF-03 | erros na amostragem da API | 0 | 1 | **falhou** |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 53377 / p95 58541 / p99 59394 / máx 629997 ms (n=12047) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 147593 / p95 151933 / p99 212620 / máx 318716 ms (n=6914) | **falhou** |
| RNF-01 | probes sem registro | 0 | 38657 de 60000 (feed ws 21343, sse 21343, só API 0) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 60000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-75-g1f83ec0 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 48 (51)/768, raw 18 (20)/256, dns 7 (8)/256, store 138 (1602)/2048, nats 312 (330)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 9.7 / 13.2 / 14.3 % do host (steal médio 0.0); 155 / 211 / 229 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 789 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2696 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.1 | 4.4 | 9 | 8 | 512 | 0 |
| web | 38.2 | 40.8 | 42.5 | 51 | 48 | 768 | 0 |
| raw | 6.6 | 7.3 | 7.8 | 20 | 18 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.2 | 8 | 7 | 256 | 0 |
| store | 78.0 | 122.2 | 143.6 | 1602 | 138 | 2048 | 0 |
| nats | 10.1 | 12.0 | 14.5 | 330 | 312 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.4 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.0 |
| cliente /ws (ts → chegada) | 29.3 | 59476.9 | 60127.4 |
| ingest_lag (ts → commit) | 10000.0 | 10000.0 | 10000.0 |
| live_delay (ts → envio ao cliente) | 17.2 | 10000.0 | 10000.0 |
| record_ready{close} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 502644 | 29 | 59492 | 60133 | 69626 |
| connection.closed | 31795 | 22 | 55054 | 59707 | 64370 |
| connection.opened | 132910 | 55014 | 60003 | 62780 | 69626 |
| connection.updated | 50786 | 54581 | 59671 | 60079 | 64457 |
| connection.updated/h2 | 3242 | 24 | 55704 | 59916 | 60153 |
| connection.updated/h2c | 3635 | 54974 | 59962 | 60098 | 61018 |
| connection.updated/http1.1 | 10207 | 54685 | 59835 | 60073 | 60899 |
| connection.updated/quic | 1 | 17 | 17 | 17 | 17 |
| connection.updated/quic/h3 | 15254 | 55020 | 59897 | 60216 | 64457 |
| connection.updated/raw | 4446 | 29 | 87 | 2500 | 55669 |
| connection.updated/tcp | 1566 | 55042 | 56128 | 60173 | 60855 |
| connection.updated/tls | 5243 | 20 | 55110 | 57498 | 60280 |
| connection.updated/tls/h2 | 4281 | 22 | 248 | 2760 | 56543 |
| connection.updated/tls/http1.1 | 2911 | 25 | 257 | 3193 | 55290 |
| http.request | 32029 | 54999 | 59868 | 60091 | 64267 |
| packet.stray | 259570 | 21 | 55 | 54935 | 63040 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 6914 | 150082 | 152796 | 153904 | 154685 |
| tcp | 12047 | 55054 | 59980 | 60143 | 630104 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 9000 | 9000 | 0 | http1.1=3548 |  |
| h1tls | 9000 | 9000 | 0 | http1.1=2965 tcp=7 tls=575 tls/http1.1=132 |  |
| h2 | 12000 | 12000 | 0 | h2=1969 h2c=2995 tcp=16 tls=877 tls/h2=159 |  |
| h3 | 12000 | 12000 | 0 | quic/h3=7871 |  |
| raw-banner | 7200 | 7200 | 0 | raw=94 |  |
| raw-echo | 6000 | 6000 | 0 | raw=75 |  |
| raw-sink | 4800 | 4800 | 0 | raw=60 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1598656
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 0
- `store_stray_total`: 269060

Relógio: servidor − local 11.939689ms no início, 4.579106ms no fim (ida e volta do ssh 16.828625ms).
Deslocamento acompanhado a cada 15 s (87 de 87 medições aceitas): 4.579106ms a 12.602615ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
