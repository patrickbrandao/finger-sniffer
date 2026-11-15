Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T20:38:46Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 10500 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 91 / p95 335 / p99 534 / máx 1107 ms (n=70204) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 93 / p95 340 / p99 538 / máx 1107 ms (n=66448) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 92 / p95 335 / p99 534 / máx 1108 ms (n=70204) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 93 / p95 340 / p99 537 / máx 1108 ms (n=66448) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 26.7 / p99 37.5 / máx 120.0 ms (n=900) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 19.5 / p99 34.1 / máx 155.1 ms (n=900) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 155 / p95 283 / p99 598 / máx 949 ms (n=7355) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 189 / p95 337 / p99 682 / máx 890 ms (n=1838) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 10500 (feed ws 10500, sse 10500, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 10500 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 27 (30)/768, raw 13 (15)/256, dns 2 (3)/256, store 66 (536)/2048, nats 178 (196)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 4.1 / 4.9 / 5.3 % do host (steal médio 0.0); 66 / 79 / 85 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 1139 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 900 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.3 | 3.6 | 3.9 | 9 | 8 | 512 | 0 |
| web | 20.5 | 22.3 | 24.0 | 30 | 27 | 768 | 0 |
| raw | 3.7 | 4.1 | 4.8 | 15 | 13 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 3 | 2 | 256 | 0 |
| store | 27.0 | 32.5 | 37.9 | 536 | 66 | 2048 | 0 |
| nats | 8.1 | 9.4 | 10.0 | 196 | 178 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.9 | 18.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 3.5 |
| cliente /ws (ts → chegada) | 91.5 | 335.2 | 534.4 |
| ingest_lag (ts → commit) | 86.4 | 250.6 | 707.7 |
| live_delay (ts → envio ao cliente) | 83.2 | 333.6 | 593.7 |
| record_ready{close} (fim → gravado) | 96.3 | 264.6 | 588.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 189.8 | 316.2 | 756.6 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 66448 | 93 | 340 | 538 | 1107 |
| connection.closed | 9005 | 123 | 258 | 584 | 881 |
| connection.opened | 9062 | 97 | 208 | 510 | 822 |
| connection.updated | 33087 | 88 | 368 | 543 | 1107 |
| connection.updated/http1.0 | 1 | 142 | 142 | 142 | 142 |
| connection.updated/http1.1 | 4589 | 75 | 184 | 514 | 781 |
| connection.updated/quic/h3 | 9004 | 97 | 401 | 574 | 1030 |
| connection.updated/raw | 3756 | 57 | 142 | 491 | 766 |
| connection.updated/tcp | 1 | 13 | 13 | 13 | 13 |
| connection.updated/tls | 3214 | 84 | 270 | 527 | 814 |
| connection.updated/tls/h2 | 7938 | 96 | 288 | 565 | 1107 |
| connection.updated/tls/http1.1 | 4584 | 102 | 297 | 614 | 909 |
| http.request | 18900 | 83 | 195 | 500 | 814 |
| packet.stray | 150 | 13 | 137 | 165 | 165 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 1838 | 180 | 328 | 673 | 881 |
| tcp | 7355 | 102 | 229 | 566 | 827 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 1575 | 1575 | 0 | http1.1=1575 |  |
| h1tls | 1575 | 1575 | 0 | tls/http1.1=1575 |  |
| h2 | 2100 | 2100 | 0 | tls/h2=2100 |  |
| h3 | 2100 | 2100 | 0 | quic/h3=2100 |  |
| raw-banner | 1260 | 1260 | 0 | raw=1260 |  |
| raw-echo | 1050 | 1050 | 0 | raw=1050 |  |
| raw-sink | 840 | 840 | 0 | raw=840 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 268623
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 4758
- `store_stray_total`: 161

Relógio: servidor − local 3.265502ms no início, 3.903181ms no fim (ida e volta do ssh 15.476792ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 3.265502ms a 3.970409ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
