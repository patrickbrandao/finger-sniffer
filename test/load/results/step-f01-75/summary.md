Commit `v0.2.1-83-gaf14a7c`, início 2026-11-15T20:45:19Z, 75 novas/s, até 300 simultâneas (máx. visto 300), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 15751 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 93 / p95 922 / p99 1273 / máx 2134 ms (n=107095) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 96 / p95 929 / p99 1278 / máx 2134 ms (n=101376) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 92 / p95 922 / p99 1273 / máx 2134 ms (n=107095) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 96 / p95 929 / p99 1278 / máx 2134 ms (n=101376) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.1 / p95 21.3 / p99 39.4 / máx 164.3 ms (n=899) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.4 / p95 21.8 / p99 75.6 / máx 262.9 ms (n=900) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 153 / p95 982 / p99 1322 / máx 1707 ms (n=11033) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 209 / p95 1055 / p99 1365 / máx 1800 ms (n=2757) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 15751 (feed ws 15750, sse 15750, só API 1) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 15751 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.2.1-83-gaf14a7c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (9)/512, web 34 (36)/768, raw 16 (17)/256, dns 2 (3)/256, store 92 (1177)/2048, nats 254 (273)/1024 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 6.1 / 7.8 / 9.1 % do host (steal médio 0.0); 98 / 125 / 146 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 612 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 899 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB | Δ nr_throttled |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.5 | 3.9 | 4.1 | 9 | 8 | 512 | 0 |
| web | 29.9 | 32.2 | 34.6 | 36 | 34 | 768 | 0 |
| raw | 5.6 | 6.2 | 6.7 | 17 | 16 | 256 | 0 |
| dns | 0.1 | 0.1 | 0.1 | 3 | 2 | 256 | 0 |
| store | 39.4 | 60.6 | 78.8 | 1177 | 92 | 2048 | 0 |
| nats | 10.1 | 12.0 | 14.0 | 273 | 254 | 1024 | 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 16.7 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.3 | 54.2 |
| cliente /ws (ts → chegada) | 92.7 | 921.7 | 1273.4 |
| ingest_lag (ts → commit) | 88.8 | 1041.8 | 2189.1 |
| live_delay (ts → envio ao cliente) | 87.6 | 998.4 | 1258.8 |
| record_ready{close} (fim → gravado) | 121.0 | 1039.7 | 1528.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 226.2 | 1102.3 | 1914.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 101376 | 96 | 929 | 1278 | 2134 |
| connection.closed | 13501 | 142 | 990 | 1332 | 1792 |
| connection.opened | 13548 | 95 | 920 | 1245 | 1631 |
| connection.updated | 51567 | 82 | 909 | 1285 | 2134 |
| connection.updated/http1.1 | 7732 | 63 | 830 | 1199 | 1607 |
| connection.updated/quic/h3 | 13510 | 103 | 977 | 1320 | 1939 |
| connection.updated/raw | 5719 | 49 | 794 | 1190 | 1616 |
| connection.updated/tls | 4870 | 107 | 973 | 1294 | 1609 |
| connection.updated/tls/h2 | 12081 | 96 | 912 | 1300 | 2118 |
| connection.updated/tls/http1.1 | 7655 | 89 | 889 | 1329 | 2134 |
| http.request | 28350 | 81 | 904 | 1235 | 1616 |
| packet.stray | 129 | 12 | 585 | 1621 | 1621 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 2757 | 200 | 1047 | 1357 | 1792 |
| tcp | 11033 | 132 | 969 | 1319 | 1699 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 2364 | 2364 | 0 | http1.1=2364 |  |
| h1tls | 2364 | 2364 | 0 | tls/http1.1=2364 |  |
| h2 | 3151 | 3151 | 0 | tls/h2=3151 |  |
| h3 | 3149 | 3149 | 0 | quic/h3=3148 |  |
| raw-banner | 1890 | 1890 | 0 | raw=1890 |  |
| raw-echo | 1574 | 1574 | 0 | raw=1574 |  |
| raw-sink | 1259 | 1259 | 0 | raw=1259 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 410641
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 10460
- `store_stray_total`: 135

Relógio: servidor − local 3.823367ms no início, 3.075681ms no fim (ida e volta do ssh 16.727458ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 2.844243ms a 3.828269ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
