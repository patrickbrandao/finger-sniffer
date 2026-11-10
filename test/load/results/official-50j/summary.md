Commit `v0.1.0-13-gc1aefd8`, início 2026-11-10T00:04:06Z, 50 novas/s, até 200 simultâneas (máx. visto 197), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 115 / p95 328 / p99 398 / máx 535 ms (n=202150) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 115 / p95 332 / p99 399 / máx 535 ms (n=193992) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 116 / p95 328 / p99 397 / máx 539 ms (n=202150) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 116 / p95 332 / p99 398 / máx 539 ms (n=193992) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 16.9 / p95 35.5 / p99 46.1 / máx 85.4 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 38.1 / p99 48.8 / máx 76.4 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 139 / p95 204 / p99 244 / máx 426 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 200 / p95 261 / p99 285 / máx 568 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 29999 (feed ws 29999, sse 29999, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 1 de 30000 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-13-gc1aefd8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (54)/96, raw 12 (21)/96, dns 4 (9)/96, store 73 (384)/384, nats 89 (97)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 58 / 65 / 77 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 789 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.5 | 16 | 10 | 96 |
| web | 16.1 | 17.5 | 19.2 | 54 | 30 | 96 |
| raw | 2.1 | 2.5 | 3.1 | 21 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 9 | 4 | 96 |
| store | 30.9 | 36.0 | 49.7 | 384 | 73 | 384 |
| nats | 5.0 | 5.6 | 6.0 | 97 | 89 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 1.9 | 4.3 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 3.0 | 9.4 |
| cliente /ws (ts → chegada) | 114.9 | 328.1 | 397.5 |
| ingest_lag (ts → commit) | 97.6 | 181.0 | 309.1 |
| live_delay (ts → envio ao cliente) | 110.2 | 336.6 | 572.1 |
| record_ready{close} (fim → gravado) | 114.1 | 259.4 | 305.1 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 194.7 | 304.3 | 314.1 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193992 | 115 | 332 | 399 | 535 |
| connection.closed | 27060 | 134 | 231 | 258 | 407 |
| connection.opened | 27206 | 117 | 179 | 208 | 314 |
| connection.updated | 90552 | 116 | 373 | 414 | 535 |
| connection.updated/http1.1 | 12159 | 99 | 171 | 206 | 300 |
| connection.updated/quic/h3 | 27001 | 118 | 397 | 428 | 531 |
| connection.updated/raw | 8157 | 108 | 169 | 196 | 285 |
| connection.updated/tls | 9451 | 103 | 155 | 189 | 288 |
| connection.updated/tls/h2 | 21620 | 125 | 373 | 406 | 535 |
| connection.updated/tls/http1.1 | 12163 | 142 | 387 | 413 | 517 |
| connection.updated/tls/raw | 1 | 17 | 17 | 17 | 17 |
| dns.query | 9 | 105 | 155 | 155 | 155 |
| http.request | 56700 | 103 | 167 | 197 | 307 |
| packet.stray | 623 | 63 | 168 | 193 | 256 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 193 | 253 | 276 | 367 |
| tcp | 21752 | 123 | 186 | 229 | 407 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 5999 | 0 | quic=1 quic/h3=5999 | 1× Get "https://ldc3zsou4yqd9vp7.dns-monitor.tmsoft.com.br/p/ldc3zsou4yqd9vp7/": timeout: no recent network activity |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 816256
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 104
- `store_stray_total`: 640

Relógio: vps602 − local 1.241346ms no início, 731.464µs no fim (ida e volta do ssh 13.021792ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -1.518682ms a 1.487909ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
