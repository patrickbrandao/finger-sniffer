Commit `v0.1.0-12-g90c86d8`, início 2026-11-09T22:46:28Z, 50 novas/s, até 200 simultâneas (máx. visto 196), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 111 / p95 326 / p99 391 / máx 486 ms (n=202138) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 111 / p95 329 / p99 392 / máx 486 ms (n=194028) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 113 / p95 326 / p99 390 / máx 486 ms (n=202138) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 113 / p95 329 / p99 391 / máx 486 ms (n=194028) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 16.7 / p95 33.0 / p99 43.3 / máx 120.0 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 16.9 / p95 33.5 / p99 44.1 / máx 138.7 ms (n=2699) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 132 / p95 195 / p99 216 / máx 315 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 198 / p95 253 / p99 271 / máx 343 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 29999 (feed ws 29999, sse 29999, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 2 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 1 de 30000 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-12-g90c86d8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (41)/96, raw 12 (21)/96, dns 7 (13)/96, store 73 (384)/384, nats 88 (97)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 53 / 59 / 67 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 782 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.6 | 16 | 10 | 96 |
| web | 15.9 | 17.3 | 18.9 | 41 | 30 | 96 |
| raw | 2.1 | 2.4 | 2.7 | 21 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.1 | 13 | 7 | 96 |
| store | 27.0 | 31.9 | 40.3 | 384 | 73 | 384 |
| nats | 5.0 | 5.7 | 6.3 | 97 | 88 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 1.8 | 3.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.7 | 2.6 | 6.2 |
| cliente /ws (ts → chegada) | 110.6 | 325.8 | 390.6 |
| ingest_lag (ts → commit) | 93.4 | 155.8 | 300.9 |
| live_delay (ts → envio ao cliente) | 106.4 | 329.5 | 570.7 |
| record_ready{close} (fim → gravado) | 109.2 | 235.1 | 300.0 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 195.7 | 304.2 | 313.8 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 194028 | 111 | 329 | 392 | 486 |
| connection.closed | 27056 | 130 | 222 | 246 | 335 |
| connection.opened | 27233 | 112 | 171 | 187 | 252 |
| connection.updated | 90525 | 112 | 370 | 407 | 486 |
| connection.updated/http1.1 | 12151 | 99 | 160 | 175 | 255 |
| connection.updated/quic | 1 | 54 | 54 | 54 | 54 |
| connection.updated/quic/h3 | 26998 | 114 | 390 | 421 | 486 |
| connection.updated/raw | 8101 | 103 | 157 | 169 | 255 |
| connection.updated/tcp | 7 | 20 | 37 | 37 | 37 |
| connection.updated/tls | 9480 | 98 | 150 | 164 | 354 |
| connection.updated/tls/h2 | 21616 | 119 | 369 | 399 | 462 |
| connection.updated/tls/http1.1 | 12162 | 136 | 382 | 401 | 471 |
| connection.updated/tls/raw | 9 | 31 | 203 | 203 | 203 |
| dns.query | 1 | 154 | 154 | 154 | 154 |
| http.request | 56700 | 100 | 157 | 172 | 256 |
| packet.stray | 623 | 20 | 168 | 180 | 202 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 190 | 246 | 264 | 335 |
| tcp | 21752 | 116 | 176 | 197 | 295 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 1 | tls/h2=6000 |  |
| h3 | 6000 | 5999 | 0 | quic=1 quic/h3=5999 | 1× Get "https://ldwk6hcx16qrd5pv.dns-monitor.tmsoft.com.br/p/ldwk6hcx16qrd5pv/": timeout: no recent network activity |
| raw-banner | 3600 | 3600 | 1 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 813870
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 12
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 80
- `store_stray_total`: 629

Relógio: vps602 − local -4.300644ms no início, -2.30943ms no fim (ida e volta do ssh 11.659208ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -5.765422ms a -1.929118ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
