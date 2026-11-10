Commit `v0.1.0-13-gc1aefd8`, início 2026-11-10T00:16:01Z, 50 novas/s, até 200 simultâneas (máx. visto 197), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 30000 abertas, 0 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 114 / p95 329 / p99 396 / máx 588 ms (n=201877) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 115 / p95 332 / p99 397 / máx 588 ms (n=193730) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 116 / p95 328 / p99 396 / máx 649 ms (n=201877) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 116 / p95 332 / p99 397 / máx 649 ms (n=193730) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 14.0 / p95 33.1 / p99 47.4 / máx 489.2 ms (n=2698) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 14.4 / p95 33.7 / p99 46.8 / máx 86.0 ms (n=2699) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 136 / p95 203 / p99 242 / máx 504 ms (n=21752) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 190 / p95 269 / p99 320 / máx 569 ms (n=5438) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 30000 (feed ws 30000, sse 30000, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 0 de 30000 | passou |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 0 | passou |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.1.0-13-gc1aefd8 | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (16)/96, web 30 (54)/96, raw 12 (21)/96, dns 4 (9)/96, store 76 (384)/384, nats 88 (154)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 56 / 64 / 71 (steal médio 0.1) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 791 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2698 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.9 | 2.2 | 2.5 | 16 | 10 | 96 |
| web | 15.9 | 17.0 | 18.0 | 54 | 30 | 96 |
| raw | 2.1 | 2.4 | 2.6 | 21 | 12 | 96 |
| dns | 0.0 | 0.1 | 0.2 | 9 | 4 | 96 |
| store | 30.3 | 34.7 | 43.2 | 384 | 76 | 384 |
| nats | 5.0 | 5.7 | 6.2 | 154 | 88 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.6 | 1.9 | 7.1 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 2.6 | 7.3 |
| cliente /ws (ts → chegada) | 114.1 | 328.7 | 396.2 |
| ingest_lag (ts → commit) | 96.5 | 161.8 | 308.1 |
| live_delay (ts → envio ao cliente) | 109.5 | 337.7 | 572.3 |
| record_ready{close} (fim → gravado) | 112.2 | 257.0 | 304.7 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 188.6 | 304.2 | 314.5 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 193730 | 115 | 332 | 397 | 588 |
| connection.closed | 27049 | 133 | 227 | 268 | 473 |
| connection.opened | 27170 | 117 | 178 | 210 | 362 |
| connection.updated | 90539 | 116 | 372 | 414 | 588 |
| connection.updated/http1.1 | 12157 | 101 | 162 | 185 | 348 |
| connection.updated/quic/h3 | 27000 | 118 | 394 | 436 | 567 |
| connection.updated/raw | 8144 | 103 | 167 | 202 | 342 |
| connection.updated/tls | 9457 | 103 | 160 | 190 | 321 |
| connection.updated/tls/h2 | 21611 | 124 | 373 | 401 | 537 |
| connection.updated/tls/http1.1 | 12167 | 138 | 390 | 419 | 588 |
| connection.updated/tls/raw | 3 | 21 | 147 | 147 | 147 |
| http.request | 56701 | 103 | 164 | 193 | 348 |
| packet.stray | 418 | 19 | 144 | 219 | 325 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 182 | 262 | 312 | 448 |
| tcp | 21752 | 121 | 186 | 225 | 473 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 0 | http1.1=4500 |  |
| h1tls | 4500 | 4500 | 0 | tls/http1.1=4500 |  |
| h2 | 6000 | 6000 | 0 | tls/h2=6000 |  |
| h3 | 6000 | 6000 | 0 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 0 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 0 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 0 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 816647
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 76
- `store_stray_total`: 423

Relógio: vps602 − local -1.286168ms no início, -1.084069ms no fim (ida e volta do ssh 16.139458ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): -2.712083ms a 930.133µs; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Todas as metas passaram.**
