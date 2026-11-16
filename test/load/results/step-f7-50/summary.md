Commit `v0.3.0-10-g8a6ba1b`, início 2026-11-16T07:28:07Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 10254 abertas, 246 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 88 / p95 237 / p99 379 / máx 610 ms (n=71340) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 89 / p95 248 / p99 380 / máx 610 ms (n=66746) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 88 / p95 237 / p99 379 / máx 609 ms (n=71340) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 89 / p95 248 / p99 380 / máx 609 ms (n=66746) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 19.8 / p99 33.5 / máx 36.5 ms (n=900) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 20.5 / p99 34.0 / máx 42.3 ms (n=900) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 147 / p95 229 / p99 239 / máx 908 ms (n=7136) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 185 / p95 234 / p99 244 / máx 29021 ms (n=1801) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 10245 (feed ws 10245, sse 10245, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 9 de 10254 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 246 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-10-g8a6ba1b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/512, web 28 (31)/768, raw 13 (15)/256, dns 3 (4)/256, store 88 (555)/6144, nats 175 (178)/1024, slice 313 (807)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 4.0 / 5.1 / 6.1 % do host (steal médio 0.0); 63 / 82 / 98 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 611 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 900 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.3 | 4.8 | 7.6 | 12 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 19.9 | 24.5 | 31.9 | 31 | 28 | 0 | 768 | 0 | 0 / 0 |
| raw | 4.4 | 6.2 | 8.4 | 15 | 13 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 3 | 0 | 256 | 0 | 0 / 0 |
| store | 24.9 | 30.4 | 35.7 | 555 | 88 | 467 | 6144 | 0 | 0 / 0 |
| nats | 8.6 | 10.8 | 14.0 | 178 | 175 | 0 | 1024 | 0 | 0 / 0 |
| slice | 61.3 | 74.0 | 82.4 | 807 | 313 | 468 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.7 |
| cliente /ws (ts → chegada) | 88.0 | 236.6 | 379.1 |
| ingest_lag (ts → commit) | 79.4 | 151.7 | 158.2 |
| live_delay (ts → envio ao cliente) | 76.7 | 267.5 | 519.5 |
| record_ready{close} (fim → gravado) | 95.8 | 219.1 | 296.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 174.5 | 302.1 | 313.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 66746 | 89 | 248 | 380 | 610 |
| connection.closed | 8764 | 125 | 213 | 229 | 251 |
| connection.opened | 8831 | 94 | 146 | 155 | 183 |
| connection.updated | 35267 | 85 | 337 | 395 | 610 |
| connection.updated/http1.0 | 1 | 22 | 22 | 22 | 22 |
| connection.updated/http1.1 | 4969 | 74 | 179 | 246 | 379 |
| connection.updated/quic/h3 | 8815 | 92 | 378 | 408 | 439 |
| connection.updated/raw | 4594 | 57 | 170 | 192 | 220 |
| connection.updated/tcp | 2 | 10 | 11 | 11 | 11 |
| connection.updated/tls | 4156 | 82 | 130 | 140 | 256 |
| connection.updated/tls/h2 | 8011 | 94 | 334 | 396 | 610 |
| connection.updated/tls/http1.1 | 4719 | 97 | 346 | 400 | 446 |
| http.request | 18275 | 79 | 131 | 141 | 175 |
| packet.stray | 203 | 12 | 113 | 148 | 148 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 1801 | 176 | 225 | 236 | 246 |
| tcp | 7136 | 106 | 192 | 224 | 251 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 1564 | 1564 | 0 | http1.1=1564 |  |
| h1tls | 1510 | 1508 | 0 | tls/http1.1=1510 | 1× Get "https://lddr0gn310o952nk.finger-west-01.badblock.net.br:8443/p/lddr0gn310o952nk/": context deadline exceeded (Clien; 1× Get "https://ldpqw3bn9qi8hmcr.finger-west-01.badblock.net.br:8443/p/ldpqw3bn9qi8hmcr/": context deadline exceeded (Clien |
| h2 | 2010 | 2006 | 0 | tls=1 tls/h2=2009 | 1× Get "https://ld8xwn25huqt8hd3.finger-west-01.badblock.net.br:8443/p/ld8xwn25huqt8hd3/": context deadline exceeded (Clien; 1× Get "https://ldc6ed4sc9i6zyvb.finger-west-01.badblock.net.br:8443/p/ldc6ed4sc9i6zyvb/": context deadline exceeded (Clien; 1× Get "https://ldu3jwkplxmid2a9.finger-west-01.badblock.net.br:8443/p/ldu3jwkplxmid2a9/": context deadline exceeded (Clien; 1× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h3 | 2063 | 2063 | 0 | quic/h3=2063 |  |
| raw-banner | 1251 | 1250 | 0 | raw=1251 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:51856->170.247.40.86:21: read tcp4 192.168.1.4:51856->170.247.40.86: |
| raw-echo | 1019 | 1018 | 0 | raw=1019 | 1× eco: read tcp4 192.168.1.4:50826->170.247.40.86:7: i/o timeout |
| raw-sink | 837 | 836 | 0 | raw=836 | 1× banner: read tcp4 192.168.1.4:51533->170.247.40.86:143: i/o timeout |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 294526
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 7477
- `store_stray_total`: 230

Relógio: servidor − local 2.754865ms no início, 2.85801ms no fim (ida e volta do ssh 16.795791ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 2.253083ms a 3.041036ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
