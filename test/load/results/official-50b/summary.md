Commit `6facb2c`, início 2026-11-09T12:10:59Z, 50 novas/s, até 200 simultâneas (máx. visto 200), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 29997 abertas, 3 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 116 / p95 810 / p99 3952 / máx 150167 ms (n=203406) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 113 / p95 469 / p99 818 / máx 150167 ms (n=195128) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 118 / p95 810 / p99 3955 / máx 150167 ms (n=203406) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 115 / p95 474 / p99 817 / máx 150167 ms (n=195128) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 25.4 / p95 48.5 / p99 63.8 / máx 223.5 ms (n=2697) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 26.0 / p95 50.5 / p99 68.4 / máx 521.8 ms (n=2698) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 156 / p95 489 / p99 814 / máx 1360 ms (n=21746) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 212 / p95 566 / p99 848 / máx 1285 ms (n=5438) | **falhou** |
| RNF-01 | probes sem registro | 0 | 0 de 29994 (feed ws 29994, sse 29994, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 3843 | **falhou** |
| RNF-01 | conexões com erro no cliente | 0 | 3 de 29997 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 3 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | 6facb2c | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 8 (11)/96, web 28 (43)/96, raw 13 (21)/96, dns 4 (7)/96, store 74 (384)/384, nats 90 (161)/192 | passou |
| RNF-01 | CPU do host (média / p95 / máx, % de 1 vCPU) | informativo | 50 / 83 / 100 (steal médio 0.0) | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 649 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2697 | passou |

CPU e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | MemoryMax MiB |
| --- | --- | --- | --- | --- | --- | --- |
| capture | 1.7 | 2.0 | 2.4 | 11 | 8 | 96 |
| web | 13.7 | 14.6 | 16.8 | 43 | 28 | 96 |
| raw | 2.1 | 2.3 | 3.2 | 21 | 13 | 96 |
| dns | 0.0 | 0.1 | 0.4 | 7 | 4 | 96 |
| store | 27.6 | 57.5 | 64.6 | 384 | 74 | 384 |
| nats | 4.4 | 5.1 | 5.7 | 161 | 90 | 192 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.6 | 3.8 |
| api GET /api/v1/probes/{id} (servidor) | 0.6 | 1.8 | 3.8 |
| cliente /ws (ts → chegada) | 115.9 | 810.0 | 3951.8 |
| ingest_lag (ts → commit) | 93.9 | 478.6 | 1204.1 |
| live_delay (ts → envio ao cliente) | 110.4 | 1028.2 | 4389.8 |
| record_ready{close} (fim → gravado) | 107.8 | 426.1 | 989.5 |
| record_ready{idle} (fim → gravado) | 133.1 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 199.8 | 536.7 | 1100.8 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 195128 | 113 | 469 | 818 | 150167 |
| connection.closed | 27063 | 131 | 483 | 799 | 150167 |
| connection.opened | 27213 | 116 | 456 | 795 | 1326 |
| connection.updated | 91905 | 123 | 3913 | 3979 | 120543 |
| connection.updated/h2 | 8 | 114 | 422 | 422 | 422 |
| connection.updated/http1.1 | 12247 | 101 | 425 | 766 | 1321 |
| connection.updated/quic/h3 | 27035 | 116 | 501 | 871 | 1559 |
| connection.updated/raw | 8275 | 3920 | 4300 | 4550 | 120543 |
| connection.updated/raw/unknown | 3 | 77 | 115 | 115 | 115 |
| connection.updated/tcp | 2 | 77 | 129 | 129 | 129 |
| connection.updated/tls | 9522 | 104 | 513 | 810 | 1326 |
| connection.updated/tls/h2 | 22208 | 128 | 481 | 853 | 1579 |
| connection.updated/tls/http1.1 | 12605 | 132 | 510 | 901 | 1783 |
| dns.query | 1 | 136 | 136 | 136 | 136 |
| http.request | 56684 | 101 | 439 | 785 | 1327 |
| packet.stray | 540 | 121 | 649 | 842 | 928 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 5438 | 199 | 553 | 837 | 1275 |
| tcp | 21746 | 118 | 458 | 775 | 1302 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 4500 | 4500 | 582 | http1.1=4500 |  |
| h1tls | 4498 | 4497 | 544 | tls/http1.1=4497 | 1× Get "https://ldc0ptzhrghrekls.dns-monitor.tmsoft.com.br:8443/p/ldc0ptzhrghrekls/": context deadline exceeded (Client.Tim |
| h2 | 5999 | 5997 | 1255 | tls=2 tls/h2=5995 | 1× Get "https://ld8uv4vywel7l55h.dns-monitor.tmsoft.com.br/p/ld8uv4vywel7l55h/": context deadline exceeded (Client.Timeout ; 1× Get "https://ldrq5aexit737k3k.dns-monitor.tmsoft.com.br/p/ldrq5aexit737k3k/": context deadline exceeded (Client.Timeout  |
| h3 | 6000 | 6000 | 926 | quic/h3=6000 |  |
| raw-banner | 3600 | 3600 | 174 | raw=3600 |  |
| raw-echo | 3000 | 3000 | 200 | raw=3000 |  |
| raw-sink | 2400 | 2400 | 162 | raw=2400 |  |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 804399
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 3280
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 2617
- `store_stray_total`: 557

Relógio: vps602 − local 245.330254ms no início, 248.500946ms no fim (ida e volta do ssh 17.660541ms).

**Há metas que falharam.**
