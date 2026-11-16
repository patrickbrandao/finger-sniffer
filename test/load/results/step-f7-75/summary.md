Commit `v0.3.0-10-g8a6ba1b`, início 2026-11-16T07:32:31Z, 75 novas/s, até 300 simultâneas (máx. visto 300), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 15427 abertas, 324 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 77 / p95 245 / p99 369 / máx 639 ms (n=109415) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 79 / p95 255 / p99 372 / máx 639 ms (n=102887) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 77 / p95 245 / p99 369 / máx 639 ms (n=109415) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 79 / p95 255 / p99 372 / máx 639 ms (n=102887) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 19.9 / p99 29.6 / máx 152.1 ms (n=900) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.5 / p95 21.3 / p99 33.9 / máx 36.6 ms (n=900) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 137 / p95 221 / p99 238 / máx 3971 ms (n=10693) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 183 / p95 226 / p99 239 / máx 28942 ms (n=2755) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 15407 (feed ws 15407, sse 15407, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 20 de 15427 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 324 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-10-g8a6ba1b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 34 (37)/768, raw 16 (18)/256, dns 3 (4)/256, store 105 (1178)/6144, nats 257 (260)/1024, slice 423 (1520)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 6.3 / 7.3 / 8.4 % do host (steal médio 0.0); 100 / 117 / 134 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 628 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 900 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.9 | 5.5 | 8.9 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 31.2 | 35.5 | 38.7 | 37 | 34 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.5 | 8.6 | 12.4 | 18 | 16 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 3 | 0 | 256 | 0 | 0 / 0 |
| store | 38.1 | 44.2 | 49.6 | 1178 | 105 | 1068 | 6144 | 0 | 0 / 0 |
| nats | 11.7 | 14.3 | 17.3 | 260 | 257 | 0 | 1024 | 0 | 0 / 0 |
| slice | 91.4 | 102.5 | 110.7 | 1520 | 423 | 1069 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.4 | 1.9 |
| cliente /ws (ts → chegada) | 77.1 | 244.8 | 369.1 |
| ingest_lag (ts → commit) | 70.7 | 150.1 | 158.0 |
| live_delay (ts → envio ao cliente) | 68.0 | 261.3 | 506.7 |
| record_ready{close} (fim → gravado) | 101.9 | 178.9 | 288.8 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 174.5 | 302.1 | 313.4 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 102887 | 79 | 255 | 372 | 639 |
| connection.closed | 13206 | 129 | 202 | 222 | 243 |
| connection.opened | 13328 | 83 | 139 | 155 | 177 |
| connection.updated | 54621 | 71 | 326 | 389 | 639 |
| connection.updated/http1.0 | 2 | 62 | 75 | 75 | 75 |
| connection.updated/http1.1 | 7718 | 60 | 167 | 238 | 480 |
| connection.updated/quic | 1 | 58 | 58 | 58 | 58 |
| connection.updated/quic/h3 | 13483 | 80 | 371 | 406 | 441 |
| connection.updated/raw | 6526 | 45 | 146 | 203 | 255 |
| connection.updated/raw/unknown | 2 | 15 | 80 | 80 | 80 |
| connection.updated/tcp | 2 | 12 | 13 | 13 | 13 |
| connection.updated/tls | 6350 | 79 | 130 | 142 | 395 |
| connection.updated/tls/h2 | 12562 | 81 | 325 | 383 | 638 |
| connection.updated/tls/http1.1 | 7975 | 73 | 338 | 394 | 639 |
| dns.query | 1 | 96 | 96 | 96 | 96 |
| http.request | 27977 | 69 | 128 | 141 | 161 |
| packet.stray | 282 | 10 | 102 | 137 | 156 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 2755 | 174 | 217 | 230 | 245 |
| tcp | 10693 | 120 | 172 | 214 | 250 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 2292 | 2292 | 0 | http1.1=2292 |  |
| h1tls | 2350 | 2345 | 0 | tls=1 tls/http1.1=2349 | 1× Get "https://ld0x7zrpodvadth8.finger-west-01.badblock.net.br:8443/p/ld0x7zrpodvadth8/": context deadline exceeded (Clien; 1× Get "https://ld56uxne04k8zw5o.finger-west-01.badblock.net.br:8443/p/ld56uxne04k8zw5o/": context deadline exceeded (Clien; 1× Get "https://ldd2ns46fd0cuvf4.finger-west-01.badblock.net.br:8443/p/ldd2ns46fd0cuvf4/": context deadline exceeded (Clien; 1× Get "https://ldpcqe0ibc9jh4gx.finger-west-01.badblock.net.br:8443/p/ldpcqe0ibc9jh4gx/": context deadline exceeded (Clien; 1× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h2 | 3136 | 3127 | 0 | tls/h2=3134 | 1× Get "https://lddg0jb9eq18l9jm.finger-west-01.badblock.net.br:8443/p/lddg0jb9eq18l9jm/": context deadline exceeded (Clien; 1× Get "https://ldfe82j5bjn8klep.finger-west-01.badblock.net.br:8443/p/ldfe82j5bjn8klep/": context deadline exceeded (Clien; 1× Get "https://ldg0etb8q8qn6bkc.finger-west-01.badblock.net.br:8443/p/ldg0etb8q8qn6bkc/": context deadline exceeded (Clien; 1× Get "https://ldkxcyzcwuy246x3.finger-west-01.badblock.net.br:8443/p/ldkxcyzcwuy246x3/": context deadline exceeded (Clien; 1× Get "https://ldwhmeyp9ek1r5zj.finger-west-01.badblock.net.br:8443/p/ldwhmeyp9ek1r5zj/": context deadline exceeded (Clien; 1× Get "https://ldz1s29f5ut09igq.finger-west-01.badblock.net.br:8443/p/ldz1s29f5ut09igq/": context deadline exceeded (Clien; 3× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h3 | 3146 | 3146 | 0 | quic/h3=3146 |  |
| raw-banner | 1794 | 1793 | 0 | raw=1794 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:49873->170.247.40.86:25: read tcp4 192.168.1.4:49873->170.247.40.86: |
| raw-echo | 1547 | 1543 | 0 | raw=1547 | 1× eco: read tcp4 192.168.1.4:49444->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:50792->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:50977->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:51234->170.247.40.86:7: i/o timeout |
| raw-sink | 1162 | 1161 | 0 | raw=1161 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:50292->170.247.40.86:143: read tcp4 192.168.1.4:50292->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 440035
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 12581
- `store_stray_total`: 333

Relógio: servidor − local 2.86262ms no início, 2.918837ms no fim (ida e volta do ssh 16.50875ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 2.197686ms a 3.089694ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
