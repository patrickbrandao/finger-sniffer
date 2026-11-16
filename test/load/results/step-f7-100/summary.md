Commit `v0.3.0-10-g8a6ba1b`, início 2026-11-16T07:36:45Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 3m30s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 20454 abertas, 546 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 66 / p95 233 / p99 349 / máx 883 ms (n=147435) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 67 / p95 244 / p99 350 / máx 883 ms (n=136609) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 66 / p95 233 / p99 349 / máx 883 ms (n=147435) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 67 / p95 245 / p99 350 / máx 883 ms (n=136609) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 19.1 / p99 33.1 / máx 153.1 ms (n=900) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 20.0 / p99 33.4 / máx 153.6 ms (n=900) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 138 / p95 193 / p99 209 / máx 518 ms (n=14476) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 151 / p95 186 / p99 214 / máx 28966 ms (n=3375) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 20434 (feed ws 20434, sse 20434, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 20 de 20454 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 546 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-10-g8a6ba1b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/512, web 40 (44)/768, raw 18 (19)/256, dns 3 (4)/256, store 127 (1755)/6144, nats 308 (311)/1024, slice 505 (2157)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.6 / 8.9 / 9.7 % do host (steal médio 0.0); 121 / 143 / 154 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 649 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 900 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.7 | 4.1 | 12 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 36.0 | 40.0 | 42.5 | 44 | 40 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.9 | 8.1 | 8.6 | 19 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 3 | 0 | 256 | 0 | 0 / 0 |
| store | 50.2 | 58.9 | 64.3 | 1755 | 127 | 1622 | 6144 | 0 | 0 / 0 |
| nats | 13.5 | 16.0 | 17.3 | 311 | 308 | 0 | 1024 | 0 | 0 / 0 |
| slice | 110.1 | 122.0 | 127.4 | 2157 | 505 | 1623 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.5 |
| cliente /ws (ts → chegada) | 65.9 | 233.1 | 348.8 |
| ingest_lag (ts → commit) | 61.8 | 145.0 | 157.6 |
| live_delay (ts → envio ao cliente) | 58.9 | 246.8 | 496.4 |
| record_ready{close} (fim → gravado) | 106.6 | 158.3 | 283.6 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 124.2 | 248.6 | 302.7 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 136609 | 67 | 244 | 350 | 883 |
| connection.closed | 17483 | 132 | 169 | 188 | 243 |
| connection.opened | 17619 | 73 | 113 | 127 | 165 |
| connection.updated | 75446 | 61 | 319 | 364 | 883 |
| connection.updated/http1.1 | 10443 | 50 | 177 | 232 | 479 |
| connection.updated/quic/h3 | 16548 | 70 | 341 | 368 | 418 |
| connection.updated/raw | 10824 | 38 | 162 | 223 | 267 |
| connection.updated/raw/unknown | 2 | 12 | 60 | 60 | 60 |
| connection.updated/tls | 9070 | 61 | 102 | 114 | 628 |
| connection.updated/tls/h2 | 17835 | 68 | 328 | 383 | 883 |
| connection.updated/tls/http1.1 | 10724 | 69 | 334 | 395 | 648 |
| http.request | 36562 | 58 | 99 | 111 | 144 |
| packet.stray | 325 | 11 | 91 | 105 | 114 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 3375 | 142 | 177 | 205 | 249 |
| tcp | 14476 | 129 | 167 | 189 | 250 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 3109 | 3102 | 0 | http1.1=3108 | 1× Get "http://ldglsqwqogdf6xbo.finger-west-01.badblock.net.br:8080/p/ldglsqwqogdf6xbo/": context deadline exceeded (Client; 1× Get "http://ldierr88f8ogy08m.finger-west-01.badblock.net.br:8080/p/ldierr88f8ogy08m/": context deadline exceeded (Client; 1× Get "http://ldjc0wrbi9phvua9.finger-west-01.badblock.net.br:8080/p/ldjc0wrbi9phvua9/": context deadline exceeded (Client; 1× Get "http://ldl08p8qi0o24u97.finger-west-01.badblock.net.br:8080/p/ldl08p8qi0o24u97/": context deadline exceeded (Client; 1× Get "http://ldy9xac1222ocyyd.finger-west-01.badblock.net.br:8080/p/ldy9xac1222ocyyd/": context deadline exceeded (Client; 2× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h1tls | 3139 | 3138 | 0 | tls/http1.1=3138 | 1× Get "https://ldkk8qlfggv89r8t.finger-west-01.badblock.net.br:8443/p/ldkk8qlfggv89r8t/": context deadline exceeded (Clien |
| h2 | 4148 | 4141 | 0 | tls=2 tls/h2=4145 | 1× Get "https://ld1rzr342nyfcnzd.finger-west-01.badblock.net.br:8443/p/ld1rzr342nyfcnzd/": context deadline exceeded (Clien; 1× Get "https://ldetb83nwzi61vkj.finger-west-01.badblock.net.br:8443/p/ldetb83nwzi61vkj/": context deadline exceeded (Clien; 1× Get "https://ldj4m9vll779nwco.finger-west-01.badblock.net.br:8443/p/ldj4m9vll779nwco/": context deadline exceeded (Clien; 1× Get "https://ldmp7zs5t8k626xc.finger-west-01.badblock.net.br:8443/p/ldmp7zs5t8k626xc/": context deadline exceeded (Clien; 1× Get "https://ldrcznu4mdjpuunv.finger-west-01.badblock.net.br:8443/p/ldrcznu4mdjpuunv/": context deadline exceeded (Clien; 1× Get "https://ldrm1jvxb4im8mnb.finger-west-01.badblock.net.br:8443/p/ldrm1jvxb4im8mnb/": context deadline exceeded (Clien; 1× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h3 | 3888 | 3888 | 0 | quic/h3=3888 |  |
| raw-banner | 2468 | 2467 | 0 | raw=2467 | 1× banner: read tcp4 192.168.1.4:58197->170.247.40.86:25: i/o timeout |
| raw-echo | 2048 | 2046 | 0 | raw=2048 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:54820->170.247.40.86:7: read tcp4 192.168.1.4:54820->170.247.40.86:7; 1× eco: read tcp4 192.168.1.4:60797->170.247.40.86:7: i/o timeout |
| raw-sink | 1654 | 1652 | 0 | raw=1653 | 1× banner: read tcp4 192.168.1.4:61462->170.247.40.86:143: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:62444->170.247.40.86:143: read tcp4 192.168.1.4:62444->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 594302
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 21314
- `store_stray_total`: 369

Relógio: servidor − local 2.892848ms no início, 2.951952ms no fim (ida e volta do ssh 17.029334ms).
Deslocamento acompanhado a cada 15 s (17 de 17 medições aceitas): 2.431631ms a 3.059849ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
