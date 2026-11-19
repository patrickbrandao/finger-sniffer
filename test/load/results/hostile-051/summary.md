Commit `v0.5.0-7-g20e513b`, início 2026-11-18T23:16:40Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 6m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 35758 abertas, 242 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 7423 / p95 36962 / p99 44541 / máx 45452 ms (n=31441) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 7422 / p95 36961 / p99 44566 / máx 45452 ms (n=29573) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 493 avisos, 238883 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 7751 / p95 32795 / p99 40343 / máx 43316 ms (n=32081) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 7746 / p95 32797 / p99 40293 / máx 43316 ms (n=30119) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 506 avisos, 239816 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 136.1 / p95 1229.8 / p99 2663.7 / máx 15000.3 ms (n=450) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 136.8 / p95 1261.1 / p99 2537.1 / máx 4977.2 ms (n=450) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 7672 / p95 35377 / p99 43407 / máx 45312 ms (n=5037) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 7915 / p95 32859 / p99 44481 / máx 45283 ms (n=1188) | **falhou** |
| RNF-01 | probes sem registro | 0 | 19625 de 35713 (feed ws 4555, sse 4512, só API 7975) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 45 de 35758 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 242 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 47 | **falhou** |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.0-7-g20e513b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 41 (44)/768, raw 18 (20)/256, dns 4 (5)/256, store 158 (1620)/6144, nats 316 (319)/1024, bot 739 (795)/1024, slice 1279 (2877)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 310 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 13.4 / 17.5 / 20.3 % do host (steal médio 0.0); 215 / 280 / 325 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 735 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 450 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.0 | 4.3 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 39.4 | 43.2 | 47.4 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.1 | 7.8 | 8.9 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 5 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 45.4 | 53.1 | 57.4 | 1620 | 158 | 1457 | 6144 | 0 | 0 / 0 |
| nats | 15.5 | 18.2 | 19.9 | 319 | 316 | 0 | 1024 | 0 | 0 / 0 |
| bot | 67.2 | 112.0 | 149.8 | 795 | 739 | 0 | 1024 | 310 | 0 / 0 |
| slice | 177.2 | 222.4 | 266.5 | 2877 | 1279 | 1498 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.2 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.0 |
| cliente /ws (ts → chegada) | 7423.4 | 36961.9 | 44541.2 |
| ingest_lag (ts → commit) | 60.7 | 143.6 | 157.3 |
| live_delay (ts → envio ao cliente) | 74.7 | 10000.0 | 10000.0 |
| record_ready{close} (fim → gravado) | 77.2 | 184.4 | 289.9 |
| record_ready{idle} (fim → gravado) |  |  |  |
| record_ready{quic_close} (fim → gravado) | 123.5 | 240.3 | 301.0 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 29573 | 7422 | 36961 | 44566 | 45452 |
| connection.closed | 3155 | 7463 | 37588 | 44706 | 45353 |
| connection.opened | 4292 | 7361 | 36992 | 44482 | 45130 |
| connection.updated | 15234 | 7466 | 36962 | 44467 | 45452 |
| connection.updated/http1.1 | 2081 | 7523 | 37282 | 44351 | 45225 |
| connection.updated/quic | 5 | 8021 | 13675 | 13675 | 13675 |
| connection.updated/quic/h3 | 4026 | 7378 | 37072 | 44674 | 45452 |
| connection.updated/raw | 1868 | 7444 | 37007 | 44363 | 45176 |
| connection.updated/tls | 1847 | 7415 | 37755 | 44377 | 45048 |
| connection.updated/tls/h2 | 3326 | 7447 | 33617 | 44466 | 45190 |
| connection.updated/tls/http1.1 | 2081 | 7659 | 37328 | 44530 | 45314 |
| http.request | 8711 | 7366 | 36789 | 44504 | 45230 |
| packet.stray | 49 | 7117 | 26938 | 44819 | 44819 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 1188 | 7902 | 32842 | 44469 | 45270 |
| tcp | 5037 | 7656 | 35340 | 43375 | 45353 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 5387 | 5386 | 0 | http1.1=1010 | 1× Get "http://ldi3op95g7yip6yi.finger-west-01.badblock.net.br:8080/p/ldi3op95g7yip6yi/": context deadline exceeded (Client |
| h1tls | 5395 | 5393 | 0 | tls/http1.1=1268 | 1× Get "https://ld6fwaa5ct7yjcd9.finger-west-01.badblock.net.br:8443/p/ld6fwaa5ct7yjcd9/": context deadline exceeded (Clien; 1× Get "https://ldmxu5xzpy34b16u.finger-west-01.badblock.net.br:8443/p/ldmxu5xzpy34b16u/": context deadline exceeded (Clien |
| h2 | 7161 | 7160 | 0 | tls/h2=1828 | 1× Get "https://ldvdb47cmktgrid7.finger-west-01.badblock.net.br:8443/p/ldvdb47cmktgrid7/": context deadline exceeded (Clien |
| h3 | 7031 | 6994 | 0 | quic=3 quic/h3=1596 | 1× Get "https://ld0lbdzb8sx0jd33.finger-west-01.badblock.net.br:8443/p/ld0lbdzb8sx0jd33/": timeout: handshake did not compl; 1× Get "https://ld2lb0lji064l17e.finger-west-01.badblock.net.br:8443/p/ld2lb0lji064l17e/": timeout: no recent network activ; 1× Get "https://ld3q4cc79go5uj4k.finger-west-01.badblock.net.br:8443/p/ld3q4cc79go5uj4k/": timeout: no recent network activ; 1× Get "https://ld42osawz81hkp9n.finger-west-01.badblock.net.br:8443/p/ld42osawz81hkp9n/": timeout: no recent network activ; 1× Get "https://ld4r2at87jzgy1r1.finger-west-01.badblock.net.br:8443/p/ld4r2at87jzgy1r1/": timeout: no recent network activ; 1× Get "https://ld5qb0w8z88glwre.finger-west-01.badblock.net.br:8443/p/ld5qb0w8z88glwre/": timeout: handshake did not compl; 1× Get "https://ld6f5t7l17pq68ic.finger-west-01.badblock.net.br:8443/p/ld6f5t7l17pq68ic/": timeout: no recent network activ; 1× Get "https://ld7c0wmnraw3s7dt.finger-west-01.badblock.net.br:8443/p/ld7c0wmnraw3s7dt/": timeout: no recent network activ; 1× Get "https://ld7lncvqnxh5dqhi.finger-west-01.badblock.net.br:8443/p/ld7lncvqnxh5dqhi/": context deadline exceeded (Clien; 1× Get "https://lda3rlz25hc3v4ev.finger-west-01.badblock.net.br:8443/p/lda3rlz25hc3v4ev/": timeout: no recent network activ; 1× Get "https://lda6xthr21bs1uug.finger-west-01.badblock.net.br:8443/p/lda6xthr21bs1uug/": timeout: no recent network activ; 1× Get "https://ldb6yut1d9xie3d6.finger-west-01.badblock.net.br:8443/p/ldb6yut1d9xie3d6/": timeout: no recent network activ; 1× Get "https://ldcmqvtby6mz3fej.finger-west-01.badblock.net.br:8443/p/ldcmqvtby6mz3fej/": timeout: no recent network activ; 1× Get "https://ldfddecsocoesixy.finger-west-01.badblock.net.br:8443/p/ldfddecsocoesixy/": timeout: no recent network activ; 1× Get "https://ldfng1zr1zro6ibm.finger-west-01.badblock.net.br:8443/p/ldfng1zr1zro6ibm/": timeout: handshake did not compl; 1× Get "https://ldgatwfat7dgpi6s.finger-west-01.badblock.net.br:8443/p/ldgatwfat7dgpi6s/": timeout: no recent network activ; 1× Get "https://ldh2q5al66fmc2yi.finger-west-01.badblock.net.br:8443/p/ldh2q5al66fmc2yi/": context deadline exceeded (Clien; 1× Get "https://ldh5er3kuttlwiyn.finger-west-01.badblock.net.br:8443/p/ldh5er3kuttlwiyn/": context deadline exceeded (Clien; 1× Get "https://ldhvvi38x9ioimdj.finger-west-01.badblock.net.br:8443/p/ldhvvi38x9ioimdj/": timeout: no recent network activ; 1× Get "https://ldji2kbv0sa3ctmh.finger-west-01.badblock.net.br:8443/p/ldji2kbv0sa3ctmh/": timeout: no recent network activ; 1× Get "https://ldjr30fsdsto98dm.finger-west-01.badblock.net.br:8443/p/ldjr30fsdsto98dm/": timeout: no recent network activ; 1× Get "https://ldjw4vvjsckjyt5t.finger-west-01.badblock.net.br:8443/p/ldjw4vvjsckjyt5t/": timeout: no recent network activ; 1× Get "https://ldlblxa7y9z55aqd.finger-west-01.badblock.net.br:8443/p/ldlblxa7y9z55aqd/": timeout: handshake did not compl; 1× Get "https://ldlmth9k54xuhfbw.finger-west-01.badblock.net.br:8443/p/ldlmth9k54xuhfbw/": timeout: no recent network activ; 1× Get "https://ldmxdg4u6jc7bky6.finger-west-01.badblock.net.br:8443/p/ldmxdg4u6jc7bky6/": timeout: no recent network activ; 1× Get "https://ldn9mnwca1u3icxy.finger-west-01.badblock.net.br:8443/p/ldn9mnwca1u3icxy/": timeout: handshake did not compl; 1× Get "https://ldom5013c33g4be0.finger-west-01.badblock.net.br:8443/p/ldom5013c33g4be0/": timeout: no recent network activ; 1× Get "https://ldosbjw69fzde04s.finger-west-01.badblock.net.br:8443/p/ldosbjw69fzde04s/": timeout: no recent network activ; 1× Get "https://ldotv2t70a7nqdbj.finger-west-01.badblock.net.br:8443/p/ldotv2t70a7nqdbj/": timeout: no recent network activ; 1× Get "https://ldritlb6u8zzhdq3.finger-west-01.badblock.net.br:8443/p/ldritlb6u8zzhdq3/": timeout: no recent network activ; 1× Get "https://lds4gocjbvuup29c.finger-west-01.badblock.net.br:8443/p/lds4gocjbvuup29c/": timeout: no recent network activ; 1× Get "https://ldunqepzkpqszj5t.finger-west-01.badblock.net.br:8443/p/ldunqepzkpqszj5t/": timeout: no recent network activ; 1× Get "https://lduq57izpgtthbhm.finger-west-01.badblock.net.br:8443/p/lduq57izpgtthbhm/": timeout: no recent network activ; 1× Get "https://ldx45sryyt60n5bi.finger-west-01.badblock.net.br:8443/p/ldx45sryyt60n5bi/": timeout: handshake did not compl; 1× Get "https://ldxy9pjpx3h7v9jx.finger-west-01.badblock.net.br:8443/p/ldxy9pjpx3h7v9jx/": timeout: no recent network activ; 1× Get "https://ldylolde9iq8m967.finger-west-01.badblock.net.br:8443/p/ldylolde9iq8m967/": timeout: no recent network activ; 1× Get "https://ldzyhgq57294p4ko.finger-west-01.badblock.net.br:8443/p/ldzyhgq57294p4ko/": timeout: no recent network activ |
| raw-banner | 4312 | 4311 | 0 | raw=968 | 1× dial tcp4 170.247.40.86:25: i/o timeout |
| raw-echo | 3595 | 3593 | 0 | raw=721 | 2× dial tcp4 170.247.40.86:7: i/o timeout |
| raw-sink | 2877 | 2876 | 0 | raw=722 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:55566->170.247.40.86:143: read tcp4 192.168.1.4:55566->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1115979
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 618825
- `store_late_packets_total`: 20614
- `store_stray_total`: 582

Relógio: servidor − local 8.6493ms no início, 11.948736ms no fim (ida e volta do ssh 16.69825ms).
Deslocamento acompanhado a cada 15 s (69 de 77 medições aceitas): 2.265099ms a 12.479123ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
