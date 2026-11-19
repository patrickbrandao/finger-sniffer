Commit `v0.5.0-7-g20e513b`, início 2026-11-18T22:49:22Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 59643 abertas, 357 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 8224 / p95 26231 / p99 44564 / máx 52600 ms (n=60739) | **falhou** |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 8218 / p95 26124 / p99 44558 / máx 52600 ms (n=57258) | **falhou** |
| RNF-02 | stream.dropped /ws | 0 | 622 avisos, 366247 eventos | **falhou** |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 7924 / p95 23176 / p99 34410 / máx 42167 ms (n=62408) | **falhou** |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 7916 / p95 23165 / p99 34410 / máx 42167 ms (n=58916) | **falhou** |
| RNF-02 | stream.dropped /sse | 0 | 891 avisos, 396413 eventos | **falhou** |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 117.8 / p95 1106.1 / p99 2607.8 / máx 9197.6 ms (n=887) | **falhou** |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 123.4 / p95 1202.7 / p99 2610.1 / máx 8118.7 ms (n=888) | **falhou** |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 8154 / p95 24333 / p99 40067 / máx 52631 ms (n=10162) | **falhou** |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 8235 / p95 24913 / p99 39093 / máx 52614 ms (n=2288) | **falhou** |
| RNF-01 | probes sem registro | 0 | 45055 de 59576 (feed ws 8068, sse 7923, só API 0) | **falhou** |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 67 de 59643 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 357 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.5.0-7-g20e513b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (11)/512, web 42 (45)/768, raw 19 (20)/256, dns 4 (4)/256, store 159 (2578)/6144, nats 314 (317)/1024, bot 551 (557)/1024, slice 1098 (3597)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-02 (018) | bot: nr_throttled / memory.events max / oom_kill (Δ na medição) | — / 0 / 0 | 151 / 0 / 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 12.0 / 14.2 / 16.9 % do host (steal médio 0.0); 192 / 227 / 270 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 736 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 887 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.6 | 4.0 | 4.3 | 11 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 39.9 | 44.2 | 49.2 | 45 | 42 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.3 | 7.6 | 8.9 | 20 | 19 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.1 | 4 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 48.1 | 56.6 | 61.4 | 2578 | 159 | 2411 | 6144 | 0 | 0 / 0 |
| nats | 15.6 | 18.4 | 20.2 | 317 | 314 | 0 | 1024 | 0 | 0 / 0 |
| bot | 45.1 | 70.8 | 78.2 | 557 | 551 | 0 | 1024 | 151 | 0 / 0 |
| slice | 158.6 | 188.3 | 212.5 | 3597 | 1098 | 2452 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.6 |
| cliente /ws (ts → chegada) | 8223.6 | 26231.0 | 44563.9 |
| ingest_lag (ts → commit) | 60.7 | 143.3 | 157.3 |
| live_delay (ts → envio ao cliente) | 74.7 | 10000.0 | 10000.0 |
| record_ready{close} (fim → gravado) | 77.0 | 158.1 | 283.4 |
| record_ready{idle} (fim → gravado) | 99.2 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 123.6 | 241.7 | 301.3 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 57258 | 8218 | 26124 | 44558 | 52600 |
| connection.closed | 6753 | 8421 | 26338 | 42517 | 52600 |
| connection.opened | 8100 | 8144 | 25893 | 44578 | 52581 |
| connection.updated | 29136 | 8264 | 26741 | 44615 | 52561 |
| connection.updated/http1.1 | 3912 | 8240 | 27200 | 44519 | 52444 |
| connection.updated/quic | 2 | 8491 | 17085 | 17085 | 17085 |
| connection.updated/quic/h3 | 7651 | 8199 | 24614 | 44383 | 52561 |
| connection.updated/raw | 3481 | 8347 | 27371 | 44778 | 52459 |
| connection.updated/tls | 3354 | 8295 | 28636 | 44615 | 52374 |
| connection.updated/tls/h2 | 6555 | 8216 | 25773 | 44615 | 52515 |
| connection.updated/tls/http1.1 | 4181 | 8339 | 27222 | 44686 | 52558 |
| http.request | 16612 | 8138 | 25393 | 44489 | 52558 |
| packet.stray | 138 | 8755 | 35470 | 51692 | 51692 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 2288 | 8220 | 24900 | 39080 | 52600 |
| tcp | 10162 | 8141 | 24324 | 40181 | 52545 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 8990 | 8990 | 0 | http1.1=1991 |  |
| h1tls | 8988 | 8985 | 0 | tls/http1.1=2366 | 1× Get "https://ld4hxf4kpcsljklb.finger-west-01.badblock.net.br:8443/p/ld4hxf4kpcsljklb/": context deadline exceeded (Clien; 1× Get "https://ld98irtnw03zq7nd.finger-west-01.badblock.net.br:8443/p/ld98irtnw03zq7nd/": context deadline exceeded (Clien; 1× Get "https://ldt9mg8c3ychxuqv.finger-west-01.badblock.net.br:8443/p/ldt9mg8c3ychxuqv/": context deadline exceeded (Clien |
| h2 | 11930 | 11927 | 0 | tls/h2=3136 | 1× Get "https://ld3aeu408ypq80u7.finger-west-01.badblock.net.br:8443/p/ld3aeu408ypq80u7/": context deadline exceeded (Clien; 1× Get "https://ldrjm1s9n6jvxyir.finger-west-01.badblock.net.br:8443/p/ldrjm1s9n6jvxyir/": context deadline exceeded (Clien; 1× Get "https://ldwps8aw7eg4vg36.finger-west-01.badblock.net.br:8443/p/ldwps8aw7eg4vg36/": context deadline exceeded (Clien |
| h3 | 11762 | 11704 | 0 | quic=5 quic/h3=2658 | 1× Get "https://ld06j31gtiabktnr.finger-west-01.badblock.net.br:8443/p/ld06j31gtiabktnr/": timeout: no recent network activ; 1× Get "https://ld26y0gl4xyltmeg.finger-west-01.badblock.net.br:8443/p/ld26y0gl4xyltmeg/": timeout: no recent network activ; 1× Get "https://ld2uz9lpsfy7k9s5.finger-west-01.badblock.net.br:8443/p/ld2uz9lpsfy7k9s5/": timeout: no recent network activ; 1× Get "https://ld3i2tp92yh8veb5.finger-west-01.badblock.net.br:8443/p/ld3i2tp92yh8veb5/": timeout: handshake did not compl; 1× Get "https://ld3z4di37m11eqvy.finger-west-01.badblock.net.br:8443/p/ld3z4di37m11eqvy/": timeout: handshake did not compl; 1× Get "https://ld4vqr0dgbf7iapm.finger-west-01.badblock.net.br:8443/p/ld4vqr0dgbf7iapm/": timeout: handshake did not compl; 1× Get "https://ld5yamh4i95nj2e2.finger-west-01.badblock.net.br:8443/p/ld5yamh4i95nj2e2/": context deadline exceeded (Clien; 1× Get "https://ld64hi9fkulpxl3e.finger-west-01.badblock.net.br:8443/p/ld64hi9fkulpxl3e/": context deadline exceeded; 1× Get "https://ld6xgvrksdls2mhu.finger-west-01.badblock.net.br:8443/p/ld6xgvrksdls2mhu/": timeout: handshake did not compl; 1× Get "https://ld8evwutmm6huf7b.finger-west-01.badblock.net.br:8443/p/ld8evwutmm6huf7b/": timeout: handshake did not compl; 1× Get "https://ld8nzcmqhe5zvdyy.finger-west-01.badblock.net.br:8443/p/ld8nzcmqhe5zvdyy/": context deadline exceeded (Clien; 1× Get "https://ld8ovf1clsoslt62.finger-west-01.badblock.net.br:8443/p/ld8ovf1clsoslt62/": timeout: handshake did not compl; 1× Get "https://lda75cijyutzczgz.finger-west-01.badblock.net.br:8443/p/lda75cijyutzczgz/": timeout: no recent network activ; 1× Get "https://ldb0nk8xcgokmsmq.finger-west-01.badblock.net.br:8443/p/ldb0nk8xcgokmsmq/": timeout: no recent network activ; 1× Get "https://ldbghcdgx8tfmovj.finger-west-01.badblock.net.br:8443/p/ldbghcdgx8tfmovj/": timeout: no recent network activ; 1× Get "https://ldbqnjwaw4ebitww.finger-west-01.badblock.net.br:8443/p/ldbqnjwaw4ebitww/": timeout: no recent network activ; 1× Get "https://ldbvilxh58xxd1mf.finger-west-01.badblock.net.br:8443/p/ldbvilxh58xxd1mf/": timeout: handshake did not compl; 1× Get "https://lddbaifkwcci2dd2.finger-west-01.badblock.net.br:8443/p/lddbaifkwcci2dd2/": timeout: no recent network activ; 1× Get "https://lddjfsgbxcrfb7nd.finger-west-01.badblock.net.br:8443/p/lddjfsgbxcrfb7nd/": timeout: no recent network activ; 1× Get "https://ldemb6x85ob54zb7.finger-west-01.badblock.net.br:8443/p/ldemb6x85ob54zb7/": timeout: no recent network activ; 1× Get "https://ldf2qb21mt9vfz2f.finger-west-01.badblock.net.br:8443/p/ldf2qb21mt9vfz2f/": timeout: no recent network activ; 1× Get "https://ldfg3vr04j5zg4n1.finger-west-01.badblock.net.br:8443/p/ldfg3vr04j5zg4n1/": timeout: no recent network activ; 1× Get "https://ldg5ay0ckhjr16rs.finger-west-01.badblock.net.br:8443/p/ldg5ay0ckhjr16rs/": timeout: handshake did not compl; 1× Get "https://ldgjmdeb82dckt6b.finger-west-01.badblock.net.br:8443/p/ldgjmdeb82dckt6b/": timeout: handshake did not compl; 1× Get "https://ldh37diaal55bccd.finger-west-01.badblock.net.br:8443/p/ldh37diaal55bccd/": timeout: handshake did not compl; 1× Get "https://ldhl52zwwvfy5n0a.finger-west-01.badblock.net.br:8443/p/ldhl52zwwvfy5n0a/": timeout: handshake did not compl; 1× Get "https://ldj6pamo3ial8u1o.finger-west-01.badblock.net.br:8443/p/ldj6pamo3ial8u1o/": timeout: no recent network activ; 1× Get "https://ldk14ug9mlhc0fb8.finger-west-01.badblock.net.br:8443/p/ldk14ug9mlhc0fb8/": timeout: handshake did not compl; 1× Get "https://ldk78eerkzboxxnj.finger-west-01.badblock.net.br:8443/p/ldk78eerkzboxxnj/": timeout: handshake did not compl; 1× Get "https://ldkwryuyazbo9bla.finger-west-01.badblock.net.br:8443/p/ldkwryuyazbo9bla/": timeout: no recent network activ; 1× Get "https://ldl7glnjh3k3jivu.finger-west-01.badblock.net.br:8443/p/ldl7glnjh3k3jivu/": timeout: no recent network activ; 1× Get "https://ldm2o557qs7jc95j.finger-west-01.badblock.net.br:8443/p/ldm2o557qs7jc95j/": context deadline exceeded (Clien; 1× Get "https://ldm2xkla4hibhevp.finger-west-01.badblock.net.br:8443/p/ldm2xkla4hibhevp/": timeout: handshake did not compl; 1× Get "https://ldn8gr0tfgfnzawh.finger-west-01.badblock.net.br:8443/p/ldn8gr0tfgfnzawh/": timeout: handshake did not compl; 1× Get "https://ldnvfe0cl0qp9tlz.finger-west-01.badblock.net.br:8443/p/ldnvfe0cl0qp9tlz/": timeout: no recent network activ; 1× Get "https://ldo0v5hdaozhb919.finger-west-01.badblock.net.br:8443/p/ldo0v5hdaozhb919/": timeout: no recent network activ; 1× Get "https://ldofdran6qcdjhbf.finger-west-01.badblock.net.br:8443/p/ldofdran6qcdjhbf/": timeout: handshake did not compl; 1× Get "https://ldpxe0bfsy49saut.finger-west-01.badblock.net.br:8443/p/ldpxe0bfsy49saut/": timeout: no recent network activ; 1× Get "https://ldq11lx2lvp76b5i.finger-west-01.badblock.net.br:8443/p/ldq11lx2lvp76b5i/": timeout: handshake did not compl; 1× Get "https://ldq24xoncy5hd0ry.finger-west-01.badblock.net.br:8443/p/ldq24xoncy5hd0ry/": timeout: handshake did not compl; 1× Get "https://ldq2tkc3bt1hgnpq.finger-west-01.badblock.net.br:8443/p/ldq2tkc3bt1hgnpq/": timeout: no recent network activ; 1× Get "https://ldr04zitr73j5042.finger-west-01.badblock.net.br:8443/p/ldr04zitr73j5042/": timeout: no recent network activ; 1× Get "https://ldre23vwag27veep.finger-west-01.badblock.net.br:8443/p/ldre23vwag27veep/": context deadline exceeded (Clien; 1× Get "https://ldsxzqiejfgu5vof.finger-west-01.badblock.net.br:8443/p/ldsxzqiejfgu5vof/": timeout: no recent network activ; 1× Get "https://ldtqhkfs9fn2eums.finger-west-01.badblock.net.br:8443/p/ldtqhkfs9fn2eums/": timeout: no recent network activ; 1× Get "https://ldtqkvbzy7ylupba.finger-west-01.badblock.net.br:8443/p/ldtqkvbzy7ylupba/": timeout: no recent network activ; 1× Get "https://ldtv0k23tfied5u2.finger-west-01.badblock.net.br:8443/p/ldtv0k23tfied5u2/": timeout: handshake did not compl; 1× Get "https://ldu254ktf3s1zgtz.finger-west-01.badblock.net.br:8443/p/ldu254ktf3s1zgtz/": timeout: handshake did not compl; 1× Get "https://ldu3qxvjz4g4a429.finger-west-01.badblock.net.br:8443/p/ldu3qxvjz4g4a429/": timeout: handshake did not compl; 1× Get "https://ldvbtbdayrwrno8f.finger-west-01.badblock.net.br:8443/p/ldvbtbdayrwrno8f/": timeout: handshake did not compl; 1× Get "https://ldw77zwnuy8qt6ni.finger-west-01.badblock.net.br:8443/p/ldw77zwnuy8qt6ni/": timeout: handshake did not compl; 1× Get "https://ldw85f3xmbng9u2x.finger-west-01.badblock.net.br:8443/p/ldw85f3xmbng9u2x/": timeout: no recent network activ; 1× Get "https://ldwm5di49e2lk3ya.finger-west-01.badblock.net.br:8443/p/ldwm5di49e2lk3ya/": timeout: no recent network activ; 1× Get "https://ldwncri6049t2gzs.finger-west-01.badblock.net.br:8443/p/ldwncri6049t2gzs/": timeout: handshake did not compl; 1× Get "https://ldxbzrpi0dyzxuqo.finger-west-01.badblock.net.br:8443/p/ldxbzrpi0dyzxuqo/": timeout: handshake did not compl; 1× Get "https://ldz7ubsgra3ai7l8.finger-west-01.badblock.net.br:8443/p/ldz7ubsgra3ai7l8/": timeout: handshake did not compl; 1× Get "https://ldzpqcw8fy3kimrs.finger-west-01.badblock.net.br:8443/p/ldzpqcw8fy3kimrs/": timeout: no recent network activ; 1× Get "https://ldzw74z7pxpcvr4c.finger-west-01.badblock.net.br:8443/p/ldzw74z7pxpcvr4c/": context deadline exceeded |
| raw-banner | 7187 | 7185 | 0 | raw=1795 | 1× banner: read tcp4 192.168.1.4:59196->170.247.40.86:25: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:53203->170.247.40.86:25: read tcp4 192.168.1.4:53203->170.247.40.86: |
| raw-echo | 5992 | 5992 | 0 | raw=1319 |  |
| raw-sink | 4794 | 4793 | 0 | raw=1257 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58752->170.247.40.86:143: read tcp4 192.168.1.4:58752->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 2010845
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/bot`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 1083594
- `store_late_packets_total`: 35025
- `store_stray_total`: 1146

Relógio: servidor − local 8.001069ms no início, 8.624876ms no fim (ida e volta do ssh 17.138208ms).
Deslocamento acompanhado a cada 15 s (103 de 108 medições aceitas): 830.231µs a 9.03378ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
