Commit `v0.3.0-10-g8a6ba1b`, início 2026-11-16T07:50:33Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 10m0s com 1m0s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 57280 abertas, 2720 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 67 / p95 232 / p99 352 / máx 2112 ms (n=435164) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 68 / p95 243 / p99 354 / máx 2112 ms (n=402863) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 66 / p95 232 / p99 351 / máx 2112 ms (n=435164) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 68 / p95 243 / p99 354 / máx 2112 ms (n=402863) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 19.3 / p99 33.4 / máx 153.5 ms (n=2700) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.3 / p95 19.5 / p99 33.5 / máx 152.5 ms (n=2700) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 138 / p95 193 / p99 208 / máx 3280 ms (n=42048) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 151 / p95 188 / p99 212 / máx 28989 ms (n=9655) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 57145 (feed ws 57145, sse 57145, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 135 de 57280 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 2720 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-10-g8a6ba1b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/512, web 41 (44)/768, raw 18 (20)/256, dns 4 (4)/256, store 132 (2399)/6144, nats 312 (315)/1024, slice 516 (2802)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.7 / 9.1 / 11.1 % do host (steal médio 0.0); 123 / 145 / 178 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 1 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 678 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 20 sumiram, 0 ficaram; ~9 min: 20 presentes, 0 sumiram | passou |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2700 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.8 | 4.3 | 12 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 35.1 | 39.7 | 44.4 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.9 | 8.1 | 9.1 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.2 | 4 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 50.6 | 58.2 | 64.2 | 2399 | 132 | 2268 | 6144 | 0 | 0 / 0 |
| nats | 13.2 | 16.0 | 18.1 | 315 | 312 | 0 | 1024 | 0 | 0 / 0 |
| slice | 109.3 | 120.7 | 130.2 | 2802 | 516 | 2269 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.5 |
| cliente /ws (ts → chegada) | 66.9 | 231.9 | 351.6 |
| ingest_lag (ts → commit) | 62.2 | 145.4 | 157.7 |
| live_delay (ts → envio ao cliente) | 59.3 | 248.9 | 498.1 |
| record_ready{close} (fim → gravado) | 107.1 | 172.4 | 287.5 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 124.6 | 253.1 | 303.6 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 402863 | 68 | 243 | 354 | 2112 |
| connection.closed | 51489 | 133 | 171 | 192 | 251 |
| connection.opened | 51966 | 74 | 115 | 131 | 2112 |
| connection.updated | 223205 | 62 | 322 | 366 | 822 |
| connection.updated/h2 | 2 | 14 | 49 | 49 | 49 |
| connection.updated/http1.0 | 3 | 57 | 65 | 65 | 65 |
| connection.updated/http1.1 | 31005 | 51 | 182 | 234 | 498 |
| connection.updated/quic/h3 | 47954 | 71 | 345 | 372 | 423 |
| connection.updated/raw | 32285 | 39 | 162 | 222 | 278 |
| connection.updated/raw/unknown | 15 | 40 | 234 | 234 | 234 |
| connection.updated/tcp | 3 | 14 | 15 | 15 | 15 |
| connection.updated/tls | 27186 | 62 | 104 | 119 | 372 |
| connection.updated/tls/h2 | 53088 | 70 | 330 | 386 | 822 |
| connection.updated/tls/http1.1 | 31663 | 71 | 337 | 397 | 647 |
| connection.updated/tls/raw | 1 | 14 | 14 | 14 | 14 |
| dns.query | 10 | 63 | 129 | 129 | 129 |
| http.request | 107262 | 59 | 101 | 115 | 165 |
| packet.stray | 1232 | 10 | 82 | 107 | 134 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 9655 | 143 | 179 | 202 | 255 |
| tcp | 42048 | 130 | 169 | 191 | 247 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 8737 | 8703 | 0 | http1.1=8736 | 1× Get "http://ld0q0m6itohiw6ma.finger-west-01.badblock.net.br:8080/p/ld0q0m6itohiw6ma/": context deadline exceeded (Client; 1× Get "http://ld3hnpuo0eak1e10.finger-west-01.badblock.net.br:8080/p/ld3hnpuo0eak1e10/": context deadline exceeded (Client; 1× Get "http://ld5e7voja06051e5.finger-west-01.badblock.net.br:8080/p/ld5e7voja06051e5/": context deadline exceeded (Client; 1× Get "http://ld65q42yhddvmnjx.finger-west-01.badblock.net.br:8080/p/ld65q42yhddvmnjx/": context deadline exceeded (Client; 1× Get "http://ld861j7sv8rck0hj.finger-west-01.badblock.net.br:8080/p/ld861j7sv8rck0hj/": context deadline exceeded (Client; 1× Get "http://ld87jo8egiu309wz.finger-west-01.badblock.net.br:8080/p/ld87jo8egiu309wz/": context deadline exceeded (Client; 1× Get "http://ld9gzxo7psgp2zfy.finger-west-01.badblock.net.br:8080/p/ld9gzxo7psgp2zfy/": context deadline exceeded (Client; 1× Get "http://lda6qdux2tn4sv2u.finger-west-01.badblock.net.br:8080/p/lda6qdux2tn4sv2u/": context deadline exceeded (Client; 1× Get "http://ldbvuroyg6f4gzdq.finger-west-01.badblock.net.br:8080/p/ldbvuroyg6f4gzdq/": context deadline exceeded (Client; 1× Get "http://ldd1fudtn9p9oq10.finger-west-01.badblock.net.br:8080/p/ldd1fudtn9p9oq10/": context deadline exceeded (Client; 1× Get "http://ldd7ce3onaidz2fs.finger-west-01.badblock.net.br:8080/p/ldd7ce3onaidz2fs/": context deadline exceeded (Client; 1× Get "http://lddbskj6r0gm8jdn.finger-west-01.badblock.net.br:8080/p/lddbskj6r0gm8jdn/": context deadline exceeded (Client; 1× Get "http://ldhe63ndvz1w0vwz.finger-west-01.badblock.net.br:8080/p/ldhe63ndvz1w0vwz/": context deadline exceeded (Client; 1× Get "http://ldi43concj66gebo.finger-west-01.badblock.net.br:8080/p/ldi43concj66gebo/": context deadline exceeded (Client; 1× Get "http://ldjala7xocrbozat.finger-west-01.badblock.net.br:8080/p/ldjala7xocrbozat/": context deadline exceeded (Client; 1× Get "http://ldmqgeucnwlmtb1w.finger-west-01.badblock.net.br:8080/p/ldmqgeucnwlmtb1w/": context deadline exceeded (Client; 1× Get "http://ldorfc0ojj4qj6l9.finger-west-01.badblock.net.br:8080/p/ldorfc0ojj4qj6l9/": context deadline exceeded (Client; 1× Get "http://ldqqakvqg2bccpnr.finger-west-01.badblock.net.br:8080/p/ldqqakvqg2bccpnr/": context deadline exceeded (Client; 1× Get "http://ldr04kjvrrgfbxpg.finger-west-01.badblock.net.br:8080/p/ldr04kjvrrgfbxpg/": context deadline exceeded (Client; 1× Get "http://ldr5azogmqepko4r.finger-west-01.badblock.net.br:8080/p/ldr5azogmqepko4r/": context deadline exceeded (Client; 1× Get "http://ldriy2rkm1p5rj50.finger-west-01.badblock.net.br:8080/p/ldriy2rkm1p5rj50/": context deadline exceeded (Client; 1× Get "http://ldsdc3pxz4htxvdu.finger-west-01.badblock.net.br:8080/p/ldsdc3pxz4htxvdu/": context deadline exceeded (Client; 1× Get "http://ldsxtr7srgmaxwcu.finger-west-01.badblock.net.br:8080/p/ldsxtr7srgmaxwcu/": context deadline exceeded (Client; 1× Get "http://ldu6rc6xpxt2m3hy.finger-west-01.badblock.net.br:8080/p/ldu6rc6xpxt2m3hy/": context deadline exceeded (Client; 1× Get "http://ldujvly886zauish.finger-west-01.badblock.net.br:8080/p/ldujvly886zauish/": context deadline exceeded (Client; 1× Get "http://ldujxcz5vvkxgjs3.finger-west-01.badblock.net.br:8080/p/ldujxcz5vvkxgjs3/": context deadline exceeded (Client; 1× Get "http://ldz4kvq7jfscohv5.finger-west-01.badblock.net.br:8080/p/ldz4kvq7jfscohv5/": context deadline exceeded (Client; 7× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h1tls | 8843 | 8806 | 0 | tls=3 tls/http1.1=8836 | 1× Get "https://ld1gkp6yr0t0j14e.finger-west-01.badblock.net.br:8443/p/ld1gkp6yr0t0j14e/": context deadline exceeded (Clien; 1× Get "https://ld7kebqc8klwu85w.finger-west-01.badblock.net.br:8443/p/ld7kebqc8klwu85w/": context deadline exceeded (Clien; 1× Get "https://ld7p43mulj7zruvt.finger-west-01.badblock.net.br:8443/p/ld7p43mulj7zruvt/": context deadline exceeded (Clien; 1× Get "https://ld8hsxscm6q7fgx6.finger-west-01.badblock.net.br:8443/p/ld8hsxscm6q7fgx6/": context deadline exceeded (Clien; 1× Get "https://ld8o9ezpo4v62sv7.finger-west-01.badblock.net.br:8443/p/ld8o9ezpo4v62sv7/": context deadline exceeded (Clien; 1× Get "https://ld8sxybqrhw8va86.finger-west-01.badblock.net.br:8443/p/ld8sxybqrhw8va86/": context deadline exceeded (Clien; 1× Get "https://ld8tzfr7nglivtbb.finger-west-01.badblock.net.br:8443/p/ld8tzfr7nglivtbb/": context deadline exceeded (Clien; 1× Get "https://ld9kblneoy5htsup.finger-west-01.badblock.net.br:8443/p/ld9kblneoy5htsup/": context deadline exceeded (Clien; 1× Get "https://ldabuihj3b81f8ia.finger-west-01.badblock.net.br:8443/p/ldabuihj3b81f8ia/": context deadline exceeded (Clien; 1× Get "https://ldatkyst6avmp0ce.finger-west-01.badblock.net.br:8443/p/ldatkyst6avmp0ce/": context deadline exceeded (Clien; 1× Get "https://ldc66a5rxc98opq9.finger-west-01.badblock.net.br:8443/p/ldc66a5rxc98opq9/": context deadline exceeded (Clien; 1× Get "https://ldeqc47koosxofl9.finger-west-01.badblock.net.br:8443/p/ldeqc47koosxofl9/": context deadline exceeded (Clien; 1× Get "https://ldfw0uejk5ayo72f.finger-west-01.badblock.net.br:8443/p/ldfw0uejk5ayo72f/": context deadline exceeded (Clien; 1× Get "https://ldi28tcu0ggv674e.finger-west-01.badblock.net.br:8443/p/ldi28tcu0ggv674e/": context deadline exceeded (Clien; 1× Get "https://ldikaag7b7krx1gx.finger-west-01.badblock.net.br:8443/p/ldikaag7b7krx1gx/": context deadline exceeded (Clien; 1× Get "https://ldiswztowf713tfn.finger-west-01.badblock.net.br:8443/p/ldiswztowf713tfn/": context deadline exceeded (Clien; 1× Get "https://ldj0n24470qkl36z.finger-west-01.badblock.net.br:8443/p/ldj0n24470qkl36z/": context deadline exceeded (Clien; 1× Get "https://ldjev2otzlrsp2cc.finger-west-01.badblock.net.br:8443/p/ldjev2otzlrsp2cc/": context deadline exceeded (Clien; 1× Get "https://ldlmkmmh4a4latin.finger-west-01.badblock.net.br:8443/p/ldlmkmmh4a4latin/": context deadline exceeded (Clien; 1× Get "https://ldm390z9q7gsa9qr.finger-west-01.badblock.net.br:8443/p/ldm390z9q7gsa9qr/": context deadline exceeded (Clien; 1× Get "https://ldo1pp6v4lgmnrpj.finger-west-01.badblock.net.br:8443/p/ldo1pp6v4lgmnrpj/": context deadline exceeded (Clien; 1× Get "https://ldpuozxyt7ff7p87.finger-west-01.badblock.net.br:8443/p/ldpuozxyt7ff7p87/": context deadline exceeded (Clien; 1× Get "https://ldq45bywtw90v8rj.finger-west-01.badblock.net.br:8443/p/ldq45bywtw90v8rj/": context deadline exceeded (Clien; 1× Get "https://ldqa7hfw0d8iltad.finger-west-01.badblock.net.br:8443/p/ldqa7hfw0d8iltad/": context deadline exceeded (Clien; 1× Get "https://ldrk88wo9cw9zern.finger-west-01.badblock.net.br:8443/p/ldrk88wo9cw9zern/": context deadline exceeded (Clien; 1× Get "https://ldt679xo26ws6vz2.finger-west-01.badblock.net.br:8443/p/ldt679xo26ws6vz2/": context deadline exceeded (Clien; 1× Get "https://ldtkib0qa7tgj2um.finger-west-01.badblock.net.br:8443/p/ldtkib0qa7tgj2um/": context deadline exceeded (Clien; 1× Get "https://lduccx2239cnviuv.finger-west-01.badblock.net.br:8443/p/lduccx2239cnviuv/": context deadline exceeded (Clien; 1× Get "https://ldwcnra1a6k0agql.finger-west-01.badblock.net.br:8443/p/ldwcnra1a6k0agql/": context deadline exceeded (Clien; 1× Get "https://ldx7fqu3my03xrdl.finger-west-01.badblock.net.br:8443/p/ldx7fqu3my03xrdl/": context deadline exceeded (Clien; 7× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h2 | 11600 | 11562 | 0 | tls=3 tls/h2=11594 | 1× Get "https://ld1i9s91dmqgbimk.finger-west-01.badblock.net.br:8443/p/ld1i9s91dmqgbimk/": context deadline exceeded (Clien; 1× Get "https://ld1wbpu41zykl4bz.finger-west-01.badblock.net.br:8443/p/ld1wbpu41zykl4bz/": context deadline exceeded (Clien; 1× Get "https://ld2dljvzzvho5vzy.finger-west-01.badblock.net.br:8443/p/ld2dljvzzvho5vzy/": context deadline exceeded (Clien; 1× Get "https://ld2ytm9sr4tjv9tv.finger-west-01.badblock.net.br:8443/p/ld2ytm9sr4tjv9tv/": context deadline exceeded (Clien; 1× Get "https://ld41jl1h5yw8dh1l.finger-west-01.badblock.net.br:8443/p/ld41jl1h5yw8dh1l/": context deadline exceeded (Clien; 1× Get "https://ld7vc89gzahlztsv.finger-west-01.badblock.net.br:8443/p/ld7vc89gzahlztsv/": context deadline exceeded (Clien; 1× Get "https://ld7y7yflgqmqi1e6.finger-west-01.badblock.net.br:8443/p/ld7y7yflgqmqi1e6/": context deadline exceeded (Clien; 1× Get "https://ld8e3uhoh2q9msc0.finger-west-01.badblock.net.br:8443/p/ld8e3uhoh2q9msc0/": context deadline exceeded (Clien; 1× Get "https://ld8fzwss71f8cqgd.finger-west-01.badblock.net.br:8443/p/ld8fzwss71f8cqgd/": context deadline exceeded (Clien; 1× Get "https://ld95ozoaxjsjzua5.finger-west-01.badblock.net.br:8443/p/ld95ozoaxjsjzua5/": context deadline exceeded (Clien; 1× Get "https://ld99x451p4yocgfd.finger-west-01.badblock.net.br:8443/p/ld99x451p4yocgfd/": context deadline exceeded (Clien; 1× Get "https://ldc6c9pvssqkoc95.finger-west-01.badblock.net.br:8443/p/ldc6c9pvssqkoc95/": context deadline exceeded (Clien; 1× Get "https://ldd24m9k4neqimon.finger-west-01.badblock.net.br:8443/p/ldd24m9k4neqimon/": context deadline exceeded (Clien; 1× Get "https://lddi6zbutljmyfw0.finger-west-01.badblock.net.br:8443/p/lddi6zbutljmyfw0/": context deadline exceeded (Clien; 1× Get "https://ldeiej6kdbqux1p7.finger-west-01.badblock.net.br:8443/p/ldeiej6kdbqux1p7/": context deadline exceeded (Clien; 1× Get "https://ldf17vb0wei24d35.finger-west-01.badblock.net.br:8443/p/ldf17vb0wei24d35/": context deadline exceeded (Clien; 1× Get "https://ldhewzf8me6mcrdz.finger-west-01.badblock.net.br:8443/p/ldhewzf8me6mcrdz/": context deadline exceeded (Clien; 1× Get "https://ldls9d7khtonyly6.finger-west-01.badblock.net.br:8443/p/ldls9d7khtonyly6/": context deadline exceeded (Clien; 1× Get "https://ldmnaenei9gfrmaa.finger-west-01.badblock.net.br:8443/p/ldmnaenei9gfrmaa/": context deadline exceeded (Clien; 1× Get "https://ldnwik6k70mwebpc.finger-west-01.badblock.net.br:8443/p/ldnwik6k70mwebpc/": context deadline exceeded (Clien; 1× Get "https://ldo0qowke5bj7mol.finger-west-01.badblock.net.br:8443/p/ldo0qowke5bj7mol/": context deadline exceeded (Clien; 1× Get "https://ldpvbgaqhti7jl56.finger-west-01.badblock.net.br:8443/p/ldpvbgaqhti7jl56/": context deadline exceeded (Clien; 1× Get "https://ldqaki7dm2vfsnh2.finger-west-01.badblock.net.br:8443/p/ldqaki7dm2vfsnh2/": context deadline exceeded (Clien; 1× Get "https://ldqj65dtdb5uygdb.finger-west-01.badblock.net.br:8443/p/ldqj65dtdb5uygdb/": context deadline exceeded (Clien; 1× Get "https://ldqms5br74u1lv8g.finger-west-01.badblock.net.br:8443/p/ldqms5br74u1lv8g/": context deadline exceeded (Clien; 1× Get "https://lds00cz1n15rn30d.finger-west-01.badblock.net.br:8443/p/lds00cz1n15rn30d/": context deadline exceeded (Clien; 1× Get "https://ldurcdcgvv5c0ktm.finger-west-01.badblock.net.br:8443/p/ldurcdcgvv5c0ktm/": context deadline exceeded (Clien; 1× Get "https://ldv7y148v2gqfmax.finger-west-01.badblock.net.br:8443/p/ldv7y148v2gqfmax/": context deadline exceeded (Clien; 1× Get "https://ldw82aq05l5rlh4r.finger-west-01.badblock.net.br:8443/p/ldw82aq05l5rlh4r/": context deadline exceeded (Clien; 1× Get "https://ldwf8n25ogf5cuab.finger-west-01.badblock.net.br:8443/p/ldwf8n25ogf5cuab/": context deadline exceeded (Clien; 1× Get "https://ldwroiftmfkw4jen.finger-west-01.badblock.net.br:8443/p/ldwroiftmfkw4jen/": context deadline exceeded (Clien; 1× Get "https://ldxhtxfq02sr6sc4.finger-west-01.badblock.net.br:8443/p/ldxhtxfq02sr6sc4/": context deadline exceeded (Clien; 1× Get "https://ldy3uifxp8ou6q32.finger-west-01.badblock.net.br:8443/p/ldy3uifxp8ou6q32/": context deadline exceeded (Clien; 1× Get "https://ldzshsb3zd122mun.finger-west-01.badblock.net.br:8443/p/ldzshsb3zd122mun/": context deadline exceeded (Clien; 4× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h3 | 10702 | 10702 | 0 | quic/h3=10702 |  |
| raw-banner | 6959 | 6951 | 0 | raw=6954 | 1× banner: read tcp4 192.168.1.4:49948->170.247.40.86:25: i/o timeout; 1× banner: read tcp4 192.168.1.4:57665->170.247.40.86:25: i/o timeout; 1× banner: read tcp4 192.168.1.4:58592->170.247.40.86:25: i/o timeout; 1× banner: read tcp4 192.168.1.4:59686->170.247.40.86:21: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59347->170.247.40.86:25: read tcp4 192.168.1.4:59347->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59857->170.247.40.86:25: read tcp4 192.168.1.4:59857->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:65161->170.247.40.86:21: read tcp4 192.168.1.4:65161->170.247.40.86:; 1× dial tcp4 170.247.40.86:21: i/o timeout |
| raw-echo | 5773 | 5760 | 0 | raw=5773 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:52527->170.247.40.86:7: read tcp4 192.168.1.4:52527->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58633->170.247.40.86:7: read tcp4 192.168.1.4:58633->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59274->170.247.40.86:7: read tcp4 192.168.1.4:59274->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:61935->170.247.40.86:7: read tcp4 192.168.1.4:61935->170.247.40.86:7; 1× eco: read tcp4 192.168.1.4:51142->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:53077->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:57882->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:59283->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:59439->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:60239->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:60308->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:60848->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:65166->170.247.40.86:7: i/o timeout |
| raw-sink | 4666 | 4661 | 0 | raw=4664 | 1× banner: read tcp4 192.168.1.4:49468->170.247.40.86:143: i/o timeout; 1× banner: read tcp4 192.168.1.4:56605->170.247.40.86:143: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:56456->170.247.40.86:143: read tcp4 192.168.1.4:56456->170.247.40.86; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59324->170.247.40.86:143: read tcp4 192.168.1.4:59324->170.247.40.86; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:65387->170.247.40.86:143: read tcp4 192.168.1.4:65387->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1747294
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 62698
- `store_stray_total`: 1350

Relógio: servidor − local 4.029357ms no início, 4.184788ms no fim (ida e volta do ssh 16.4985ms).
Deslocamento acompanhado a cada 15 s (47 de 47 medições aceitas): 3.757904ms a 4.321105ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
