Commit `v0.3.0-10-g8a6ba1b`, início 2026-11-16T07:41:05Z, 100 novas/s, até 400 simultâneas (máx. visto 400), vida 3.8s, 3 trocas, 9m0s com 30s de aquecimento descartado, mix h1=15,h1tls=15,h2=20,h3=20,raw-echo=10,raw-banner=12,raw-sink=8, origem mac; 51881 abertas, 2119 puladas.

| Meta | Métrica | Alvo | Medido | Resultado |
| --- | --- | --- | --- | --- |
| RNF-02 | atraso do feed /ws (p99) | < 1000 ms | p50 66 / p95 225 / p99 346 / máx 821 ms (n=409840) | passou |
| RNF-02* | atraso do feed /ws sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 67 / p95 234 / p99 349 / máx 821 ms (n=380140) | passou |
| RNF-02 | stream.dropped /ws | 0 | 0 avisos, 0 eventos | passou |
| RNF-02 | atraso do feed /sse (p99) | < 1000 ms | p50 65 / p95 225 / p99 346 / máx 821 ms (n=409840) | passou |
| RNF-02* | atraso do feed /sse sem o connection.updated do raw.session (ts = accept), p99 | < 1000 ms | p50 67 / p95 234 / p99 348 / máx 821 ms (n=380140) | passou |
| RNF-02 | stream.dropped /sse | 0 | 0 avisos, 0 eventos | passou |
| RNF-03 | GET /connections/{id} no cliente (p95) | < 100 ms | p50 17.0 / p95 19.1 / p99 32.9 / máx 152.5 ms (n=2550) | passou |
| RNF-03 | GET /probes/{id} no cliente (p95) | < 100 ms | p50 17.2 / p95 19.4 / p99 33.2 / máx 151.3 ms (n=2550) | passou |
| RNF-03 | erros na amostragem da API | 0 | 0 | passou |
| RNF-04 | TCP: fim no cliente → connection.closed (p95) | ≤ 500 ms | p50 138 / p95 194 / p99 211 / máx 3223 ms (n=39746) | passou |
| RNF-04 | QUIC: CONNECTION_CLOSE no cliente → connection.closed (p95) | ≤ 500 ms | p50 151 / p95 185 / p99 211 / máx 29004 ms (n=9388) | passou |
| RNF-01 | probes sem registro | 0 | 0 de 51744 (feed ws 51744, sse 51744, só API 0) | passou |
| RNF-01 | registros degraded da carga | 0 | 0 | passou |
| RNF-01 | conexões com erro no cliente | 0 | 137 de 51881 | **falhou** |
| RNF-01 | conexões puladas pelo teto do gerador | 0 | 2119 | **falhou** |
| RNF-01 | dropped_events_total (todos os serviços, Δ) | 0 | 0 | passou |
| RNF-01 | kernel_drops do capture (Δ) | 0 | 0 | passou |
| RNF-01 | health: serviços fora de ok (amostras) | 0 | 0 | passou |
| — | versão estável durante a medição (versions_match) | 1 versão | v0.3.0-10-g8a6ba1b | passou |
| RNF-01 | RAM por unit: anon máx (memory.current máx) / MemoryMax, MiB | anon < MemoryMax | capture 10 (12)/512, web 41 (44)/768, raw 18 (20)/256, dns 4 (4)/256, store 129 (2267)/6144, nats 309 (313)/1024, slice 508 (2670)/10240 | passou |
| ADR 0045 | memory.events do store: max / oom_kill (Δ na medição) | 0 / 0 | 0 / 0 | passou |
| RNF-01 | cpu.stat nr_throttled por unit (Δ na medição) | 0 em todas | capture 0, web 0, raw 0, dns 0, store 0, nats 0 | passou |
| RNF-01 | CPU do host (média / p95 / máx) | informativo | 7.5 / 8.9 / 10.7 % do host (steal médio 0.0); 120 / 143 / 171 % de um núcleo (16 vCPU) | passou |
| — | conntrack -S (Δ antes → depois: drop, insert_failed, early_drop, error) | informativo | drop 0, insert_failed 0, early_drop 0, error 0 | passou |
| RNF-05 | idade (pelo início) do registro mais antigo durante a carga | informativo | 678 s (retenção 600 s) | passou |
| RNF-05 | expurgo depois da retenção | 20 primeiros 404; ~9 min ainda 200 | antigos: 0 sumiram, 0 ficaram; ~9 min: 0 presentes, 0 sumiram | **falhou** |
| RNF-07 | maior frame capturado (capture_max_frame_bytes) | ≤ 1514 | 1514 | passou |
| RNF-07 | offload_suspect (Δ capture, registros amostrados) | 0 | 0 / 0 de 2550 | passou |

CPU (% de um núcleo) e RAM por unit (cgroup, a cada 1 s, sem o aquecimento):

| Unit | CPU média % | CPU p95 % | CPU máx % | RAM máx MiB | anon máx MiB | shmem máx MiB | MemoryMax MiB | Δ nr_throttled | Δ memory.events max / oom_kill |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capture | 3.4 | 3.7 | 4.1 | 12 | 10 | 0 | 512 | 0 | 0 / 0 |
| web | 35.5 | 39.4 | 42.7 | 44 | 41 | 0 | 768 | 0 | 0 / 0 |
| raw | 6.7 | 7.8 | 8.9 | 20 | 18 | 0 | 256 | 0 | 0 / 0 |
| dns | 0.1 | 0.1 | 0.5 | 4 | 4 | 0 | 256 | 0 | 0 / 0 |
| store | 49.0 | 57.5 | 61.7 | 2267 | 129 | 2131 | 6144 | 0 | 0 / 0 |
| nats | 13.3 | 16.1 | 17.9 | 313 | 309 | 0 | 1024 | 0 | 0 / 0 |
| slice | 107.8 | 119.7 | 127.4 | 2670 | 508 | 2132 | 10240 | 0 | 0 / 0 |

Decomposição (ms; histogramas do store por diferença aquecimento → fim, interpolados nos buckets):

| Etapa | p50 | p95 | p99 |
| --- | --- | --- | --- |
| api GET /api/v1/connections/{conn_id} (servidor) | 0.5 | 1.0 | 1.0 |
| api GET /api/v1/probes/{id} (servidor) | 0.5 | 1.0 | 1.6 |
| cliente /ws (ts → chegada) | 65.6 | 225.0 | 346.3 |
| ingest_lag (ts → commit) | 61.4 | 145.0 | 157.8 |
| live_delay (ts → envio ao cliente) | 58.4 | 242.9 | 489.9 |
| record_ready{close} (fim → gravado) | 105.5 | 157.8 | 280.3 |
| record_ready{idle} (fim → gravado) | 10000.0 | 10000.0 | 10000.0 |
| record_ready{quic_close} (fim → gravado) | 123.9 | 244.6 | 301.9 |

Atraso do feed por tipo de evento (/ws, ms):

| kind | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| @fact | 380140 | 67 | 234 | 349 | 821 |
| connection.closed | 48939 | 131 | 169 | 192 | 321 |
| connection.opened | 49347 | 73 | 115 | 132 | 246 |
| connection.updated | 208180 | 61 | 317 | 364 | 821 |
| connection.updated/h2 | 1 | 63 | 63 | 63 | 63 |
| connection.updated/http1.0 | 2 | 36 | 51 | 51 | 51 |
| connection.updated/http1.1 | 28613 | 50 | 167 | 228 | 496 |
| connection.updated/quic/h3 | 46566 | 70 | 344 | 366 | 432 |
| connection.updated/raw | 29681 | 38 | 155 | 218 | 264 |
| connection.updated/raw/unknown | 15 | 37 | 84 | 84 | 84 |
| connection.updated/tcp | 3 | 14 | 15 | 15 | 15 |
| connection.updated/tls | 24316 | 61 | 104 | 120 | 593 |
| connection.updated/tls/h2 | 49764 | 67 | 321 | 378 | 821 |
| connection.updated/tls/http1.1 | 29215 | 67 | 330 | 385 | 651 |
| connection.updated/tls/raw | 4 | 13 | 158 | 158 | 158 |
| dns.query | 35 | 52 | 91 | 92 | 92 |
| http.request | 102209 | 58 | 100 | 116 | 230 |
| packet.stray | 1130 | 10 | 83 | 109 | 137 |

Registro a partir de `data.ended` (último pacote) → connection.closed (ms):

| L4 | n | p50 | p95 | p99 | máx |
| --- | --- | --- | --- | --- | --- |
| quic | 9388 | 142 | 176 | 200 | 287 |
| tcp | 39746 | 128 | 166 | 191 | 321 |

Conexões por tipo:

| tipo | abertas | ok | degraded | proto no registro | erros |
| --- | --- | --- | --- | --- | --- |
| h1 | 7872 | 7854 | 0 | http1.1=7871 | 1× Get "http://ld1504imzp8dygsq.finger-west-01.badblock.net.br:8080/p/ld1504imzp8dygsq/": context deadline exceeded (Client; 1× Get "http://ld2bcw0d6sl5nz0c.finger-west-01.badblock.net.br:8080/p/ld2bcw0d6sl5nz0c/": context deadline exceeded (Client; 1× Get "http://ld5nwkq87l079abp.finger-west-01.badblock.net.br:8080/p/ld5nwkq87l079abp/": context deadline exceeded (Client; 1× Get "http://ld5znzkzi0d52xxq.finger-west-01.badblock.net.br:8080/p/ld5znzkzi0d52xxq/": context deadline exceeded (Client; 1× Get "http://ld7iqtq8xpf2orov.finger-west-01.badblock.net.br:8080/p/ld7iqtq8xpf2orov/": context deadline exceeded (Client; 1× Get "http://ldb3p2du17y6cft9.finger-west-01.badblock.net.br:8080/p/ldb3p2du17y6cft9/": context deadline exceeded (Client; 1× Get "http://ldb66ijc0q1u8xyx.finger-west-01.badblock.net.br:8080/p/ldb66ijc0q1u8xyx/": context deadline exceeded (Client; 1× Get "http://lddlx4h8yb2609m3.finger-west-01.badblock.net.br:8080/p/lddlx4h8yb2609m3/": context deadline exceeded (Client; 1× Get "http://ldjfp9pze9pfa8cc.finger-west-01.badblock.net.br:8080/p/ldjfp9pze9pfa8cc/": context deadline exceeded (Client; 1× Get "http://ldq7o42b7kfvnt1x.finger-west-01.badblock.net.br:8080/p/ldq7o42b7kfvnt1x/": context deadline exceeded (Client; 1× Get "http://ldrj0qchcbxs62uf.finger-west-01.badblock.net.br:8080/p/ldrj0qchcbxs62uf/": context deadline exceeded (Client; 1× Get "http://ldrk9jv7xnbcb4l0.finger-west-01.badblock.net.br:8080/p/ldrk9jv7xnbcb4l0/": context deadline exceeded (Client; 1× Get "http://ldw9j9ikdodfx23l.finger-west-01.badblock.net.br:8080/p/ldw9j9ikdodfx23l/": context deadline exceeded (Client; 5× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h1tls | 7938 | 7902 | 0 | tls=2 tls/http1.1=7934 | 1× Get "https://ld148ufejgav62n8.finger-west-01.badblock.net.br:8443/p/ld148ufejgav62n8/": context deadline exceeded (Clien; 1× Get "https://ld2zjbkimn9fuq06.finger-west-01.badblock.net.br:8443/p/ld2zjbkimn9fuq06/": context deadline exceeded (Clien; 1× Get "https://ld39nmhvul275djz.finger-west-01.badblock.net.br:8443/p/ld39nmhvul275djz/": context deadline exceeded (Clien; 1× Get "https://ld4ynaopxwgnplkw.finger-west-01.badblock.net.br:8443/p/ld4ynaopxwgnplkw/": context deadline exceeded (Clien; 1× Get "https://ld4zjxr8bkemfaoq.finger-west-01.badblock.net.br:8443/p/ld4zjxr8bkemfaoq/": context deadline exceeded (Clien; 1× Get "https://ld56p1domhg73kwz.finger-west-01.badblock.net.br:8443/p/ld56p1domhg73kwz/": context deadline exceeded (Clien; 1× Get "https://ld5zndvs675n5ymu.finger-west-01.badblock.net.br:8443/p/ld5zndvs675n5ymu/": context deadline exceeded (Clien; 1× Get "https://ld60oa74rgz01p65.finger-west-01.badblock.net.br:8443/p/ld60oa74rgz01p65/": context deadline exceeded (Clien; 1× Get "https://ld6g4jpg1gimwt0j.finger-west-01.badblock.net.br:8443/p/ld6g4jpg1gimwt0j/": context deadline exceeded (Clien; 1× Get "https://ld6uef6g7hqdop6v.finger-west-01.badblock.net.br:8443/p/ld6uef6g7hqdop6v/": context deadline exceeded (Clien; 1× Get "https://ld80n36mjvrkiml6.finger-west-01.badblock.net.br:8443/p/ld80n36mjvrkiml6/": context deadline exceeded (Clien; 1× Get "https://ld852d4t6gvr0d90.finger-west-01.badblock.net.br:8443/p/ld852d4t6gvr0d90/": context deadline exceeded (Clien; 1× Get "https://ld9mtjj51m2tbuib.finger-west-01.badblock.net.br:8443/p/ld9mtjj51m2tbuib/": context deadline exceeded (Clien; 1× Get "https://ldaiibe6c4s0dvc4.finger-west-01.badblock.net.br:8443/p/ldaiibe6c4s0dvc4/": dial tcp4 170.247.40.86:8443: i/; 1× Get "https://ldbx9sojiq5v0ilz.finger-west-01.badblock.net.br:8443/p/ldbx9sojiq5v0ilz/": context deadline exceeded (Clien; 1× Get "https://lddx5gdz3o3ya9d3.finger-west-01.badblock.net.br:8443/p/lddx5gdz3o3ya9d3/": context deadline exceeded (Clien; 1× Get "https://ldekf7xeuu2oeuob.finger-west-01.badblock.net.br:8443/p/ldekf7xeuu2oeuob/": context deadline exceeded (Clien; 1× Get "https://ldevw4lys8uyb3zt.finger-west-01.badblock.net.br:8443/p/ldevw4lys8uyb3zt/": context deadline exceeded (Clien; 1× Get "https://ldf2v1sj8hq7rxnc.finger-west-01.badblock.net.br:8443/p/ldf2v1sj8hq7rxnc/": context deadline exceeded (Clien; 1× Get "https://ldgopccijygj3tws.finger-west-01.badblock.net.br:8443/p/ldgopccijygj3tws/": context deadline exceeded (Clien; 1× Get "https://ldmi92lrirlorrvq.finger-west-01.badblock.net.br:8443/p/ldmi92lrirlorrvq/": context deadline exceeded (Clien; 1× Get "https://ldnsqaq6wdnorrq8.finger-west-01.badblock.net.br:8443/p/ldnsqaq6wdnorrq8/": context deadline exceeded (Clien; 1× Get "https://ldnu6xuxlwqoth83.finger-west-01.badblock.net.br:8443/p/ldnu6xuxlwqoth83/": context deadline exceeded (Clien; 1× Get "https://ldpx4v7hn9z9ihdu.finger-west-01.badblock.net.br:8443/p/ldpx4v7hn9z9ihdu/": context deadline exceeded (Clien; 1× Get "https://ldqeqcyviv73dymw.finger-west-01.badblock.net.br:8443/p/ldqeqcyviv73dymw/": context deadline exceeded (Clien; 1× Get "https://ldqf0h7p4li6gssz.finger-west-01.badblock.net.br:8443/p/ldqf0h7p4li6gssz/": context deadline exceeded (Clien; 1× Get "https://ldtk7kujds9arwdr.finger-west-01.badblock.net.br:8443/p/ldtk7kujds9arwdr/": context deadline exceeded (Clien; 1× Get "https://ldtnkg4979w53em7.finger-west-01.badblock.net.br:8443/p/ldtnkg4979w53em7/": context deadline exceeded (Clien; 1× Get "https://lduxnfd0u4g5uqb8.finger-west-01.badblock.net.br:8443/p/lduxnfd0u4g5uqb8/": context deadline exceeded (Clien; 1× Get "https://ldxb44yf19pjnv07.finger-west-01.badblock.net.br:8443/p/ldxb44yf19pjnv07/": context deadline exceeded (Clien; 1× Get "https://ldxgaggc1ivboise.finger-west-01.badblock.net.br:8443/p/ldxgaggc1ivboise/": context deadline exceeded (Clien; 1× Get "https://ldzb425w0birmovn.finger-west-01.badblock.net.br:8443/p/ldzb425w0birmovn/": context deadline exceeded (Clien; 1× Get "https://ldzc7802vv636s0m.finger-west-01.badblock.net.br:8443/p/ldzc7802vv636s0m/": context deadline exceeded (Clien; 3× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h2 | 10507 | 10455 | 0 | tls=5 tls/h2=10499 | 1× Get "https://ld03zrv1b6ie0d69.finger-west-01.badblock.net.br:8443/p/ld03zrv1b6ie0d69/": context deadline exceeded (Clien; 1× Get "https://ld04l46zlcnlih2o.finger-west-01.badblock.net.br:8443/p/ld04l46zlcnlih2o/": context deadline exceeded (Clien; 1× Get "https://ld18k8vmezfrkhlr.finger-west-01.badblock.net.br:8443/p/ld18k8vmezfrkhlr/": context deadline exceeded (Clien; 1× Get "https://ld1g2eg2kvyleocx.finger-west-01.badblock.net.br:8443/p/ld1g2eg2kvyleocx/": context deadline exceeded (Clien; 1× Get "https://ld3sh4dodjeew18x.finger-west-01.badblock.net.br:8443/p/ld3sh4dodjeew18x/": context deadline exceeded (Clien; 1× Get "https://ld4l65uimuchqqq4.finger-west-01.badblock.net.br:8443/p/ld4l65uimuchqqq4/": context deadline exceeded (Clien; 1× Get "https://ld4mannvr2upj7p4.finger-west-01.badblock.net.br:8443/p/ld4mannvr2upj7p4/": context deadline exceeded (Clien; 1× Get "https://ld5mfattxa88lg35.finger-west-01.badblock.net.br:8443/p/ld5mfattxa88lg35/": context deadline exceeded (Clien; 1× Get "https://ld85puyfp5lpz8wl.finger-west-01.badblock.net.br:8443/p/ld85puyfp5lpz8wl/": context deadline exceeded (Clien; 1× Get "https://ld92bq0fxbzcpoh5.finger-west-01.badblock.net.br:8443/p/ld92bq0fxbzcpoh5/": context deadline exceeded (Clien; 1× Get "https://ldabb7kqd8s7oyfi.finger-west-01.badblock.net.br:8443/p/ldabb7kqd8s7oyfi/": context deadline exceeded (Clien; 1× Get "https://ldam2jf3od2t3rfk.finger-west-01.badblock.net.br:8443/p/ldam2jf3od2t3rfk/": context deadline exceeded (Clien; 1× Get "https://ldb9be4hrifoi9cn.finger-west-01.badblock.net.br:8443/p/ldb9be4hrifoi9cn/": context deadline exceeded (Clien; 1× Get "https://ldcj8204r609s6u2.finger-west-01.badblock.net.br:8443/p/ldcj8204r609s6u2/": context deadline exceeded (Clien; 1× Get "https://lddtu1rz03lnstjp.finger-west-01.badblock.net.br:8443/p/lddtu1rz03lnstjp/": context deadline exceeded (Clien; 1× Get "https://lddtzl8n8ak22aqn.finger-west-01.badblock.net.br:8443/p/lddtzl8n8ak22aqn/": context deadline exceeded (Clien; 1× Get "https://lde6d94liatqifcr.finger-west-01.badblock.net.br:8443/p/lde6d94liatqifcr/": context deadline exceeded (Clien; 1× Get "https://lde6t80i873cq7bi.finger-west-01.badblock.net.br:8443/p/lde6t80i873cq7bi/": context deadline exceeded (Clien; 1× Get "https://ldebei1kxmznjddl.finger-west-01.badblock.net.br:8443/p/ldebei1kxmznjddl/": context deadline exceeded (Clien; 1× Get "https://ldepdl77lkyj80lt.finger-west-01.badblock.net.br:8443/p/ldepdl77lkyj80lt/": context deadline exceeded (Clien; 1× Get "https://ldesgk1agebzcurx.finger-west-01.badblock.net.br:8443/p/ldesgk1agebzcurx/": context deadline exceeded (Clien; 1× Get "https://ldg2aj4230p5efu3.finger-west-01.badblock.net.br:8443/p/ldg2aj4230p5efu3/": context deadline exceeded (Clien; 1× Get "https://ldgj0yucc8x2i7fp.finger-west-01.badblock.net.br:8443/p/ldgj0yucc8x2i7fp/": context deadline exceeded (Clien; 1× Get "https://ldi76mifnn23nrq1.finger-west-01.badblock.net.br:8443/p/ldi76mifnn23nrq1/": context deadline exceeded (Clien; 1× Get "https://ldi9u2nxcbq39qo7.finger-west-01.badblock.net.br:8443/p/ldi9u2nxcbq39qo7/": context deadline exceeded (Clien; 1× Get "https://ldjd491wsquprlr2.finger-west-01.badblock.net.br:8443/p/ldjd491wsquprlr2/": context deadline exceeded (Clien; 1× Get "https://ldlb3w01j0kdoyak.finger-west-01.badblock.net.br:8443/p/ldlb3w01j0kdoyak/": context deadline exceeded (Clien; 1× Get "https://ldlu2i9jxrtnzxpl.finger-west-01.badblock.net.br:8443/p/ldlu2i9jxrtnzxpl/": context deadline exceeded (Clien; 1× Get "https://ldnwdmu7iuiaawkt.finger-west-01.badblock.net.br:8443/p/ldnwdmu7iuiaawkt/": context deadline exceeded (Clien; 1× Get "https://ldobypdxjv8sm2lb.finger-west-01.badblock.net.br:8443/p/ldobypdxjv8sm2lb/": context deadline exceeded (Clien; 1× Get "https://ldptptfkdj3v8xve.finger-west-01.badblock.net.br:8443/p/ldptptfkdj3v8xve/": context deadline exceeded (Clien; 1× Get "https://ldqodtn26avibkmb.finger-west-01.badblock.net.br:8443/p/ldqodtn26avibkmb/": context deadline exceeded (Clien; 1× Get "https://ldqsar3da2bgnndb.finger-west-01.badblock.net.br:8443/p/ldqsar3da2bgnndb/": context deadline exceeded (Clien; 1× Get "https://ldr9vf03ean26ooo.finger-west-01.badblock.net.br:8443/p/ldr9vf03ean26ooo/": context deadline exceeded (Clien; 1× Get "https://ldrst33tovnhx8hu.finger-west-01.badblock.net.br:8443/p/ldrst33tovnhx8hu/": context deadline exceeded (Clien; 1× Get "https://ldtinhxznny63ydw.finger-west-01.badblock.net.br:8443/p/ldtinhxznny63ydw/": context deadline exceeded (Clien; 1× Get "https://ldv0ddmxong7adyn.finger-west-01.badblock.net.br:8443/p/ldv0ddmxong7adyn/": context deadline exceeded (Clien; 1× Get "https://ldvqy8lfo3azecni.finger-west-01.badblock.net.br:8443/p/ldvqy8lfo3azecni/": context deadline exceeded (Clien; 1× Get "https://ldvsvmfj269jo5ul.finger-west-01.badblock.net.br:8443/p/ldvsvmfj269jo5ul/": context deadline exceeded (Clien; 1× Get "https://ldvyumxfn5bq3l3v.finger-west-01.badblock.net.br:8443/p/ldvyumxfn5bq3l3v/": context deadline exceeded (Clien; 1× Get "https://ldx9bi6dvz07i0kj.finger-west-01.badblock.net.br:8443/p/ldx9bi6dvz07i0kj/": context deadline exceeded (Clien; 1× Get "https://ldzwwq2j033ctbjw.finger-west-01.badblock.net.br:8443/p/ldzwwq2j033ctbjw/": context deadline exceeded (Clien; 10× context deadline exceeded (Client.Timeout or context cancellation while reading body) |
| h3 | 9910 | 9910 | 0 | quic/h3=9910 |  |
| raw-banner | 6280 | 6271 | 0 | raw=6277 | 1× banner: read tcp4 192.168.1.4:58017->170.247.40.86:25: i/o timeout; 1× banner: read tcp4 192.168.1.4:60714->170.247.40.86:25: i/o timeout; 1× banner: read tcp4 192.168.1.4:60917->170.247.40.86:21: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:49643->170.247.40.86:25: read tcp4 192.168.1.4:49643->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:57970->170.247.40.86:25: read tcp4 192.168.1.4:57970->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58117->170.247.40.86:25: read tcp4 192.168.1.4:58117->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58491->170.247.40.86:25: read tcp4 192.168.1.4:58491->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58797->170.247.40.86:25: read tcp4 192.168.1.4:58797->170.247.40.86:; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:60033->170.247.40.86:21: read tcp4 192.168.1.4:60033->170.247.40.86: |
| raw-echo | 5187 | 5171 | 0 | raw=5187 | 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:55427->170.247.40.86:7: read tcp4 192.168.1.4:55427->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:57933->170.247.40.86:7: read tcp4 192.168.1.4:57933->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58442->170.247.40.86:7: read tcp4 192.168.1.4:58442->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58729->170.247.40.86:7: read tcp4 192.168.1.4:58729->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:58768->170.247.40.86:7: read tcp4 192.168.1.4:58768->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59079->170.247.40.86:7: read tcp4 192.168.1.4:59079->170.247.40.86:7; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59542->170.247.40.86:7: read tcp4 192.168.1.4:59542->170.247.40.86:7; 1× eco: read tcp4 192.168.1.4:56988->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:58037->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:58199->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:58435->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:58521->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:58824->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:60369->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:60460->170.247.40.86:7: i/o timeout; 1× eco: read tcp4 192.168.1.4:61145->170.247.40.86:7: i/o timeout |
| raw-sink | 4187 | 4181 | 0 | raw=4183 | 1× banner: read tcp4 192.168.1.4:58138->170.247.40.86:143: i/o timeout; 1× banner: read tcp4 192.168.1.4:59454->170.247.40.86:143: i/o timeout; 1× banner: read tcp4 192.168.1.4:59554->170.247.40.86:143: i/o timeout; 1× banner: read tcp4 192.168.1.4:59654->170.247.40.86:143: i/o timeout; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:50073->170.247.40.86:143: read tcp4 192.168.1.4:50073->170.247.40.86; 1× depois do meio-fechamento: writeto tcp4 192.168.1.4:59357->170.247.40.86:143: read tcp4 192.168.1.4:59357->170.247.40.86 |

Outros contadores (Δ durante a medição):

- `capture_kernel_drops_total`: 0
- `capture_kernel_packets_total`: 1609691
- `capture_queue_freezes_total`: 0
- `capture_truncated_total`: 0
- `dropped_events_total/capture`: 0
- `dropped_events_total/dns`: 0
- `dropped_events_total/raw`: 0
- `dropped_events_total/store`: 0
- `dropped_events_total/web`: 0
- `fs_store_connections_degraded_total`: 0
- `fs_store_live_dropped_total`: 0
- `store_late_packets_total`: 54978
- `store_stray_total`: 1162

Relógio: servidor − local 3.027647ms no início, 4.01282ms no fim (ida e volta do ssh 16.991958ms).
Deslocamento acompanhado a cada 15 s (39 de 39 medições aceitas): 2.594183ms a 4.30619ms; o atraso do feed usa o vigente na chegada, o RNF-04 é medido só no relógio local.

**Há metas que falharam.**
