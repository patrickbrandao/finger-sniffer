# Auditoria F5: spec × implementação (task 071)

> Data: 09/11/2026. Commit auditado: `origin/main` bfa81d7 (bfa81d70dcf1dd86c0c2fdbb20b7dc6251406eb2).
> As divergências encontradas viraram as tarefas 077–088 (tabela "Tarefas criadas" abaixo); este relatório é o
> retrato da auditoria e não é atualizado conforme elas são entregues.

Papel: reviewer. Base: `origin/main` bfa81d7 (depois chegaram 486ba13/076, 5aaa1d3/074 e 98cb740/066, que
fecham o `-timeout` do e2e, o `rtt_app_ms` e os casos 6 e 11). vps602 em 09/11/2026, ~09:30–10:00 UTC, com
versões misturadas (capture/dns/raw 9d18a32, store d91c354, web 344bdec), o que gerou a task 078.
Método: leitura do código, testes Go dos pacotes de cada escopo (todos verdes), `make verify-quick` num clone
descartável (OK), CI de 99e48d3 (verify-full OK, cobertura total 88,1%), fuzz manual de 60 s nos alvos de
008/009/010/011 (sem pânico) e tráfego real contra a vps602 (curl h1/h2/h2c/h3, openssl, ws/RFC 8441, nc, dig
direto e por 8.8.8.8/1.1.1.1/9.9.9.9), com registros e pcaps da API conferidos com tshark 4.4 e `p0f -r`.
Não rodei: e2e completo, carga (068), Chrome/Firefox ao vivo, deploy numa VPS limpa nem idempotência do deploy.

## Tarefas criadas

| Tarefa | Dono | Classificação | Resumo |
| --- | --- | --- | --- |
| 077 | implementer-store | **bloqueia-release** | registro fechado só ~1 s depois do fim (`CloseGrace` 1 s) × RNF-04 p95 ≤ 500 ms |
| 078 | infra | **bloqueia-release** | `deploy SVC=x` troca todos os binários e reinicia um; vps602 com versões misturadas, openapi 0.3.0 servido |
| 086 | architect | **bloqueia-release** | contratos: 400 não declarado, asyncapi não subiu de versão, Akamai do h2c Upgrade, unidade do handshake, close do WS |
| 079 | implementer-capture | pode-esperar | snaplen ignorado, `offload_suspect` com agregação, teto em bytes do lote, IPv6 com extensão no BPF, nomes de métricas |
| 080 | implementer-store | pode-esperar | retenção conta do início; conexão > 10 min some ao fechar e gera registro fantasma |
| 081 | implementer-store | pode-esperar | `offload_suspect` nunca preenchido, `ip` só do SYN, IPv6 com extensão, `close.how` com RST final |
| 082 | implementer-store | pode-esperar | health não compara sysctls nem acusa `versions_match:false`; API em `*:9000/9001` |
| 083 | implementer-raw | pode-esperar | raw em todos os endereços (ADR 0001); `server_sent_after_client_fin` true sem entrega |
| 084 | infra | pode-esperar | `.env.example` sem 4 `FS_*` lidas pelo código |
| 085 | implementer-web | pode-esperar | Alt-Svc depois dos `h=` (spec: antes) |
| 087 | architect | pode-esperar | 13 mudanças de spec/ADR (relógio TSval, QUIC × RNF-04, tempo de fuzz, WS × RF-08, etc.) |
| 088 | tester | pode-esperar | golden pcap Windows para JA4T/p0f |

Já abertas antes, sem nova tarefa: 075 (idle_before_close). 074 e 076 foram mergeadas durante a auditoria.

## Spec 000
| Item | Status | Evidência / teste |
| --- | --- | --- |
| Sucesso 1 (13 casos, caminho direto) | ok depois do 98cb740 (066) | test/e2e/f3_*, f4_*, f5_idle_test.go, f5_tcp_test.go |
| Sucesso 2 (FoxIO/tshark) | ok | f5_fingerprints_test.go TestF5Fingerprints; conferência ao vivo de JA3/JA4/JA4 q/Akamai/JA4H/JA4T/p0f |
| Sucesso 3 (RNF na carga) | pendente (068) | — |
| RNF-04 registro ≤ 500 ms | **divergência → 077** | medido 1084–1333 ms |
| RNF-05 retenção 10 min / 2 GiB | ok para conexões curtas; longas → 080 | f2_test.go TestRetention |
| RNF-06/07 (relógio, frames ≤ MTU+14) | ok | NTP sincronizado; `capture_max_frame_bytes` = 1514 em download de 64 MiB |
| Go 1.27, CGO_ENABLED=0, estático, Apache-2.0 + NOTICE | ok | `go version -m`, `file`, scripts/check-binaries.sh |

## Spec 001
5 serviços + NATS, units e ordem, capabilities, MemoryMax, FS_EVENTS (memória, 60 s, 32 MiB, 5 subjects, durável
`store`), buffer do produtor 30 s/16 MiB, eventos ≤ 900 KiB, NATS só em 127.0.0.1: ok. CA1 health com os 5 `ok`:
ok, mas `versions_match:false` (078). CA2 mesmo `conn_id` para pacotes/TCP/TLS/HTTP e DNS do probe: ok, ao vivo.

## Spec 002 e ADR 0014
Um arquivo por papel em `.claude/agents/`: ok. Pastas sem dono, delegação de contrato, PRs sem revisão do reviewer:
087 item 10. verify-quick informado no PR: ok (exceções #15, #17, #32, todos chore). CHANGELOG por fragmentos: ok.
Reimplantação após merge: 078.

## Spec 003 (capture)
| Item | Status | Código | Teste |
| --- | --- | --- | --- |
| RF-01 AF_PACKET TPACKET_V3, dois sentidos | ok | internal/capture/capture_linux.go:34-43 | TestCaptureLive |
| RF-01 snaplen | **079** | config.go:30 | — |
| RF-02 BPF de exclusão (no socket de fato, `ss -0 -b`) | ok; IPv6 com extensão → 079 | bpf.go, frame.go | TestExcludeFilter, TestCaptureLive |
| RF-03 FSPB v1 | ok | pkg/event/fspb.go | TestFSPBRoundTrip, TestFSPBErrors |
| RF-04 lote 5 ms/256 | ok; sem teto em bytes → 079 | batch.go:36 | TestBatcher |
| RF-05 buffer e descarte | ok | pkg/service/producer.go | TestProducerDropsByAge/BySize |
| RF-06 offload → degraded | ok; flag por pacote → 079/081 | status.go:63-70 | TestHealth |
| RF-07 perdas do kernel | ok (0 na VPS) | capture_linux.go:82-87 | sem teste dedicado |
| CA-1/2/3 | ok (pcap no tshark; nenhuma porta excluída em 372 conexões e 657 avulsos; frames ≤ 1514) | — | TestF2ExitCriterion |
| CA-4 NATS parado | n.v. ao vivo; unitário ok | — | testes do producer |
| Métricas | nomes divergentes → 079/087 | capture_linux.go:109-111 | — |

## Spec 004 (store e API)
| Item | Status | Teste |
| --- | --- | --- |
| RF-01 stream/consumidor | ok (ao vivo `/jsz`) | TestEnsureStreamUpdatesSubjects, TestSubjectsMatchAsyncAPI |
| RF-02/02a correlação, QUIC por DCID, `fs.v1.store.conn_id` | ok (conn_id do corpo = API em h1/h2/h3) | correlate_test.go, connid_test.go, http3_test.go |
| RF-03 avulsos | ok | TestIngest*Stray* |
| RF-04 pcap 16 MiB | ok (9 pcaps no tshark) | TestIngestPcapTruncation, TestAPIPcap |
| RF-05 SQLite WAL/BLOB/goose | ok (schema na VPS = migration) | migrations_test.go |
| RF-06 retenção | **080** | TestRetention, TestRetentionSizeCap |
| RF-07 9000/9001, CORS, JSON | ok; 400 fora do contrato → 086 | TestHTTPSAPI, TestAPI |
| RF-08 SSE/WS, 64 clientes, 503, ping | ok ao vivo | live_test.go |
| RF-09 health / RF-10 /metrics / RF-11 degradado | ok | TestTracker, TestMetrics (GatherAndLint), TestIngestDegradedMode |
| RNF-01 GET p95 < 100 ms | ok (< 1 ms no servidor; 65 ms p95 do Mac com RTT ~23 ms) | — |
| RNF-01 registro ≤ 500 ms / CA1 | **077** | TestRecordCompleteWithin500ms mede só o Finalize |
| CA5 contrato | 538 registros, 498 DNS, 671 avulsos e o health validados contra o schema com 0 erros; erros → 086 | TestAPIExamples |
| CA6–CA10 | ok (CA6 só no código; CA8 dropped só unitário) | — |
Campos do openapi nunca preenchidos: `offload_suspect` (081); `ip.options_hex` (plausível); `rtt_app_ms` (074,
resolvido). UDP sem `times`, QUIC `times.first_data` nulo, DNS UDP sem probe: 087 item 13.

## Spec 005 (web)
RF-01 portas (ss na VPS), RF-02 detecção (TLS na 80/8080, claro na 443/8443, h2c, raw/unknown), RF-03 ALPN,
RF-05 rotas, RF-06 corpo/conn_id/inline, RF-07 todos os controles conferidos byte a byte ao vivo, RF-07a Date
(ADR 0021), RF-09 response_sent × fluxo out, RF-10 eventos, RF-11 ACME, CAs (idle 5/120 s): ok (respond_test.go
TestControl*, date_test.go, TestDetectionAnyPort, TestIdleDefault, TestStatic). **RF-04 posição do Alt-Svc → 085.**
RF-08 × close do WebSocket → 087 item 4.

## Spec 006 (raw)
RF-01 portas e banners, RF-02 modos, RF-03 TLS automático, RF-04 PROBE, RF-06 leituras e truncamento, RF-07 idle,
interfaces e todos os CAs: ok ao vivo (server_test.go, tls_test.go, e2e TestCase8RawPorts/RawTLS).
**RF-05 "o registro mostra se chegou" → 083.** Endereços (ADR 0001) → 083.

## Spec 007 (dns)
RF-01 UDP/TCP 53 nos IPs públicos, RF-02 SOA/NS/A/AAAA/HTTPS (h3 só com UDP 443, ADR 0019)/TXT ACME, RF-03 rótulos
noh3/v4/v6/nodata/nx, RF-04 REFUSED com RA=0 e RRL 20/s (TC=1 em UDP), RF-06 eventos (ECS, cookie, padding, NSID,
caixa 0x20), resolvedores públicos e os 5 CAs: ok ao vivo (zone_test.go, rrl_test.go, TestQueryEventMatchesOpenAPI,
e2e TestCase10*). Nenhuma divergência.

## Spec 008 (TLS e fingerprints)
RF-01 ClientHello cru (2 registros / 2 segmentos ao vivo), RF-02 parser e IANA, RF-03 JA3/JA3N/JA4/JA4_r/JA4_o/stable
(iguais ao tshark ao vivo, t e q), RF-04 alertas, RF-05, RF-06 config TLS no health, CA1–CA3: ok
(TestGoldenFoxIO, TestGoldenTshark, TestParseMatchesTshark, TestClientHelloSplitInTwoSegments). CA4 fuzz 60 s →
087 item 3. Unidade do handshake → 086 item 4.

## Spec 009 (HTTP/1)
RF-01..RF-10 ok ao vivo (campos sem normalizar, chunked com extensões, 100-continue, pipelining, sinais de proxy,
JA4H, Upgrade h2c, 431) — pkg/h1 *_test.go, internal/web TestPipelining3, TestProxySignals, TestHeadLimit. CA fuzz
60 s → 087 item 3.

## Spec 010 (HTTP/2)
RF-01..RF-07 ok ao vivo (SETTINGS em ordem, PRIORITY, HPACK, Akamai, JA4H, h2c prior knowledge e Upgrade, controles,
frames do servidor) — h2passive *_test.go, TestFingerproxyVectors, TestH2CPriorKnowledge/Upgrade. CA1 Firefox só
contra tshark (documentado). CA2 SETTINGS repetidos → 087 item 5. Akamai do Upgrade → 086 item 3.

## Spec 011 (HTTP/3 e QUIC) e ADR 0019
RF-01..RF-07 e CA1, CA3–CA6 ok ao vivo (JA4 q e transport params iguais ao tshark, Version Negotiation, Alt-Svc e
HTTPS RR, fecho ~2,1 s com `quic_close`, cobertura 96,9%) — TestGoldenInitials, TestH3Integration, e2e
TestCase12*. CA2 Chrome ao vivo n.v. (coberto por TestF4PageChrome). QUIC × RNF-04 → 087 item 2.

## Spec 012 (WebSocket)
RF-01..RF-05 ok ao vivo (eco, fragmentação, ping/pong, deflate, subprotocolo, RFC 8441 com `over: h2`) —
TestWSEchoHTTP1, TestWSOverH2, TestWSEchoTLSDeflate, FuzzWSParser. RF-06 close de cada lado → 086 item 5.

## Spec 013 (IP e TCP)
RF-01 linha do tempo, RF-03 totais, RF-04 TTL/saltos, RF-06 SYN, RF-07 JA4T/p0f (igual ao FoxIO e ao `p0f -r`),
RF-08 janela/keepalive/zero-window, RF-09 segmentação, RF-10 frequência, RF-11 RTT do handshake (20,974 ms × tshark
20,97376), RF-12 SYN cookie: ok (TestGoldenPcaps, TestAnalysis*, TestSynCookie). RF-02 → 075. RF-05 bloco `ip` e
IPv6 com extensão → 081. RF-10/CA-4 relógio entre IPs → 087 item 1. CA-1 Windows → 088.

## Spec 014 (htdocs)
RF-01..RF-07 ok (sem terceiros nem innerHTML, inglês, `.go`/`..`/ocultos dão 404 ao vivo) — TestSiteURLs,
TestNoUnsafeDOM, TestIndexNoThirdParty, TestStatic. CA feed < 1 s no navegador n.v. ao vivo (e2e F4).

## Spec 015 (ACME)
RF-01..RF-07 ok (certificados LE YR2 válidos até 07/02/2027 nos dois slots; `.key` 0600; 1 emissão de produção por
slot; SNI) — testes Pebble TestACMEPebble* (rodados com FS_TEST_PEBBLE), TestHotReload, TestSlotFor. CA `curl` sem
`-k` em `*.dns-monitor` e `vps602:9000`: ok. Recarga a quente ao vivo n.v.

## Spec 016 (infra) e ADRs 0004, 0011, 0012, 0015, 0016
Offloads (8 off), sysctls (arquivo idêntico, valores efetivos), sem nft/conntrack, NTP, units instaladas = repo,
hardening (`systemd-analyze security` 3.3–3.7, CAP_NET_RAW só no capture), MemoryMax/NOFILE, journald 24 h/200 MB,
NATS v2.15.2 com checksum, layout `/finger-sniffer`, trava `flock -w 300`: ok (deploy/*_test.go). RF-10 deploy →
078. CA-2 "conferido pelo health" → 082. `.env.example` → 084. CA-1 (VPS limpa) e CA-3 (idempotência) n.v.

## Spec 017 (verificação) e ADR 0013
RF-01..RF-12 ok (quick reproduzido: só pacotes afetados; banco-modelo `rebuilt`/`fresh`; full no CI em PR e main;
lint/formatter/lefthook). RF-13 carga → 068. RF-09 `-timeout` → 076 (resolvido). RF-04 build no quick e cobertura
sem `cmd/` → 087 item 11.

## Demais ADRs
0001 ok salvo endereços (082, 083, 087 item 8). 0002 ok salvo versões (078, 082). 0003/0016/0017/0018/0020 ok.
0005 ok. 0006/0007/0008 ok. 0009 ok salvo lista desatualizada (087 item 9). 0010 ok (FoxIO isolado em
pkg/fingerprint/ja4plus com LICENSE-FoxIO-1.1; p0f.fp externo com sha256). 0019 ok salvo versão do asyncapi (086)
e meta de 500 ms (087). 0021 ok. 0022 coerente; depende de 068 e 077. HISTORY.md lista 0001–0022 coerente.

## Transversais
Comentários em pt-BR e identificadores/chaves JSON/subjects em inglês: ok (grep sem achados). Dependências: só as
da ADR 0009 + libdns; `prometheus/client_model` direta só em teste (087 item 9). Propriedade de pastas: 087 item 10.

## Para o PR de release (072)
Antes da v0.1.0: 077, 078 e 086 resolvidas e a 068 medida depois da 077 e da 078. O comentário deste relatório no
PR de release fica para quando o PR existir.
