# traefix num container de teste no finger-01 (tasks 273 e 313)

Registro do teste do traefix à parte do `traefik-app`, em 2026-11-18, pela spec 019 (RF-03, RF-04, RF-09–RF-12 e
critérios de aceite), spec 016 RF-15 e ADRs 0062 e 0063. A troca do `traefik-app` é a task 306.

## Imagem

| Item | Valor |
| --- | --- |
| Imagem | `tmsoftbrasil/traefix:latest` (`docker pull` no início do teste) |
| Digest | `sha256:5597196b65f08699d07c438a2c4e8fe2283820421bd9a7544ec41d2b7fe32b58` |
| `traefik version` | `fork-point-218-g9f480d2e7`, go1.27.4, linux/amd64, build `2026-11-18_05:50:31` |
| `sender` dos lotes | `traefix/fork-point-218-g9f480d2e7` |
| Rótulos OCI | `version` = `fork-point-218-g9f480d2e7`, `revision` = `9f480d2e73b435dc96ee349f4e2fbe44356f5c28`, `licenses` = `MIT AND Apache-2.0 AND LicenseRef-FoxIO-1.1`, `base.name` = `alpine:3.24` |
| `NOTICE` | `/usr/share/licenses/traefix/NOTICE` (Coraza, CRS, JA3, JA4, JA4H/JA4T com a FoxIO License 1.1, p0f) |
| Referência upstream | `traefik:latest` já no host (v3.7.19, a do `traefik-app`); a base do traefix é `v3.8.0-rc.3`, sem imagem upstream igual no host |

A imagem foi apagada do host no fim do teste (a task 306 faz o próprio `pull`, ADR 0062 item 7).

## Configuração

Containers `fs-traefix-test` (traefix) e `fs-traefix-test-upstream` (`traefik:latest`, só para a paridade), ambos
`--network host` (o Docker do host tem `iptables: false` e `userland-proxy: false`, então porta publicada não
funcionaria sem mexer em rede; na rede do host o SYN e a origem são os do cliente, em IPv4 e IPv6). Arquivos em
`/finger-sniffer/var/traefix-test/` (fora do `rsync --delete` do deploy), certificado B do espelho
(`/finger-sniffer/var/certs/http01.*`) montado só leitura. Nada do `traefik-app` foi tocado.

| Entrada | Endereço | O que é |
| --- | --- | --- |
| `fstest` | TCP e UDP `:18443` | perfil da spec 019 RF-03: `tcp: true`, `rawBytes: true`, `http3: {}`, `http3HeaderOrder` desligado |
| `fsnoraw` | TCP `:18446` | igual, com `rawBytes: false` (medida de custo e lote real sem bytes crus) |
| `fsh3o` | TCP e UDP `:18447` | igual a `fstest` com `http3HeaderOrder: true` (medida de custo) |
| `fsplain` | TCP `:18444` | sem o bloco `fingerprint` (paridade e custo-base) |
| `fsmetrics` | `127.0.0.1:18082` | `/metrics` (Prometheus) e `/ping` |
| upstream `fsplain` | TCP `:18445` | `traefik:latest` com os mesmos routers de `fsplain` |

`export.url` apontou para um gravador próprio em `127.0.0.1:18090` que guardava cada lote e o repassava sem
mudança a `http://10.249.255.254:9003/bot/v1/ingest/traefik` (com os cabeçalhos), para gravar os lotes reais e
conferir a resposta do bot a cada um. Fora isso o perfil é o da spec 019.

Routers em `fstest` (backend: o web do espelho, `http://170.247.40.86:8080`, com `stripPrefix` e um
`serversTransport` com `maxIdleConnsPerHost: -1`, para cada requisição abrir uma conexão nova ao web e a página
`/p/<id>/` devolver o `conn_id` dela):

```yaml
http:
  middlewares:
    fs-bot-observe:            # sem chave: modo observe
      forwardAuth:
        address: http://10.249.255.254:9003/bot/v1/auth
        timeout: 200ms
        authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]
        authResponseHeaders: [X-Traefix-Verdict, X-Traefix-Score, X-Traefix-Signals]
        failOpen:
          denyRequiresResponseHeader: X-Traefix-Verdict
          header: { name: X-Traefix-Verdict, value: unavailable }
    fs-bot-block:              # igual, com requestHeaders.Authorization de uma chave --mode block
    fs-bot-revoked:            # igual, com a chave de uma chave revogada
  routers:
    fs-observe: { rule: PathPrefix(`/observe/`), middlewares: [fs-bot-observe, fs-strip], service: fs-web }
    fs-block:   { rule: PathPrefix(`/block/`),   middlewares: [fs-bot-block, fs-strip],   service: fs-web }
    fs-revoked: { rule: PathPrefix(`/revoked/`), middlewares: [fs-bot-revoked, fs-strip], service: fs-web }
    fs-ping:    { rule: Path(`/ping`), service: ping@internal }
```

As duas chaves (`fs-traefix-test-block` e `fs-traefix-test-revoked`, domínio `finger-01.badblock.net.br`) foram
criadas pela CLI do bot no servidor, gravadas só no arquivo do traefix (modo 600) e revogadas no fim.

## Resultados (passo 3)

Bot da `main` em produção (`v0.5.0-3-gd245b8f`, tasks 302 e 303), sem deploy novo. Clientes no Mac do gerador
(curl 8.23.0 com OpenSSL, Go net/http, Chrome 157 headless). `TestF8TraefixReal` (e2e) verde na última rodada.

| Critério | Resultado |
| --- | --- |
| Lotes aceitos | 287 lotes do teste com resposta `202` e `rejected: 0` (1 sem resposta: o caso do bot parado); depois de mais ~540 mil registros da medida de custo, `bot_ingest_records_total` 542 838 com `parse_errors` 0 e `bot_ingest_dropped_total` 0 |
| `bot_ingest_fingerprint_mismatch_total` | Δ 0 em todos os `kind` (`ja3`, `ja3n`, `ja4`, `ja4r`, `ja4o`, `akamai`, `ja4t`), inclusive `ja4o` |
| JA4 do bot × web do espelho, mesmo cliente | igual em curl h1/h2/h3 (IPv4 e IPv6), Go h1/h2 (IPv4 e IPv6) e Chrome h2/h3: `t13d3012h1_…`, `t13d3012h2_1d37bd780c83_581742d1f3c4`, `q13d0311h3_55b375c5d22e_df5ee7f3ca36` (curl), `t13d1312h2_f57a46bbacb6_a089bac06eae` (Go), `t13d1517h2_8daaf6152771_cb7bf5808d99` e `q13d0312h3_55b375c5d22e_178839b6cec1` (Chrome); `X-Traefix-Ja4` igual |
| Akamai do bot × web | igual em curl, Go e Chrome h2; `X-Traefix-H2` igual |
| JA4T, p0f e TTL do traefix × store | 241 de 241 conexões TCP casadas iguais nos três (`tcp.ja4t`, `tcp.p0f` = `raw_sig` do store, `tcp.ttl` = TTL do SYN no store); `X-Traefix-Ja4t` igual ao JA4T do store nas 7 conexões da conferência. SO do p0f: `Mac OS X` no store e no bot em IPv4; vazio nos dois em IPv6 (o `p0f.fp` não tem assinatura IPv6 do macOS) |
| RTT | `tcp.rttMicros` (kernel) × `rtt_handshake_ms` do store: diferença média absoluta de 4,2 ms em 241 conexões (medidas diferentes; sem regra que use) |
| Casamento traefix ↔ store | 100 de 100 conexões novas de Go h2 IPv4 (`subject.conn_id` preenchido); 7 de 7 na conferência; h3 também casa com a conexão QUIC do store |
| IPv6 | real na rede do host (origem do cliente, SYN do cliente); o caso do `docker-proxy` não se aplica. Origem privada: conexões vindas de `127.0.0.1` e `10.249.255.254` saem com `view.tcp: false` (visão TCP descartada) |
| `X-Traefix-*` forjados | `X-Traefix-Src-Ip`, `x-traefix-ja4h`, `X-TRAEFIX-JA4`, `X_Traefix_Conn_Id` e `X-Traefix-Verdict` do cliente não chegam ao backend nem ao bot (origem, JA4 e JA4H do bot são os reais) |
| `X-Fs-*` forjados | não mudam o veredito (mesma classe e sinais que o par com nomes neutros); chegam ao backend como vieram (o traefix só limpa o prefixo dele, ADR 0063 item 1) |
| Primeira requisição de curl | `X-Traefix-Verdict: bot` no backend em observe; `bot_auth_fingerprint_total{kind="tls",source="header"}` Δ 86 para 15 primeiras requisições contadas (mais as 100 da rodada de casamento) |
| `--mode block` | 403 com `X-Traefix-Verdict: bot` na primeira requisição |
| Chave revogada | 200 com `X-Traefix-Verdict: unavailable`; `traefik_forwardauth_failopen_total{reason="http_4xx"}` Δ 1 |
| Bot parado | 200 com `unavailable`; `traefik_forwardauth_failopen_total` Δ 1 e `traefik_fingerprint_export_dropped_total` Δ 2 (com o gravador no meio o motivo saiu `http_5xx`; sem ele seria `send_error`) |
| Sem o bloco `fingerprint` × `traefik:latest` | resposta ao cliente igual (status, cabeçalhos e corpo em `/ping` e num 404); o backend recebe `Forwarded` e `X-Real-Port` a mais (ver desvios) |
| Chave vazia (PT-09) | `Authorization: "Bearer "` e a chave num `http://` público recusados na carga, por router (o router fica fora, 404), com a mensagem do erro no log |

## Custo de CPU (passo 4, RF-11)

Carga externa do Mac do gerador (`tmp/txload`, gerador Go próprio, fora do Git: 64 workers com keep-alive, 30 s por
configuração, `GET /ping` em `ping@internal`, sem backend: limite superior), ~18 ms de RTT, 2 600–3 400 req/s. CPU
pelo `cpu.stat` do cgroup do container; ocioso 2–3 ms/s. Duas rodadas (µs de CPU por requisição):

| Configuração | h1 | h2 | h3 |
| --- | --- | --- | --- |
| `traefik:latest` upstream (v3.7.19) | 150 / 137 | 200 / 203 | — |
| traefix sem `fingerprint` | 154 / 153 | 237 / 244 | 259 / 259 |
| traefix, `rawBytes: false` | 185 / 180 | 257 / 258 | — |
| traefix, `rawBytes: true` (perfil) | 191 / 185 | 264 / 265 | 282 / 281 (`http3HeaderOrder: false`) |
| traefix, `http3HeaderOrder: true` | — | — | 297 / 300 |

- Custo do bloco `fingerprint` com export (perfil × traefix sem ele): **+21–24% em h1, +9–11% em h2, +9% em h3**.
- `rawBytes: false` economiza 3–4% em h1 e 1–3% em h2 com keep-alive (só a conexão leva os bytes crus), como o
  traefix mediu. Recomendação para a 306: manter `rawBytes: true` (ADR 0063 item 8).
- `http3HeaderOrder: true` custa +6–7% em h3 sobre o perfil (+15% sobre o traefix sem `fingerprint`) e é o que dá
  `fields`, `fieldNames` e JA4H ao registro h3 (ver desvios). Fica a decisão do architect para a 306; o tráfego h3
  dos sites é pequeno.
- O traefix sem `fingerprint` já gasta mais que o `traefik:latest` em h2 (+18–20%); a base é outra (`v3.8.0-rc.3`
  contra v3.7.19) e não há imagem upstream da mesma versão no host, então essa parte não se separa da do fork.
- Sobre o upstream do host, o perfil completo custa +27–35% em h1 e +30–32% em h2, abaixo dos +40%/+29% medidos pelo
  traefix no Xeon (mesma ordem de grandeza). Em ~3 000 req/s o container ficou em 0,5–0,9 núcleo.

## Lotes reais (passo 5)

`internal/bot/testdata/ingest/real/`: `h1-curl-v4`, `h2-curl-v4`, `h2-chrome-v6`, `h2-curl-v4-noraw` (`rawBytes:
false`), `h3-curl-v4`, `h3-curl-v4-headerorder` e `conn-only-chrome-v6` (conexão do Chrome sem requisição). Cada
arquivo é o lote do traefix com os registros de uma conexão; o IP do gerador foi trocado por `198.51.100.73` e
`2001:db8:4400::5db6` no `src.ip` e no `tcp.syn` (somas de verificação refeitas). `TestTraefixRealBatches` confere
`rejected` 0, sem `parse_error`, sem divergência e a visão de cada um; `TestTraefixRealBatchesContract` valida
contra o openapi do bot e contra a cópia do esquema do traefix (para a cópia, sem o `tcp.ja4t` de escala com 1
dígito, PT-11).

## Pedidos ao traefix (passo 6)

| Id | Estado conferido na `latest` (`fork-point-218-g9f480d2e7`) |
| --- | --- |
| PT-01 | entregue: regra de versão na documentação ("Schema Versioning"); campos novos (`tcp`, `ja3n`, …) com `v1` e ignorados quando desconhecidos |
| PT-02 | entregue: rótulos OCI e `NOTICE` acima |
| PT-03 | entregue: `sender` e `traefik version` = `fork-point-218-g9f480d2e7` |
| PT-04 | entregue do lado do traefix (testes `golden_capture_test.go` e `server_entrypoint_tcp_fingerprint_schema_test.go` no repositório); do lado de cá, fingerprints iguais às do espelho em todos os clientes |
| PT-05 | entregue: `tcp.ja4t`, `p0f`, `ttl`, `rttMicros`, `syn` e `X-Traefix-Ja4t` iguais ao store em 241 conexões, IPv4 e IPv6 na rede do host |
| PT-06 | entregue: `ja3n`, `ja3nString`, `ja4r`, `ja4o` e `headersPriority` presentes; com `rawBytes: false` o bot usa as prontas sem divergência |
| PT-07 | entregue: `X-Traefix-Alpn` (`h2,http/1.1`) |
| PT-08 | medido acima |
| PT-09 | entregue: chave vazia e chave em `http://` público recusadas na carga |
| PT-10 | pedido (não conferível na rede do host) |
| PT-11 | pedido: o lote real de macOS (`…_1430_6`) e de Linux (`…_7`) ainda não valida na cópia do esquema |

## Desvios e problemas encontrados (candidatos a pedidos)

1. **`Forwarded` e `X-Real-Port` sempre no backend**: o traefix acrescenta o `Forwarded` (RFC 7239) e o
   `X-Real-Port` a toda requisição encaminhada, com ou sem o bloco `fingerprint` (commit `193af416c` do traefix), e
   remove os do cliente. O traefik upstream não faz isso: na troca do `traefik-app` (task 306) os backends dos sites
   do humano passam a receber dois cabeçalhos novos e perdem um `Forwarded` vindo do cliente. Candidato a PT:
   opção para desligar, ou ao menos documentar como diferença do upstream.
2. **`dst.ip` em h3 é `::`**: o registro de conexão QUIC traz o endereço do socket em escuta (`::`), não o destino
   real (no TCP vem o IP certo). O bot só usa a porta; candidato a PT para o IP de destino real em h3.
3. **h3 sem `http3HeaderOrder` não tem `fields`**: além de `fieldNames` e JA4H (documentados), o registro de
   requisição h3 sai sem `fields` (sem o User-Agent no ingest). A documentação do traefix só cita `fieldNames`. O
   forwardAuth ainda recebe o UA por `authRequestHeaders`. Candidato a PT (mandar `fields` sem a ordem) ou a
   correção da documentação.
4. **PT-11 confirmado com lotes reais**: o padrão de `tcp.ja4t` da cópia do esquema recusa a escala de 1 dígito.
5. Avisos de carga do traefix com o perfil: `aliasHeadersStrategy`, `maxResponseBodySize` e `trustForwardHeader`
   do forwardAuth não configurados (avisos herdados do upstream v3.8); não mudaram o resultado. Para a 306, avaliar
   `trustForwardHeader: false` no middleware do bot.
6. Na paridade, `http3: {}` numa entrada acrescenta `Alt-Svc` às respostas (comportamento do upstream, não do
   fork).

## Limpeza

Containers `fs-traefix-test` e `fs-traefix-test-upstream` removidos, gravador parado, `/finger-sniffer/var/traefix-test/`
apagado, chaves revogadas, imagem `tmsoftbrasil/traefix:latest` apagada. `traefik-app` intacto (mesmo `StartedAt`
`2026-11-15T15:49:51Z`, 0 reinícios); health do espelho com os 6 serviços `ok` e `versions_match`.

## fork-point-223 (task 313)

Segunda conferência, em 2026-11-19, pela ADR 0065 (tempos, `relay_rtt_gap`, TTL em h3) e pelos critérios da spec 019,
com o bot da `main` em produção (`v0.5.1-2-gf7daf1c`, task 312, rules `v1.4`), sem deploy novo. Mesmo método da task
273 (rede do host, gravador de lotes, backend no web do espelho na 8080); clientes no Mac do gerador (curl 8.23.0 com
OpenSSL, Chrome 157 headless). Neste dia o Mac estava sem rota IPv6: os casos diretos são IPv4 (o relay sai em IPv6
pelo lado do servidor).

### Imagem e configuração

| Item | Valor |
| --- | --- |
| Imagem | `tmsoftbrasil/traefix:latest` (`docker pull` no início; não existia no host) |
| Digest | `sha256:5a1d2156d4e649333f756071c8a515bf42128217012e79eecc0c52c2fec992d9` |
| `traefik version` / `sender` | `fork-point-223-g59c901c7b` / `traefix/fork-point-223-g59c901c7b`, go1.27.4, build `2026-11-19_16:48:21` |
| Rótulo `revision` | `59c901c7bd0b64218d168738bff45e9c2a2abe6a` |

| Entrada | Endereço | O que é |
| --- | --- | --- |
| `fstest` | TCP e UDP `:18443` | perfil da spec 019 RF-03: `tcp: true`, `headerDetail: full`, `rawBytes: true`, `http3: {}`; routers `/observe/`, `/block/`, `/revoked/` como na task 273 |
| `fsbasic` | TCP `:18448` | igual, com `headerDetail: basic` (medida dos cabeçalhos) |
| `fsplain` | TCP `:18444` | sem `fingerprint` |
| `fsmetrics` | `127.0.0.1:18082` | `/metrics` e `/ping` |

Um container (`fs-traefix-test`), o gravador em `127.0.0.1:18090` e três chaves de teste pela CLI do bot
(`fs-traefix-test-313-block` `--mode block`, `-revoked` revogada na criação, `-query` para a consulta dos vereditos),
todas revogadas no fim. Sem o `traefik:latest` de paridade desta vez (a paridade é da task 273).

**Relay**: SOCKS5 por `ssh -D 127.0.0.1:18491` do Mac até o finger-01 e `curl --socks5-hostname` (Chrome com
`--proxy-server=socks5://…`). O `sshd` resolve `finger-01.badblock.net.br` e conecta no IP público do próprio host
(`2804:231c:e500:cafe::86`; com `--connect-to …:170.247.40.86:18443`, IPv4): a origem que o traefix vê é pública (o bot
aplica o sinal), o kernel mede a volta TCP com o próprio host e o TLS leva a volta até o Mac.

### Direto × relay (ADR 0065 item 3)

Dez conexões novas por linha (curl h2 e Chrome h2), tempos do veredito pela consulta (`/verdict/conn/<X-Traefix-Conn-Id>`,
registro do ingest) e iguais aos do `X-Traefix-Timing` que o backend recebeu; `src=kernel` em todas. Em ms, mediana
(mín.–máx.):

| Caminho | `tcp_rtt_us` | `tls_rtt_us` | `rtt_gap_us` | `est_to_first_us` | `relay_rtt_gap` |
| --- | --- | --- | --- | --- | --- |
| curl direto IPv4 | 10,4 (6,3–37,9) | 13,1 (8,9–75,9) | 3,8 (−29,0–69,3) | 0,1 (0,1–23,6) | 1 de 10 |
| Chrome direto IPv4 | 8,9 (2,9–14,6) | 11,4 (7,5–31,7) | 4,6 (−3,2–21,0) | 0,4 (0,1–10,3) | 1 de 10 |
| curl relay IPv6 | 0,02 (0,016–0,028) | 20,0 (13,0–34,5) | 19,9 (13,0–34,4) | 13,8 (7,0–442,2) | 4 de 10 |
| curl relay IPv4 | 0,02 | 21,3 (14,8–61,2) | 21,3 (14,8–61,2) | 13,0 (5,9–227,5) | 3 de 10 |
| Chrome relay IPv6 | 0,02 | 14,6 (5,9–68,7) | 14,6 (5,8–68,7) | 17,5 (5,1–47,8) | 3 de 10 |
| e2e `relay` 1ª rodada, curl direto | 8,4 (3,5–12,7) | 11,7 (6,2–265,2) | 5,5 (−0,7–254,6) | 1,5 (0,2–4,9) | 0 de 10 |
| e2e `relay` 1ª rodada, curl relay IPv6 | 0,02 | 26,6 (10,4–253,6) | 26,5 (10,4–253,6) | 9,4 (5,4–223,5) | 2 de 10 |
| e2e `relay` 2ª rodada, curl direto | 9,0 (3,6–59,5) | 8,1 (6,3–72,4) | 0,8 (−52,4–63,3) | 1,6 (0,1–4,4) | 0 de 10 |
| e2e `relay` 2ª rodada, curl relay IPv6 | 0,02 | 11,9 (6,5–64,7) | 11,9 (6,5–64,7) | 12,2 (6,6–42,6) | 2 de 10 |

- O bot decidiu cada uma das 90 conexões pelos limiares da ADR 0065 (`rtt_gap` > 20 ms, > 30% do `tcp_rtt`,
  `est_to_first` > 10 ms), igual no veredito e no `X-Traefix-Signals` do forwardAuth (pelo cabeçalho).
- O marcador mais forte aqui é o `tcp_rtt_us` do relay (16–28 µs, o par TCP é o próprio host), mas ele é deste
  arranjo (relay no host do traefix), não de um relay em geral.
- A volta Mac ↔ finger-01 é curta (`tcp_rtt` direto com mediana de 8–10 ms): o caminho cliente ↔ relay que o sinal mede
  fica perto do limiar de 20 ms e o `est_to_first` do relay perto do de 10 ms (mediana 9–18 ms). Por isso o relay só sai
  com o sinal em 14 de 50 conexões (28%), e o "relay perto do cliente" da documentação do traefix aparece.
- Falsos positivos diretos (2 de 40): `tls_rtt` com picos de 50–250 ms no Mac (Wi-Fi) e, nas duas, `est_to_first`
  também alto (17,5 e 10,3 ms); nos outros picos diretos o `est_to_first` ficou abaixo de 5 ms e segurou o sinal.
- Grade sobre as 90 conexões (relay / direto com o sinal): `gap` > 20 e `est` > 10 ms (atual) 14/50 e 2/40; `gap` > 15
  e `est` > 10 ms 23/50 e 2/40; `gap` > 15 e `est` > 5 ms 35/50 e 2/40; `gap` > 10 e `est` > 5 ms 43/50 e 2/40. Proposta ao architect: `rtt_gap` > 15 ms (o
  limite inferior do traefix) e `est_to_first` > 5 ms, com os 30% e o peso 15; os falsos positivos diretos são os
  mesmos nas três e só a agregação por cliente (task 314) os tira. Amostra pequena, de um cliente só e com o relay no
  próprio host.
- Rodada sintética: os lotes reais do relay com a origem trocada por endereço de documentação saem com `relay_rtt_gap`
  e, com a origem em `127.0.0.1`, sem ele e com `view.tcp: false` (`TestTraefixRealTiming`).
- O relay troca a visão TCP: JA4T do SYN do próprio host (`65476_2-4-8-1-3_65476_12` em IPv6, `65495_…_65495_12` em
  IPv4), e o Chrome pelo relay perde o `known_client`. O SYN IPv4 do relay chega com TTL 128 (`ip_default_ttl=128` é
  sysctl do host, fora do espelho) e o SYN de loopback vem com a soma TCP parcial (a placa não calcula); nos lotes do
  `testdata` a soma foi refeita junto com a troca da origem.

### TTL em h3 (ADR 0065 item 4)

curl `--http3-only` e Chrome h3 (3 conexões cada, mais as do e2e): `udp` no registro de conexão (`ttl` 56, `dscp` 0,
`ecn` 0), `X-Traefix-Ttl: 56` e `X-Traefix-Transport` com `proto=udp,…,ttl=56,ttl_init=64,hops=8` no backend; o
veredito traz `ttl_initial` 64, sem `tcp_rtt_us` nem JA4T. `X-Traefix-Timing` em h3: `src=user,proto=udp`,
`quic_rtt_us` 6,7–13,7 ms, `initial_to_hs_us` 9,8–19,4 ms.

### Pedidos ao traefix

| Id | Estado conferido na `fork-point-223-g59c901c7b` |
| --- | --- |
| PT-10 | pedido: a documentação agora explica quando o SYN não é do cliente (PROXY protocol, balanceador, `docker-proxy`, SYN cookies), mas o registro não marca o caso |
| PT-11 | pedido: o padrão de `tcp.ja4t` do esquema ainda exige 2 dígitos na escala (`_6` do macOS recusado); o contorno de `TestTraefixRealBatchesContract` continua |
| PT-12 | pedido: `Forwarded` e `X-Real-Port` seguem no backend, com `full` e com `basic` |
| PT-13 | **entregue**: `dst.ip` dos registros h3 é o IP real (`170.247.40.86`), não mais `::` |
| PT-14 | pedido: o registro de requisição h3 sem `http3HeaderOrder` segue sem `fields`, `fieldNames` e `ja4h`; o veredito h3 pelo ingest sai com `ua_missing` |
| PT-16, PT-17 | pedidos (não conferíveis; com `basic` não há `timing` nem `X-Traefix-Timing`, como a ADR 0065 previa) |

### Cabeçalhos `X-Traefix-*` no backend (registro para a task 306)

Bytes de nome + valor + 4 (`": "` e `"\r\n"`), sem os três do veredito (`-Verdict`, `-Score`, `-Signals`), pelo
registro da requisição traefix → web no store:

| Cliente | `full` | `basic` |
| --- | --- | --- |
| curl h1 | 26 cabeçalhos, 3 194–3 200 B | 16, 1 081–1 084 B |
| curl h2 | 28, 3 339–3 364 B | 17, 1 136–1 140 B |
| Chrome h2 | 28, 3 221–3 242 B | 17, 1 149–1 152 B |
| curl h3 | 22, 2 267–2 274 B | — |
| Chrome h3 | 22, 2 065–2 071 B | — |

Com `basic` o backend recebe `Alpn`, `Conn-Id`, `Dst-Port`, `H2`, `Ja3`, `Ja3n`, `Ja4`, `Ja4h`, `Ja4t`, `Proto`,
`Server-Ip`, `Server-Port`, `Src-Ip`, `Src-Port`, `Time`, `Transport` e `Ttl`; `full` acrescenta `H2-Detail`,
`Header-Order`, `Ja3-String`, `Ja3n-String`, `Ja4h-R`, `Ja4o`, `Ja4r`, `P0f`, `Timing`, `Tls` e `Tls-Hello` (o curl
pesa mais pelas 30 cifras em `Ja3-String`/`Ja4r`). O `X-Traefix-Transport` de `basic` já traz `rtt_syn_us` e `rtt_us`
do `TCP_INFO` (volta TCP), sem a volta TLS.

### Resultados gerais

| Critério | Resultado |
| --- | --- |
| Lotes aceitos | 461 lotes, todos `202` com `rejected: 0`; `traefik_fingerprint_export_dropped_total` 0 |
| `TestF8TraefixReal` | verde (`observe`, `forged-headers`, `fingerprints` IPv4, `match-rate` 100 de 100, `relay`, `h3-ttl`, `block-first-request`, `fail-open-revoked-key`, `metrics` com `bot_ingest_fingerprint_mismatch_total` Δ 0); IPv6 pulado sem rota no Mac; paridade e bot parado não rodados |
| JA4, Akamai, JA4T | iguais aos do espelho (curl h1/h2/h3, Go h1/h2, Chrome h2/h3) e ao store |
| Lotes reais novos | `h2-curl-v4-timing`, `h2-curl-relay-v6`, `h2-curl-relay-v4`, `h2-chrome-relay-v6`, `h3-curl-v4-udp`, `h3-chrome-v4-udp` em `internal/bot/testdata/ingest/real/` (origens trocadas por `198.51.100.73`, `203.0.113.86` e `2001:db8:4400::86`; os registros de uma conexão de lotes seguidos juntados num arquivo), aceitos pelo `TestTraefixRealBatches` e pelo teste de contrato (openapi e cópia do esquema) |

### Achados novos

1. **Requisição sem router não tem fingerprint no registro**: o `/favicon.ico` do Chrome (sem router no teste) sai com
   um registro de requisição sem `fields`, `fieldNames` nem `ja4h` (status 404). Como o veredito por conexão segue a
   última requisição, a conexão do Chrome passa a `ua_missing` depois do favicon (visto em h2 e h3). Do lado do bot é
   candidato a não trocar a visão HTTP da conexão por uma requisição sem campos; do lado do traefix, a documentação só
   diz isso do access log.
2. **Relay perto do cliente**: com 8–10 ms de volta, o sinal pega 28% das conexões do relay (ver a proposta de
   limiares acima).
3. **Picos de `tls_rtt_us` no cliente direto** (até 265 ms com `est_to_first` < 5 ms): o `est_to_first` é o que segura
   o falso positivo; não baixar o limiar dele abaixo de ~5 ms sem a agregação.
4. **SYN de loopback com soma TCP parcial** no `tcp.syn` (relay no próprio host): o bot não confere a soma, sem efeito.
5. O `X-Traefix-Transport` de `basic` traz a volta TCP do `TCP_INFO`; com o PT-17 a volta TLS completaria o sinal sem
   os cabeçalhos de detalhe.
6. Os avisos de carga da task 273 (`aliasHeadersStrategy`, `maxResponseBodySize`, `trustForwardHeader`) continuam.

### Limpeza

Container `fs-traefix-test` removido, gravador parado, `/finger-sniffer/var/traefix-test/` apagado, as três chaves
revogadas, imagem `tmsoftbrasil/traefix:latest` apagada (não existia antes), túnel `ssh -D` fechado, nenhuma porta
18xxx em escuta. `traefik-app` intacto (`StartedAt` `2026-11-15T15:49:51Z`, 0 reinícios); health do espelho com os 6
serviços `ok` e `versions_match`.

## Como rodar de novo o e2e

Com o container de teste no ar (configuração acima):

```sh
B=https://finger-01.badblock.net.br
FS_E2E_TRAEFIX_URL=$B:18443/observe FS_E2E_TRAEFIX_BLOCK_URL=$B:18443/block \
FS_E2E_TRAEFIX_REVOKED_URL=$B:18443/revoked FS_E2E_TRAEFIX_PLAIN_URL=$B:18444 \
FS_E2E_TRAEFIK_UPSTREAM_URL=$B:18445 FS_E2E_TRAEFIX_STOP_BOT=1 FS_E2E_TRAEFIX_SOCKS=127.0.0.1:18491 \
go test -tags e2e -count=1 -v -run TestF8TraefixReal ./test/e2e/
```

O caso `relay` (task 313) precisa do túnel aberto antes: `ssh -p 48022 -N -D 127.0.0.1:18491 root@finger-01.tmsoft.com.br`.
