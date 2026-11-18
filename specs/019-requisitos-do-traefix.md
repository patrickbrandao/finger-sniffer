# 019 — Integração com o traefix

Status: aprovada
Depende de: 001, 013, 018, 020

## Contexto
O finger-sniffer é um espelho de análise de conexões; na fase F8 o serviço `finger-sniffer-bot` (spec 018) dá
vereditos de bot (humano, robô bom, robô, suspeito) a partir de como a conexão e as requisições chegaram: TLS
(ClientHello → JA3/JA4), HTTP/2 (SETTINGS, ordem de pseudo-headers → Akamai), cabeçalhos (JA4H), TCP (JA4T, p0f) e
comportamento. Os sites atrás de um traefik terminam o TLS no traefik: o espelho vê os pacotes, mas não o ClientHello
nem o HTTP. O **traefix** é o traefik modificado, projeto externo mantido pelo humano (`patrickbrandao/traefix`,
imagem `tmsoftbrasil/traefix`, ADR 0054), que exporta esses dados e marca as requisições encaminhadas.

O traefix é **consumido como está** (ADRs 0062 e 0063): os recursos e os formatos são do projeto traefix,
documentados nele (`docs/content/reference/install-configuration/entrypoints-fingerprint.md`,
`traefix-fingerprint-v1.schema.json` e
`docs/content/reference/routing-configuration/http/middlewares/forwardauth-failopen.md`). Esta spec diz como o
finger-sniffer usa a entrega: o perfil de configuração, o que o bot lê de cada parte, as divergências aceitas, os
pedidos ao traefix e os critérios de aceite. Os dois projetos **andam juntos** (decisão do humano, ADR 0062 itens 7
e 8): roda-se sempre `tmsoftbrasil/traefix:latest`, e toda necessidade nova do finger-sniffer entra aqui como pedido
ao traefix, implementado pelo humano na `latest`. Entregas: `fork-point-213-g5c011b2f3` e
`fork-point-218-g9f480d2e7` (visão TCP, `X-Traefix-*`), ambas em 2026-11-18.

Termos: **entrada coberta** = entrada (`entryPoint`) com o bloco `fingerprint`; **bot** = o servidor de
`export.url` e do forwardAuth.

## Requisitos
- RF-01: **base e compatibilidade**: traefik v3, mesmo binário `traefik`, mesmas opções e portas; sem o bloco
  `fingerprint` e sem `failOpen` no `forwardAuth`, comportamento do upstream. A base é a que a `latest` tiver (hoje
  `master` sobre `v3.8.0-rc.3`, sem tag estável), aceita pelo humano também no `traefik-app` (ADR 0062 item 9).
- RF-02: **identificação da conexão**: `connId` (ULID de 26 caracteres) e `time` do accept (RFC 3339 UTC com
  nanossegundos) por conexão; `src`/`dst` (`ip`, `port`) do socket ou do PROXY protocol (com o DNAT do Docker sem
  userland-proxy, a origem é a do cliente); IPv4 em forma pontuada; o `connId` se mantém na migração de caminho do
  QUIC. O bot casa com o store por `src`, porta de destino pública e início a menos de 5 s (spec 018 RF-04).
- RF-03: **perfil de configuração estática** (por entrada coberta; flags `--entrypoints.<nome>.fingerprint.*` e env
  `TRAEFIK_ENTRYPOINTS_<NOME>_FINGERPRINT_*` equivalentes):
  ```yaml
  entryPoints:
    websecure:
      address: ":443"
      http3: {}
      fingerprint:
        tcp: true                  # visão TCP pelo SYN salvo (só Linux; ADR 0063 item 5)
        export:
          url: http://10.249.255.254:9003/bot/v1/ingest/traefik   # site externo: https://finger-01.badblock.net.br:9002/...
          headers:
            Authorization: "Bearer fsk_..."  # opcional na 9003 (sem ela o modo é observe), obrigatória na 9002
          rawBytes: true           # ClientHello, prefixo h2 e SYN crus: o bot calcula como o espelho e tira o SO do p0f
          # padrões do traefix, iguais aos usados pelo bot:
          # fields: [User-Agent, Accept, Accept-Language, Accept-Encoding, "Sec-CH-UA*", "Sec-Fetch-*"]
          # queueSize: 4096, queueMaxBytes: 16777216, batchSize: 64, flushInterval: 100ms, sendTimeout: 2s
        # http3HeaderOrder: false  # desligado até a medida de custo da task 273 (ADR 0062 item 5)
  ```
  Sem `headerPrefix`: vale o prefixo padrão `X-Traefix-` (ADR 0063 item 1). `allowSensitiveFields` nunca é ligado.
  `tcp` não funciona com `proxyProtocol` na entrada. No finger-01, `10.249.255.254` é o IP do host na bridge
  `br-net-public` do traefik (`FS_BOT_INTERNAL_LISTEN=10.249.255.254/16`, origens aceitas `10.249.0.0/16`, task 269).
- RF-04: **forwardAuth do bot** (middleware dinâmico):
  ```yaml
  http:
    middlewares:
      bot:
        forwardAuth:
          address: http://10.249.255.254:9003/bot/v1/auth
          timeout: 200ms                   # obrigatório: o padrão do traefix é 30 s
          authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]   # nunca vazio
          requestHeaders:
            Authorization: "Bearer fsk_..."  # chave da auth (modo block exige chave --mode block); vazia falha na carga
          authResponseHeaders: [X-Traefix-Verdict, X-Traefix-Score, X-Traefix-Signals]
          failOpen:
            denyRequiresResponseHeader: X-Traefix-Verdict
            header: { name: X-Traefix-Verdict, value: unavailable }
  ```
  Comportamento esperado (o da ADR 0058 com os nomes da ADR 0063): rede, prazo vencido e 5xx seguem ao backend com
  `X-Traefix-Verdict: unavailable`; 4xx sem `X-Traefix-Verdict` (401 `invalid_key`, 403 `forbidden_origin`, 400,
  429) segue com `unavailable`; só o 403 do modo `block`, que traz `X-Traefix-Verdict`, volta ao cliente; `Cookie`
  e `Authorization` do visitante não vão à auth (fora de `authRequestHeaders`); os `X-Traefix-*` do fingerprint vão à
  auth sempre; `X-Traefix-*` forjados pelo cliente nunca chegam ao backend; `requestHeaders` num `http://` público
  falha na carga (use IP privado ou https), e chave vazia ou só `Bearer ` também.
- RF-05: **cabeçalhos ao backend e à auth**: `X-Traefix-Src-Ip`, `X-Traefix-Src-Port`, `X-Traefix-Dst-Port`,
  `X-Traefix-Conn-Id`, `X-Traefix-Proto` (`h1`|`h2`|`h3`), `X-Traefix-Ja4h` (JA4H FoxIO com a ordem e a caixa
  recebidas), `X-Traefix-Ja3` (MD5 do JA3), `X-Traefix-Ja4` (`t…` em TCP, `q…` em QUIC), `X-Traefix-H2` (Akamai, só
  em h2), `X-Traefix-Alpn` (ALPN oferecido, na ordem do cliente, por vírgula, `%XX` fora do ASCII visível e para `,`
  e `%`; só com TLS) e `X-Traefix-Ja4t` (com `tcp`). Todo cabeçalho do cliente com o prefixo, em qualquer caixa e
  também com `_` no lugar de `-`, é removido antes de qualquer middleware. Em h3 sem `http3HeaderOrder`, sem
  `X-Traefix-Ja4h`; em h3, sem `X-Traefix-Ja4t`. Os backends leem só `X-Traefix-*` (um `X-Fs-*` pode ter vindo do
  cliente; ADR 0063 item 1).
- RF-06: **lote do ingest**: `POST` de `traefix.fingerprint/v1` (`schema`, `sender` = `traefix/fork-point-<n>-g<sha>`,
  `entryPoint`, `sentAt`, `records`), JSON, uma tentativa por lote, assíncrono (nunca atrasa nem falha uma
  requisição). Formato completo no esquema publicado pelo traefix, copiado em
  `cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json` e traduzido no openapi do bot (ADR 0063 item 3). Registros:
  - `type: connection`, enviado na primeira requisição da conexão ou no fechamento sem requisição (inclusive
    handshake interrompido): `connId`, `time`, `entryPoint`, `src`, `dst`, `proto`; `tls` (`sni`, `alpnOffered`,
    `alpn`, `version`, `cipher` em nomes IANA, `ja3`, `ja3String`, `ja3n`, `ja3nString`, `ja4`, `ja4r`, `ja4o`,
    `clientHello` com `rawBytes` — com registros TLS em TCP, mensagem de handshake pura em QUIC —,
    `clientHelloTruncated`, `quicTransportParameters`); `http2` (`akamai`, `headersPriority`, `prefix` com
    `rawBytes`, `prefixTruncated`); `http3` (`settings`, com `http3HeaderOrder`); `tcp` (com `tcp`: `ja4t`, `p0f`
    = `raw_sig` do p0f v3, `ttl` recebido, `rttMicros`, `syn` cru desde o cabeçalho IP com `rawBytes`);
  - `type: request`, no fim da resposta: `connId`, `start`, `end`, `proto`, `method`, `authority`, `path` (sem query,
    até 256 bytes), `httpVersion`, `fieldNames`, `fields` (lista `{name, value}` na ordem recebida, valor até
    512 bytes, só os de `fields`), `cookieNames`, `ja4h`, `status` (`0` com a conexão assumida), `router`,
    `service`, `headersTruncated`;
  - campos sem valor são omitidos; bytes em base64; nunca valores de `Cookie`, `Authorization`,
    `Proxy-Authorization`, `Set-Cookie`, query nem corpo;
  - versão do esquema (PT-01): campo, tipo de registro, cabeçalho ou valor novo mantém `v1`; remoção, renomeação,
    mudança de tipo, unidade ou sentido, ou campo que vira obrigatório vai a `traefix.fingerprint/v2`, avisado antes.
- RF-07: **leitura do lote pelo bot** (ADRs 0062 itens 2 e 3, 0063 itens 2, 4 e 5; spec 020 RF-05): esquema pelo
  campo `schema` (`traefix.fingerprint/v1`; ausente = `TraefikIngestBatch`, formato anterior mantido em `/bot/v1`;
  outro valor → 400); campos e tipos de registro desconhecidos ignorados (`bot_ingest_ignored_total{type}`);
  fingerprints calculadas pelo bot a partir dos bytes crus quando vêm (ClientHello do QUIC como mensagem pura, JA4
  `q`), as prontas do traefix (`ja3`, `ja3n`, `ja4`, `ja4r`, `ja4o`, `akamai`, `headersPriority`) só sem os bytes, e
  a divergência entre as duas em `bot_ingest_fingerprint_mismatch_total{kind}`; dos `fields`, o primeiro valor de
  cada nome permitido; visão TCP do `tcp.*` (JA4T, TTL inicial, MSS e derivados da spec 013 RF-06a, SO do p0f pelo
  `tcp.syn`), descartada com `src.ip` loopback, link-local ou privado; `quicTransportParameters`, `http3.settings`,
  `tcp.p0f`, `tcp.rttMicros` e `headersTruncated` sem uso nas regras.
- RF-08: **leitura do forwardAuth pelo bot** (ADRs 0058 item 1, 0062 item 4 e 0063 itens 1, 5–7): `X-Traefix-*`
  (os `X-Fs-*` antigos só sem `X-Traefix-Conn-Id`, nunca misturados); JA4H de `X-Traefix-Ja4h`; visão TLS e h2 do
  registro de conexão do ingest quando já chegou, senão de `X-Traefix-Ja4`/`-Ja3`/`-H2`, com o ALPN de
  `X-Traefix-Alpn` (sem ele, `ua_alpn_mismatch` não avalia); visão TCP do store quando casada, senão do registro do
  traefix, senão o JA4T de `X-Traefix-Ja4t`; na 9003, com `X-Traefix-Ja4` a espera de `FS_BOT_VIEW_WAIT` só aguarda
  o store; na 9002 não há espera pelo store. Respostas com `X-Traefix-Verdict`/`-Score`/`-Signals` e os `X-Fs-*`
  equivalentes (obsoletos).
- RF-09: **imagem e versão**: sempre `tmsoftbrasil/traefix:latest` (Docker Hub), no container de teste e no
  `traefik-app`, sem fixar tag nem digest (ADR 0062 item 7). Cada teste, e2e ou troca registra o digest e o `sender`
  vistos; a atualização da `latest` no finger-01 é do humano. Rótulos OCI (`revision`, `version`, `licenses` =
  `MIT AND Apache-2.0 AND LicenseRef-FoxIO-1.1`) e `NOTICE` em `/usr/share/licenses/traefix/` (PT-02).
- RF-10: **métricas do traefix** (qualquer backend de métricas do traefik), usadas nos critérios e nos docs:
  `traefik_fingerprint_export_records_total{entrypoint,type}`,
  `traefik_fingerprint_export_dropped_total{entrypoint,reason}` (`queue_full`, `send_error`, `http_4xx`,
  `http_5xx`, `too_large`), `traefik_fingerprint_export_batches_total{entrypoint,code}` (`error` sem resposta),
  `traefik_fingerprint_export_queue_records{entrypoint}`, `traefik_fingerprint_export_send_seconds{entrypoint}`,
  `traefik_fingerprint_capture_truncated_total{entrypoint,part}` (`client_hello`, `h2_prefix`, `headers`),
  `traefik_forwardauth_failopen_total{middleware,reason}` (`timeout`, `network`, `http_5xx`, `http_4xx`; no máximo
  uma linha de log por minuto por middleware).
- RF-11: **custo**: acima da meta antiga de 5%; no Linux (benchmark do traefix, sem backend, teto) +40% em h1 e +29%
  em h2 com export e `rawBytes`; `rawBytes: false` não reduz CPU com keep-alive. Aceito pelo humano (ADR 0062 item
  9). A task 273 mede no finger-01, com carga externa, como registro e para escolher `http3HeaderOrder`.
- RF-12: **contrato**: o traefix valida os lotes reais no esquema publicado (testes dele); o lado de cá valida contra a
  cópia do esquema e contra a tradução no openapi os lotes de exemplo (`internal/bot/testdata/ingest`) e os lotes reais gravados pela task 273.
  Os goldens do espelho (`test/golden/tls/pcaps`, `test/golden/pcaps`) também rodam no traefix (PT-04).
- RF-13: **h3**: `X-Traefix-Proto: h3`, JA4 `q`, ClientHello do Initial, transport parameters, `SETTINGS` e JA4H
  com `http3HeaderOrder`; o bot usa JA4 `q` e JA4H; transport parameters e `SETTINGS` do h3 ficam para uma regra
  futura. h3 não tem visão TCP.
- RF-14: **andar juntos** (ADR 0062 item 8): o bot aceita a ausência de qualquer recurso pedido até ele aparecer no
  dado e ignora campos desconhecidos; o e2e da F8 pelo router de teste registra o `sender`, e `rejected`,
  `bot_ingest_parse_errors_total` ou `bot_ingest_fingerprint_mismatch_total` subindo com um `sender` novo é regressão
  do traefix, reportada ao humano. Mudança do esquema publicado → o architect atualiza a cópia.

## Pedidos ao traefix
Necessidades do finger-sniffer implementadas pelo humano na `latest` (ADR 0062 item 8). O architect acrescenta e
avisa; o estado muda para `entregue` quando a `latest` traz o recurso e o lado de cá o confere (a task 273 confere os
entregues em 2026-11-18).

| Id | Pedido | Estado |
| --- | --- | --- |
| PT-01 | Mudança incompatível no lote ou nos cabeçalhos só com `schema` novo (`traefix.fingerprint/v2`, …), avisada antes | entregue (`fork-point-218`, regra na documentação) |
| PT-02 | Rótulos OCI `version`, `revision` e `licenses` e `NOTICE` com as mudanças (Coraza/CRS, JA4+, p0f) | entregue (`fork-point-218`) |
| PT-03 | `sender` e `traefik version` com `fork-point-<n>-g<sha>` | entregue (`fork-point-218`) |
| PT-04 | Testes cruzados: lotes validados no esquema publicado e goldens do espelho (JA3, JA4, JA4_r, Akamai, JA4H, JA4T, p0f) | entregue (`fork-point-218`; JA4_o sem golden) |
| PT-05 | Visão TCP: JA4T, `raw_sig` do p0f, TTL, RTT e SYN cru; `X-Traefix-Ja4t` | entregue (`fork-point-218`; IPv6 só em container) |
| PT-06 | JA3N, JA4_r, JA4_o e detalhe do h2 prontos, para `rawBytes: false` sem perda | entregue (`fork-point-218`) |
| PT-07 | ALPN oferecido no forwardAuth (`X-Traefix-Alpn`) | entregue (`fork-point-218`) |
| PT-08 | Custo de CPU medido no Linux e reduzido | entregue como medida e otimização parcial (+40% h1, +29% h2, teto; aceito) |
| PT-09 | Chave vazia em `requestHeaders` falha na carga | entregue (`fork-point-218`) |
| PT-10 | Marcar no registro de conexão quando o SYN salvo pode não ser do cliente (`docker-proxy`, proxy local) | pedido |

## Comportamento esperado do lado do finger-sniffer
- No finger-01, `export.url` e o forwardAuth usam a 9003 (HTTP, só loopback e a rede do traefik, chave opcional; o
  modo `block` exige a chave de uma chave `--mode block`); um site externo usa
  `https://finger-01.badblock.net.br:9002` com chave em `export.headers.Authorization` e em
  `requestHeaders.Authorization` (ADR 0054 item 7, caso b), e recebe a visão TCP do traefix (o espelho não vê os
  pacotes dele).
- Na primeira requisição de cada conexão, o registro de conexão ainda não chegou (sai com a requisição e espera o
  lote); o veredito do forwardAuth usa os `X-Traefix-Ja4`/`-H2`/`-Alpn`/`-Ja4t`/`-Ja4h` da própria requisição.
- O 403 do modo `block` traz sempre `X-Traefix-Verdict`; nenhuma resposta de erro do bot traz `X-Traefix-Verdict`
  nem `X-Fs-Verdict` (spec 020).
- No finger-01 o traefix entra primeiro num container de teste à parte e no router de teste; a troca do
  `traefik-app` é só observando (ingest e `X-Traefix-*` ligados, sem forwardAuth nos sites do humano; ADR 0054 item
  9), depois da task 273.

## Interfaces e contratos
- `POST /bot/v1/ingest/traefik` (`TraefixFingerprintBatch`, traduzido da cópia do esquema do traefix, e
  `TraefikIngestBatch`) e
  `GET /bot/v1/auth` (`cmd/finger-sniffer-bot/openapi.yaml` 0.4.0, spec 020). Mudança só aditiva em `/bot/v1`
  (ADR 0054 item 3); uma mudança de formato do lado do traefix segue o PT-01 e vira ADR aqui.
- Cabeçalhos da RF-05 (traefix → backend e auth); `Authorization: Bearer <chave>` (traefix → bot, no export e no
  forwardAuth); `X-Traefix-Verdict`, `X-Traefix-Score`, `X-Traefix-Signals` (bot → traefix → backend, por
  `authResponseHeaders`; `X-Traefix-Verdict: unavailable` posto pelo traefix em fail-open); `X-Fs-*` equivalentes
  nas respostas do bot, obsoletos.

## Critérios de aceite (do lado do finger-sniffer)
- [ ] Com o traefix (`latest`, digest e `sender` registrados) num container de teste no finger-01, `curl`, Go e
      Chrome por um router de teste geram no bot conexões com JA4/Akamai/JA4T iguais aos que o espelho calcula para
      o mesmo cliente, `bot_ingest_fingerprint_mismatch_total` Δ 0 (exceto `ja4o`, sem golden) e casamento com o
      store (spec 018 RF-04) em ≥ 99% (e2e da F8, spec 017 RF-17).
- [ ] Lotes reais do traefix (TCP h1, h2 e QUIC h3, com `tcp`) gravados em `testdata` e aceitos pelo teste de
      contrato do bot, com `rejected` 0 e `bot_ingest_parse_errors_total` Δ 0.
- [ ] Bot parado: o site de teste continua respondendo (fail-open) e `traefik_fingerprint_export_dropped_total` e
      `traefik_forwardauth_failopen_total` sobem.
- [ ] `X-Traefix-Src-Ip`, `X-Traefix-Ja4` e `X-Traefix-Ja4h` forjados pelo cliente não chegam ao backend nem ao bot;
      `X-Fs-*` forjados não mudam o veredito.
- [ ] Um `curl` puro na primeira requisição de uma conexão sai `bot` pelo forwardAuth com
      `bot_auth_fingerprint_total{kind="tls",source="header"}` subindo e, com chave `--mode block`, recebe 403 com
      `X-Traefix-Verdict`; chave revogada não derruba o site (fail-open `http_4xx`).
- [ ] Sem a visão do store (registro do traefix com `src` fora do finger-01, simulado), `ua_os_tcp_mismatch` e
      `known_client` avaliam pela visão TCP do traefix.
- [ ] CPU do traefix medida no finger-01 (RF-11) e registrada no PR da task 273.
- [ ] Troca do `traefik-app` em modo só observação sem mudança de resposta nos sites do humano (task 306, depois da
      273).

## Fora de escopo
- Código, CI, imagem, documentação e atualização do upstream do traefix: são do projeto traefix (ADR 0054).
- Matchers `JA3()`/`JA4()`/`JA4H()`/`JA4T()`, middleware `fingerprintList`, WAF Coraza, campos `Fingerprint*` no
  access log e atributos de trace do traefix: disponíveis para o humano nos sites, sem uso pelo bot.
- Ligar forwardAuth ou modo `block` nos sites do humano: ação do humano.

## Decisões relacionadas
- specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md
- specs/decisions/0062-traefix-consumido-como-esta.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0058-forwardauth-do-bot-ja4h-chave-e-ja4t-sem-mss.md
- specs/decisions/0048-fork-do-traefik.md (substituída)
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0051-api-de-vereditos-e-chaves.md
- specs/decisions/0053-uso-nao-comercial-e-licencas.md
