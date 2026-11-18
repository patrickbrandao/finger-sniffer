# 019 — Integração com o traefix

Status: aprovada
Depende de: 001, 018, 020

## Contexto
O finger-sniffer é um espelho de análise de conexões; na fase F8 o serviço `finger-sniffer-bot` (spec 018) dá
vereditos de bot (humano, robô bom, robô, suspeito) a partir de como a conexão e as requisições chegaram: TLS
(ClientHello → JA3/JA4), HTTP/2 (SETTINGS, ordem de pseudo-headers → Akamai), cabeçalhos (JA4H), TCP (JA4T, p0f) e
comportamento. Os sites atrás de um traefik terminam o TLS no traefik: o espelho vê os pacotes, mas não o ClientHello
nem o HTTP. O **traefix** é o traefik modificado, projeto externo mantido pelo humano (`patrickbrandao/traefix`,
imagem `tmsoftbrasil/traefix`, ADR 0054), que exporta esses dados e marca as requisições encaminhadas.

O traefix é **consumido como está** (ADR 0062): os recursos e os formatos são do projeto traefix, documentados nele
(`docs/content/reference/install-configuration/entrypoints-fingerprint.md` e
`docs/content/reference/routing-configuration/http/middlewares/forwardauth-failopen.md`). Esta spec diz como o
finger-sniffer usa a entrega: o perfil de configuração, o que o bot lê de cada parte, as divergências aceitas e os
critérios de aceite. Versão de referência: `fork-point-213-g5c011b2f3` (`master` em `5c011b2f3`, sobre
`v3.8.0-rc.3`), entregue em 2026-11-18.

Termos: **entrada coberta** = entrada (`entryPoint`) com o bloco `fingerprint`; **bot** = o servidor de
`export.url` e do forwardAuth.

## Requisitos
- RF-01: **base e compatibilidade**: traefik v3, mesmo binário `traefik`, mesmas opções e portas; sem o bloco
  `fingerprint` e sem `failOpen` no `forwardAuth`, comportamento do upstream. A entrega atual sai do `master` sobre
  `v3.8.0-rc.3` (sem tag estável): aceita para o container de teste; para o `traefik-app` dos sites do humano,
  pendência P9 (ADR 0062 item 8).
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
        headerPrefix: X-Fs-        # obrigatório: nomes X-Fs-* da spec 020 (o padrão do traefix é X-Traefix-)
        export:
          url: http://10.249.255.254:9003/bot/v1/ingest/traefik   # site externo: https://finger-01.badblock.net.br:9002/...
          headers:
            Authorization: "Bearer fsk_..."  # opcional na 9003 (sem ela o modo é observe), obrigatória na 9002
          rawBytes: true           # ClientHello e prefixo h2 crus: o bot calcula como o web do espelho
          # padrões do traefix, iguais aos usados pelo bot:
          # fields: [User-Agent, Accept, Accept-Language, Accept-Encoding, "Sec-CH-UA*", "Sec-Fetch-*"]
          # queueSize: 4096, queueMaxBytes: 16777216, batchSize: 64, flushInterval: 100ms, sendTimeout: 2s
        # http3HeaderOrder: false  # desligado até a medida de custo da task 273 (ADR 0062 item 5)
  ```
  `allowSensitiveFields` nunca é ligado. No finger-01, `10.249.255.254` é o IP do host na bridge `br-net-public` do
  traefik (`FS_BOT_INTERNAL_LISTEN=10.249.255.254/16`, origens aceitas `10.249.0.0/16`, task 269).
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
            Authorization: "Bearer fsk_..."  # chave da auth (modo block exige chave --mode block)
          authResponseHeaders: [X-Fs-Verdict, X-Fs-Score, X-Fs-Signals]
          failOpen:
            denyRequiresResponseHeader: X-Fs-Verdict
            header: { name: X-Fs-Verdict, value: unavailable }
  ```
  Comportamento esperado (o mesmo da ADR 0058): rede, prazo vencido e 5xx seguem ao backend com
  `X-Fs-Verdict: unavailable`; 4xx sem `X-Fs-Verdict` (401 `invalid_key`, 403 `forbidden_origin`, 400, 429) segue com
  `unavailable`; só o 403 do modo `block`, que traz `X-Fs-Verdict`, volta ao cliente; `Cookie` e `Authorization` do
  visitante não vão à auth (fora de `authRequestHeaders`); os `X-Fs-*` do fingerprint vão à auth sempre; os
  `X-Fs-Verdict`/`X-Fs-Score` forjados pelo cliente não chegam ao backend; `requestHeaders` num `http://` público
  falha na carga (use IP privado ou https). A recusa de chave vazia em host público não existe no traefix e é
  aceita: o bot responde 401 e o fail-open de 4xx segue (ADR 0062 item 8).
- RF-05: **cabeçalhos ao backend e à auth** (com `headerPrefix: X-Fs-`): `X-Fs-Src-Ip`, `X-Fs-Src-Port`,
  `X-Fs-Dst-Port`, `X-Fs-Conn-Id`, `X-Fs-Proto` (`h1`|`h2`|`h3`), `X-Fs-Ja4h` (JA4H FoxIO com a ordem e a caixa
  recebidas), `X-Fs-Ja3` (MD5 do JA3), `X-Fs-Ja4` (`t…` em TCP, `q…` em QUIC) e `X-Fs-H2` (Akamai, só em h2). Todo
  cabeçalho do cliente com o prefixo, em qualquer caixa e também com `_` no lugar de `-`, é removido antes de
  qualquer middleware. Em h3 sem `http3HeaderOrder`, sem `X-Fs-Ja4h`.
- RF-06: **lote do ingest**: `POST` de `traefix.fingerprint/v1` (`schema`, `sender` = `traefix/<versão>`,
  `entryPoint`, `sentAt`, `records`), JSON, uma tentativa por lote, assíncrono (nunca atrasa nem falha uma
  requisição). Registros:
  - `type: connection`, enviado na primeira requisição da conexão ou no fechamento sem requisição (inclusive
    handshake interrompido): `connId`, `time`, `entryPoint`, `src`, `dst`, `proto`, `tls` (`sni`, `alpnOffered`,
    `alpn`, `version`, `cipher` em nomes IANA, `clientHello` com `rawBytes` — com registros TLS em TCP, mensagem de
    handshake pura em QUIC —, `clientHelloTruncated`, `ja3`, `ja3String`, `ja4`, `quicTransportParameters`),
    `http2` (`prefix` com `rawBytes`, `prefixTruncated`, `akamai`), `http3` (`settings`, com `http3HeaderOrder`);
  - `type: request`, no fim da resposta: `connId`, `start`, `end`, `proto`, `method`, `authority`, `path` (sem query,
    até 256 bytes), `httpVersion`, `fieldNames`, `fields` (lista `{name, value}` na ordem recebida, valor até
    512 bytes, só os de `fields`), `cookieNames`, `ja4h`, `status` (`0` com a conexão assumida), `router`,
    `service`, `headersTruncated`;
  - campos sem valor são omitidos; bytes em base64; nunca valores de `Cookie`, `Authorization`,
    `Proxy-Authorization`, `Set-Cookie`, query nem corpo.
- RF-07: **leitura do lote pelo bot** (ADR 0062 itens 2 e 3; spec 020 RF-04): esquema escolhido pelo campo `schema`
  (`traefix.fingerprint/v1`; ausente = `TraefikIngestBatch`, formato anterior mantido em `/bot/v1`; outro valor →
  400); fingerprints calculadas pelo bot a partir dos bytes crus quando vêm (ClientHello do QUIC como mensagem pura,
  JA4 `q`), as prontas do traefix (`tls.ja4`, `tls.ja3`, `http2.akamai`) só sem os bytes; divergência entre as duas
  conta em `bot_ingest_fingerprint_mismatch_total{kind}`; dos `fields`, o primeiro valor de cada nome permitido;
  `quicTransportParameters`, `http3.settings` e `headersTruncated` aceitos sem uso nas regras.
- RF-08: **leitura do forwardAuth pelo bot** (ADR 0058 item 1 e ADR 0062 item 4): JA4H de `X-Fs-Ja4h`; visão TLS e
  h2 do registro de conexão do ingest quando já chegou, senão de `X-Fs-Ja4`/`X-Fs-Ja3`/`X-Fs-H2`; a visão vinda do
  cabeçalho não tem ALPN oferecido e não avalia `ua_alpn_mismatch`; com eles presentes a espera de
  `FS_BOT_VIEW_WAIT` só aguarda o store.
- RF-09: **imagem e versão**: `tmsoftbrasil/traefix` (Docker Hub), tags `fork-point-<n>-g<sha>` e `latest`. O teste
  e a troca no finger-01 fixam o **digest** `@sha256:` da imagem testada, anotado com a tag de origem; nunca
  `latest`. Rótulos OCI `version`/`revision`/`licenses` e `NOTICE` são recomendação ao projeto traefix, sem
  bloqueio (ADR 0054 item 10).
- RF-10: **métricas do traefix** (qualquer backend de métricas do traefik), usadas nos critérios e nos docs:
  `traefik_fingerprint_export_records_total{entrypoint,type}`,
  `traefik_fingerprint_export_dropped_total{entrypoint,reason}` (`queue_full`, `send_error`, `http_4xx`,
  `http_5xx`, `too_large`), `traefik_fingerprint_export_batches_total{entrypoint,code}` (`error` sem resposta),
  `traefik_fingerprint_export_queue_records{entrypoint}`, `traefik_fingerprint_export_send_seconds{entrypoint}`,
  `traefik_fingerprint_capture_truncated_total{entrypoint,part}` (`client_hello`, `h2_prefix`, `headers`),
  `traefik_forwardauth_failopen_total{middleware,reason}` (`timeout`, `network`, `http_5xx`, `http_4xx`; no máximo
  uma linha de log por minuto por middleware).
- RF-11: **custo**: a meta de ≤ 5% de CPU a mais que o upstream não foi atingida no benchmark do traefix (+14% em
  TLS + h2 e +31% em TLS + h1 num Apple M2, cliente e servidor na mesma máquina). A task 273 mede no finger-01, com
  carga externa, a CPU do traefix com `rawBytes` ligado e desligado e com `http3HeaderOrder`; o resultado vai ao
  humano com a P9 antes da troca do `traefik-app`. Memória extra e fila dentro de `queueMaxBytes` como no traefix.
- RF-12: **contrato**: o traefix não testa contra o openapi do bot; o lado de cá valida `traefix.fingerprint/v1`
  com lotes de exemplo (`internal/bot/testdata`) e com lotes reais gravados do traefix pela task 273.
- RF-13: **h3**: entregue pelo traefix (`X-Fs-Proto: h3`, JA4 `q`, ClientHello do Initial, transport parameters,
  `SETTINGS` e JA4H com `http3HeaderOrder`); o bot usa JA4 `q` e JA4H; transport parameters e `SETTINGS` do h3 ficam
  para uma regra futura.

## Comportamento esperado do lado do finger-sniffer
- No finger-01, `export.url` e o forwardAuth usam a 9003 (HTTP, só loopback e a rede do traefik, chave opcional; o
  modo `block` exige a chave de uma chave `--mode block`); um site externo usa
  `https://finger-01.badblock.net.br:9002` com chave em `export.headers.Authorization` e em
  `requestHeaders.Authorization` (ADR 0054 item 7, caso b).
- Na primeira requisição de cada conexão, o registro de conexão ainda não chegou (sai com a requisição e espera o
  lote); o veredito do forwardAuth usa os `X-Fs-Ja4`/`X-Fs-H2`/`X-Fs-Ja4h` da própria requisição.
- O 403 do modo `block` traz sempre `X-Fs-Verdict`; nenhuma resposta de erro do bot traz `X-Fs-Verdict` (spec 020).
- No finger-01 o traefix entra primeiro num container de teste à parte e no router de teste; a troca do
  `traefik-app` é só observando (ingest e `X-Fs-*` ligados, sem forwardAuth nos sites do humano; ADR 0054 item 9) e
  espera a P9.

## Interfaces e contratos
- `POST /bot/v1/ingest/traefik` (`TraefixFingerprintBatch` e `TraefikIngestBatch`) e `GET /bot/v1/auth`
  (`cmd/finger-sniffer-bot/openapi.yaml` 0.3.0, spec 020). Mudança só aditiva em `/bot/v1` (ADR 0054 item 3); uma
  mudança de formato do lado do traefix é fato novo e vira ADR aqui.
- Cabeçalhos da RF-05 (traefix → backend e auth); `Authorization: Bearer <chave>` (traefix → bot, no export e no
  forwardAuth); `X-Fs-Verdict`, `X-Fs-Score`, `X-Fs-Signals` (bot → traefix → backend, por `authResponseHeaders`;
  `X-Fs-Verdict: unavailable` posto pelo traefix em fail-open).

## Critérios de aceite (do lado do finger-sniffer)
- [ ] Com o traefix (digest fixado) num container de teste no finger-01, `curl`, Go e Chrome por um router de teste
      geram no bot conexões com JA4/Akamai iguais aos que o web do espelho calcula para o mesmo cliente,
      `bot_ingest_fingerprint_mismatch_total` Δ 0 e casamento com o store (spec 018 RF-04) em ≥ 99% (e2e da F8,
      spec 017 RF-17).
- [ ] Lotes reais do traefix (TCP h1, h2 e QUIC h3) gravados em `testdata` e aceitos pelo teste de contrato do bot,
      com `rejected` 0 e `bot_ingest_parse_errors_total` Δ 0.
- [ ] Bot parado: o site de teste continua respondendo (fail-open) e `traefik_fingerprint_export_dropped_total` e
      `traefik_forwardauth_failopen_total` sobem.
- [ ] `X-Fs-Src-Ip`, `X-Fs-Ja4` e `X-Fs-Ja4h` forjados pelo cliente não chegam ao backend nem ao bot.
- [ ] Um `curl` puro na primeira requisição de uma conexão sai `bot` pelo forwardAuth com
      `bot_auth_fingerprint_total{kind="tls",source="header"}` subindo e, com chave `--mode block`, recebe 403; chave
      revogada não derruba o site (fail-open `http_4xx`).
- [ ] CPU do traefix medida no finger-01 (RF-11) e registrada no PR da task 273.
- [ ] Troca do `traefik-app` em modo só observação sem mudança de resposta nos sites do humano (task 306, depois da
      P9).

## Fora de escopo
- Código, CI, imagem, documentação e atualização do upstream do traefix: são do projeto traefix (ADR 0054).
- Matchers `JA3()`/`JA4()`/`JA4H()`, middleware `fingerprintList`, WAF Coraza, campos `Fingerprint*` no access log e
  atributos de trace do traefix: disponíveis para o humano nos sites, sem uso pelo bot.
- Ligar forwardAuth ou modo `block` nos sites do humano: ação do humano.

## Decisões relacionadas
- specs/decisions/0062-traefix-consumido-como-esta.md
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0058-forwardauth-do-bot-ja4h-chave-e-ja4t-sem-mss.md
- specs/decisions/0048-fork-do-traefik.md (substituída)
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0051-api-de-vereditos-e-chaves.md
- specs/decisions/0053-uso-nao-comercial-e-licencas.md
