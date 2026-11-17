# 019 — Requisitos do traefix para o finger-sniffer

Status: aprovada
Depende de: 001, 018, 020

## Contexto
O finger-sniffer é um espelho de análise de conexões; na fase F8 o serviço `finger-sniffer-bot` (spec 018) dá
vereditos de bot (humano, robô bom, robô, suspeito) a partir de como a conexão e as requisições chegaram: TLS
(ClientHello → JA3/JA4), HTTP/2 (SETTINGS, ordem de pseudo-headers → Akamai), cabeçalhos (JA4H), TCP (JA4T, p0f) e
comportamento. Os sites atrás de um traefik terminam o TLS no traefik: o espelho vê os pacotes, mas não o ClientHello
nem o HTTP. O **traefix** é o traefik modificado, projeto externo mantido pelo humano (imagem
`tmsoftbrasil/traefix`, ADR 0054), que copia esses dados para o bot e marca as requisições encaminhadas para o
backend consultar o veredito.

Esta spec é a lista autossuficiente do que o traefix precisa oferecer. O contrato de dados é o
[`cmd/finger-sniffer-bot/openapi.yaml`](../cmd/finger-sniffer-bot/openapi.yaml) (OpenAPI 3.1, `TraefikIngestBatch`,
`TraefikRecord`, `GET /bot/v1/auth`). O cálculo de JA3/JA4/Akamai fica no bot; o traefix só copia bytes, exceto o
JA4H (RF-04 e RF-06).

Termos: **entrada coberta** = entrada (`entryPoint`) listada em `experimental.fingerSniffer.entryPoints`; **bot** =
o servidor de `ingestURL` e do forwardAuth.

## Requisitos
- RF-01: **base e compatibilidade**: traefik v3 numa tag estável do upstream, mesmo binário `traefik`, mesmas
  opções, mesmas portas. Sem `experimental.fingerSniffer` e sem `failOpen` no `forwardAuth`, o comportamento é
  idêntico ao do upstream (os testes do upstream dos pacotes tocados passam sem mudança). Tudo o que segue vale só
  nas entradas cobertas, e nunca muda os bytes que o traefik lê ou escreve.
- RF-02: **identificação da conexão**: cada conexão aceita numa entrada coberta recebe `fs_conn_id` (ULID, 26
  caracteres Crockford base32) e `ts` do accept (RFC 3339 UTC com nanossegundos); `src` e `dst` (`ip`, `port`) são o
  `RemoteAddr`/`LocalAddr` do socket (com o DNAT do Docker sem userland-proxy, a origem é a do cliente; com PROXY
  protocol na entrada, a origem informada por ele); `entry_point` = nome da entrada. IPv4 em forma pontuada (não
  mapeado em IPv6).
- RF-03: **captura por conexão** (um registro `type=connection` por conexão, enviado quando o handshake TLS termina
  e, no h2, quando o primeiro `HEADERS` termina, ou no fechamento, o que vier primeiro):
  - TLS: `client_hello` = bytes crus do cliente desde o primeiro registro de handshake até o fim da mensagem
    ClientHello, inclusive cabeçalhos de registro TLS e ClientHello fragmentado em vários registros ou leituras (até
    16 KiB; acima, envia o prefixo e `client_hello_truncated=true`); `sni`, `alpn_offered` (na ordem do cliente),
    `alpn` negociado, `tls_version` e `cipher` negociados (nomes IANA, ex.: `TLS 1.3`, `TLS_AES_128_GCM_SHA256`);
  - h2: `h2_prefix` = bytes do cliente depois do prefácio (`PRI * HTTP/2.0...`) até o fim do primeiro frame `HEADERS`
    (com os `CONTINUATION`), inclusive `SETTINGS`, `WINDOW_UPDATE` e `PRIORITY` anteriores, decifrados (até 16 KiB;
    acima, prefixo e `h2_prefix_truncated=true`); h2c (sem TLS) também;
  - a cópia é feita sobre os bytes já lidos pelo traefik (envoltório do `net.Conn`), para de copiar ao atingir o
    limite ou o fim do que interessa e libera o buffer logo depois.
- RF-04: **resumo por requisição** (um registro `type=request` por requisição, quando a resposta termina):
  `fs_conn_id` da conexão, `ts` de início, `ended` de fim, `proto` (`h1`|`h2`|`h3`), `method`, `authority`, `path`
  sem query (até 256 bytes), `http_version`, `field_names` (nomes dos campos na ordem recebida, como vieram, sem
  pseudo-headers), `fields` com valores **só** de `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`,
  `Sec-CH-UA*` e `Sec-Fetch-*` (até 512 bytes cada), `cookie_names` na ordem, `ja4h` completo (FoxIO, calculado no
  traefix com os valores dos cookies, que nunca saem dele), `status`, `router` e `service` do traefik. Nunca enviar
  valores de `Cookie`, `Authorization`, query nem corpo.
- RF-05: **envio ao bot**: `POST` de `TraefikIngestBatch` (JSON, `Content-Type: application/json`) em `ingestURL`,
  com `Authorization: Bearer <apiKey>` quando `apiKey` estiver definida e `sender` = versão do traefix (RF-09);
  lote a cada 100 ms ou 64 registros, o que vier primeiro (no máximo 1024 registros e 4 MiB por lote); o registro de
  conexão vai antes dos de requisição dela sempre que possível. Fila limitada por `queueSize` (4096 registros) e por
  `queueMaxBytes` (16 MiB); fila cheia descarta o registro novo; prazo de 2 s por envio, uma tentativa só (erro de
  rede, 4xx ou 5xx descartam o lote e contam). O envio é assíncrono: **nunca** atrasa nem falha uma requisição.
- RF-06: **cabeçalhos ao backend** nas entradas cobertas: `X-Fs-Src-Ip`, `X-Fs-Src-Port`, `X-Fs-Dst-Port`,
  `X-Fs-Conn-Id`, `X-Fs-Proto` (valores da RF-02/RF-04) e `X-Fs-Ja4h` (o JA4H completo da requisição, o mesmo
  `ja4h` da RF-04, calculado antes dos middlewares com a ordem dos campos recebida; ADR 0058). Todo campo `X-Fs-*` vindo do cliente (qualquer caixa) é
  removido antes dos middlewares, inclusive antes do forwardAuth, para o cliente não forjar origem nem veredito.
- RF-07: **forwardAuth com fail-open**: opções novas `failOpen` (bool, padrão `false` = upstream) e `timeout`
  (duração, padrão 200 ms com `failOpen`) no middleware `forwardAuth`. Os `X-Fs-*` da RF-06 (inclusive `X-Fs-Ja4h`)
  vão também na requisição de auth. Com `failOpen`, erro de rede, prazo vencido ou 5xx do servidor de auth deixam a
  requisição seguir ao backend com `X-Fs-Verdict: unavailable`; 2xx e 4xx seguem a regra do upstream (2xx libera e
  copia `authResponseHeaders`; 4xx volta ao cliente), salvo no forwardAuth do bot (RF-07a).
- RF-07a: **forwardAuth do bot** (ADR 0058): opção nova `fingerSniffer` (bool, padrão `false`) no `forwardAuth`.
  Só com `fingerSniffer: true`:
  - `apiKey` (string, por middleware; vazia = sem chave): a requisição de auth leva `Authorization: Bearer <apiKey>`;
    `experimental.fingerSniffer.apiKey` é só do ingest e nunca é herdada;
  - o `Cookie` e o `Authorization` do visitante nunca vão na requisição de auth (só ao backend, como no upstream);
  - com `failOpen`, 4xx **sem** `X-Fs-Verdict` na resposta (401 `invalid_key`, 403 `forbidden_origin`, 400, 429) é
    erro de configuração ou limite do operador: segue ao backend com `X-Fs-Verdict: unavailable`, conta em
    `fingersniffer_forwardauth_failopen_total{reason="http_4xx"}` e loga no máximo uma linha por minuto com o código
    e o campo `error` do corpo JSON; só 4xx **com** `X-Fs-Verdict` (o 403 do modo `block`) volta ao cliente;
  - a carga falha com mensagem clara se `apiKey` estiver definida num `address` `http://` cujo host não seja
    loopback nem IP privado (chave em claro), ou vazia num `address` cujo host não seja loopback nem IP privado
    (servidor público sem chave).
  Sem `fingerSniffer`, `failOpen` vale só para rede, prazo e 5xx (seguro para outro servidor de auth).
- RF-08: **configuração**, desligada por padrão, nas três formas do traefik (arquivo, flags `--experimental.
  fingersniffer.*`, env `TRAEFIK_EXPERIMENTAL_FINGERSNIFFER_*`):
  ```yaml
  experimental:
    fingerSniffer:
      ingestURL: http://10.249.255.254:9003/bot/v1/ingest/traefik   # obrigatório para ligar
      apiKey: ""               # obrigatório fora do finger-01 (9002)
      entryPoints: [websecure] # entradas cobertas
      queueSize: 4096
      queueMaxBytes: 16777216  # 16 MiB
      batchSize: 64
      flushInterval: 100ms
      sendTimeout: 2s
  ```
  Dinâmica (middleware): `forwardAuth: { address: http://10.249.255.254:9003/bot/v1/auth, fingerSniffer: true,
  apiKey: "fsk_...", failOpen: true, timeout: 200ms, authResponseHeaders: [X-Fs-Verdict, X-Fs-Score,
  X-Fs-Signals] }` (na 9003 a `apiKey` é opcional, mas sem ela o modo é sempre `observe`; na 9002 é obrigatória). Configuração inválida (URL sem esquema,
  entrada inexistente) falha na carga com mensagem clara, como as opções do upstream. No finger-01,
  `10.249.255.254` é o IP do host na bridge `br-net-public` do traefik (`FS_BOT_INTERNAL_LISTEN=10.249.255.254/16`,
  origens aceitas `10.249.0.0/16`, task 269).
- RF-09: **imagem e versão**: `tmsoftbrasil/traefix` no Docker Hub, `linux/amd64` (outras arquiteturas opcionais),
  binário estático, rótulos OCI `source`, `version`, `revision` e `licenses=MIT`; tags imutáveis por versão
  `<tag-upstream>-traefix.<n>` (ex.: `v3.6.2-traefix.1`, nunca reescritas) além de `latest`; `traefik version` e o
  `sender` do lote mostram a mesma versão. MIT e `NOTICE` com as mudanças, como o upstream.
- RF-10: **métricas e logs** (no provedor de métricas do traefik, ex.: Prometheus):
  `fingersniffer_ingest_records_total{type}`, `fingersniffer_ingest_dropped_total{reason}` (`queue_full`,
  `send_error`, `http_4xx`, `http_5xx`, `too_large`), `fingersniffer_ingest_batches_total{code}`,
  `fingersniffer_ingest_queue_records`, `fingersniffer_ingest_send_seconds` (histograma),
  `fingersniffer_capture_truncated_total{part}` (`client_hello`, `h2_prefix`),
  `fingersniffer_forwardauth_failopen_total{reason}` (`timeout`, `network`, `http_5xx`, `http_4xx`). Descarte gera no máximo uma
  linha de log por minuto, com a contagem.
- RF-11: **custo**: com tudo ligado, ≤ 5% de CPU a mais que o upstream no mesmo teste de TLS + h2 (benchmark do
  traefix); memória extra por conexão ≤ 32 KiB enquanto captura e ~0 depois; fila dentro de `queueMaxBytes`;
  forwardAuth com `failOpen` não acrescenta mais que o `timeout` no pior caso.
- RF-12: **testes de aceite no traefix** (no CI do projeto traefix):
  - unidade: ClientHello fragmentado em vários registros e em leituras de 1 byte, ClientHello > 16 KiB (truncado),
    h2 com `CONTINUATION`, h2c, limites, conexão fechada antes do fim do handshake;
  - envio: lote por tempo e por tamanho, fila cheia (descarta e conta), bot fora do ar e lento (prazo), 413/429/5xx do
    bot, requisição nunca atrasada (latência igual com o bot fora);
  - remoção de `X-Fs-*` do cliente (inclusive caixa misturada) e presença dos `X-Fs-*` no backend e na auth;
    `X-Fs-Ja4h` igual ao `ja4h` do registro `type=request` da mesma requisição;
  - fail-open: timeout, erro de rede e 5xx seguem com `X-Fs-Verdict: unavailable`; 4xx volta ao cliente; sem
    `failOpen`, comportamento do upstream; com `fingerSniffer`: `Authorization: Bearer <apiKey>` na auth, sem
    `Cookie` nem `Authorization` do visitante, 401/403/429 sem `X-Fs-Verdict` seguem com `unavailable` e contam
    `http_4xx`, 403 com `X-Fs-Verdict` volta ao cliente, `apiKey` em `http://` público ou vazia em host público
    falham na carga;
  - contrato: cada lote gerado valida contra `TraefikIngestBatch` do openapi do bot (cópia do arquivo no teste);
    `ja4h` igual ao da implementação de referência da FoxIO para os mesmos cabeçalhos;
  - sem configuração: testes do upstream dos pacotes tocados passam;
  - benchmark da RF-11.
- RF-13: **segunda onda** (não bloqueia a primeira entrega; campos novos entram no contrato antes, de forma aditiva):
  h3/QUIC — `client_hello` do Initial decifrado (CRYPTO frames do ClientHello do QUIC), transport parameters e os
  primeiros frames dos streams de controle (`SETTINGS` do h3), `X-Fs-Proto: h3`, e o `fs_conn_id` mantido na migração
  de caminho da conexão QUIC.

## Comportamento esperado do lado do finger-sniffer
- O bot casa o registro de conexão do traefix com a conexão vista pelo espelho pela origem (`src`), porta de destino
  pública e início a menos de 5 s (spec 018 RF-04); por isso `src` e `dst.port` têm de ser os do cliente e da entrada.
- No finger-01, `ingestURL` e o forwardAuth usam a 9003 (HTTP, só loopback e a rede do traefik, chave opcional; o
  modo `block` exige a `apiKey` de uma chave `--mode block`); um site externo usa
  `https://finger-01.badblock.net.br:9002` com chave em `apiKey` do ingest e do forwardAuth (ADR 0054 item 7, caso b).
- No forwardAuth, a primeira requisição de cada conexão tem JA4H só pelo `X-Fs-Ja4h`; sem ele, o bot usa o JA4H da
  última requisição da conexão no ingest (ADR 0058 item 1).
- O 403 do modo `block` traz sempre `X-Fs-Verdict`; nenhuma resposta de erro do bot traz `X-Fs-Verdict` (spec 020).
- No finger-01 o traefix entra primeiro só observando: ingest e `X-Fs-*` ligados, sem forwardAuth nos sites do
  humano (ADR 0054 item 9, task 273).

## Interfaces e contratos
- `POST /bot/v1/ingest/traefik` (`TraefikIngestBatch`/`TraefikRecord`) e `GET /bot/v1/auth`
  (`cmd/finger-sniffer-bot/openapi.yaml`, spec 020). Mudança só aditiva em `/bot/v1` (ADR 0054 item 3).
- Cabeçalhos `X-Fs-Src-Ip`, `X-Fs-Src-Port`, `X-Fs-Dst-Port`, `X-Fs-Conn-Id`, `X-Fs-Proto`, `X-Fs-Ja4h` (traefix → backend e auth); `Authorization: Bearer <apiKey>` (traefix
  → bot, só no forwardAuth do bot);
  `X-Fs-Verdict`, `X-Fs-Score`, `X-Fs-Signals` (bot → traefix → backend, por `authResponseHeaders`;
  `X-Fs-Verdict: unavailable` posto pelo traefix em fail-open).

## Critérios de aceite (do lado do finger-sniffer)
- [ ] Com o traefix num container de teste no finger-01, `curl`, Go e Chrome por um router de teste geram no bot
      conexões com JA4/Akamai iguais aos que o web do espelho calcula para o mesmo cliente, e casamento com o store
      (spec 018 RF-04) em ≥ 99% (e2e da F8, spec 017 RF-17).
- [ ] Bot parado: o site de teste continua respondendo (fail-open) e o traefix conta os descartes.
- [ ] `X-Fs-Src-Ip` e `X-Fs-Ja4h` forjados pelo cliente não chegam ao backend nem ao bot.
- [ ] Um `curl` puro na primeira requisição de uma conexão sai `bot` pelo forwardAuth (com `X-Fs-Ja4h`) e, com chave
      `--mode block`, recebe 403; chave revogada não derruba o site (fail-open `http_4xx`).
- [ ] Troca do `traefik-app` em modo só observação sem mudança de resposta nos sites do humano (task 273).

## Fora de escopo
- Plugins Yaegi; middleware de bloqueio próprio (o bloqueio é a resposta 403 do forwardAuth em modo `block`).
- Código, CI, imagem e atualização do upstream do traefix: são do projeto traefix (ADR 0054).
- Ligar forwardAuth ou modo `block` nos sites do humano: ação do humano.

## Decisões relacionadas
- specs/decisions/0054-traefix-projeto-externo.md
- specs/decisions/0058-forwardauth-do-bot-ja4h-chave-e-ja4t-sem-mss.md
- specs/decisions/0048-fork-do-traefik.md (substituída em parte pela 0054)
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0051-api-de-vereditos-e-chaves.md
- specs/decisions/0053-uso-nao-comercial-e-licencas.md
