# API de vereditos de bot

Derivado das specs [018](../specs/018-bot.md) (serviço bot), [019](../specs/019-requisitos-do-traefix.md)
(traefix) e [020](../specs/020-api-de-vereditos.md) (API), das ADRs
[0047](../specs/decisions/0047-fase-de-bots-servico-bot.md)–[0057](../specs/decisions/0057-regras-v1-1-teto-do-indice-e-ajustes-da-segunda-onda.md)
e do contrato [cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) (OpenAPI 3.1, versão
0.1.1, também em `/bot/v1/openapi.yaml`). Em caso de divergência, valem as specs e o contrato.

O serviço `finger-sniffer-bot` junta a visão IP/TCP do espelho (o que o store viu da conexão: SYN, JA4T, p0f, TTL,
MSS) com a visão de aplicação do **traefix** (o traefik modificado, projeto externo, imagem `tmsoftbrasil/traefix`:
ClientHello cru, prefixo do h2, resumo de cada requisição), avalia sinais e devolve um **veredito explicável**: a
classe, o score e a lista dos sinais que pesaram.

> **Uso não comercial** ([ADR 0053](../specs/decisions/0053-uso-nao-comercial-e-licencas.md)). A API e as chaves são
> oferecidas sem cobrança e só para uso não comercial (campo `info.x-terms` do contrato). O JA4 é BSD-3-Clause; JA4H e
> JA4T seguem a FoxIO License 1.1: uso comercial por terceiros exige licença da FoxIO e é responsabilidade deles.

## Portas

| Porta | Uso | Chave |
| --- | --- | --- |
| `https://finger-01.badblock.net.br:9002` | pública, TLS com os certificados da 9000 (A e B por SNI) | obrigatória em toda rota, exceto `health` e `openapi.yaml` |
| `http://10.249.255.254:9003` | interna, HTTP, só para o traefik do finger-01 e os containers da bridge `br-net-public` (`10.249.0.0/16`) e loopback | opcional |

As duas ficam fora da captura. Na 9003 qualquer origem fora do loopback e de `FS_BOT_INTERNAL_ALLOW` recebe 403
`forbidden_origin`. Sem chave na 9003, o `site` vale para qualquer domínio e os limites são só os globais; um
`Authorization` que não seja `Bearer fsk_...` é ignorado ali, porque o forwardAuth repassa os cabeçalhos do
visitante (um `Basic` do próprio site não pode virar 401; [ADR 0055](../specs/decisions/0055-ajustes-da-primeira-onda-da-f8.md)
item 5). `Bearer fsk_...` inválida dá 401 nas duas portas.

## O veredito

Corpo `Verdict` (ADR [0049](../specs/decisions/0049-veredito-e-sinais-v1.md), regras `v1.1` da ADR 0057):

```json
{
  "class": "bot",
  "score": 70,
  "signals": [
    {"id": "ja4h_library", "kind": "incoherence", "weight": 20,
     "detail": "ja4h ge20nn020000_5594a17e7e7e of curl, no accept-language"},
    {"id": "library_client", "kind": "list", "weight": 50, "detail": "ua declares curl"}
  ],
  "view": {"tcp": true, "tls": true, "http": true, "h2": true, "h3": false, "behavior": false},
  "fingerprints": {"ja4": "t13d...", "akamai": "...", "ja4h": "ge20nn020000_5594a17e7e7e_000000000000_000000000000",
                   "ja4t": "65535_2-1-3-1-1-8-4-0-0_1430_6", "p0f_os": "Mac OS X", "ttl_initial": 64,
                   "ua_family": "curl", "ua_os": "other"},
  "crawler": null,
  "rules_version": "v1.1",
  "lists_version": "91cc382c89a43660",
  "subject": {"kind": "request", "site": "www.example.com", "src": {"ip": "198.51.100.23", "port": 40000},
              "dst_port": 443, "fs_conn_id": "01JC0X3K8V2T7Q9F4M6P1R5S10", "conn_id": "01JC0X3K8V2T7Q9N4M6P1R5S10",
              "method": "GET", "path": "/"},
  "ts": "2026-11-16T12:00:00.060000000Z"
}
```

### Classes e score

`score` = soma dos pesos dos sinais presentes, entre 0 e 100 (pesos negativos para cliente legítimo). Quanto maior,
mais indício de automação.

| Classe | Quando |
| --- | --- |
| `good_bot` | robô verificado: IP na lista do operador, UA do mesmo robô e DNS reverso/direto ok (Google, Bing, Apple); para OpenAI e DuckDuckGo, que não publicam sufixo de DNS reverso, a lista do operador basta. Prevalece sobre o score; `crawler` traz o nome |
| `bot` | score ≥ 70 |
| `suspect` | score 40–69 |
| `human` | score < 40 **e** a visão tem pelo menos `tls` e `http` |
| `unknown` | score < 40 e visão incompleta |

`view` diz o que havia para decidir: `tcp` (conexão vista pelo espelho e casada), `tls` (ClientHello), `http`
(requisição), `h2`, `h3`, `behavior` (agregados do IP no site) e `parse_error` (bytes do traefix ilegíveis). Um
`human` exige `tls` e `http`; sem eles, score baixo sai `unknown`.

`rules_version` é a versão das regras (`v1.1`) e `lists_version` um hash das listas em uso (base própria e listas
de IP; a ja4db só quando ligada). A mesma entrada com as mesmas duas versões dá sempre o mesmo veredito. Mudança de
peso ou de regra é nova `rules_version`.

### Sinais (rules v1.1)

Os ids são estáveis; os pesos são provisórios (revistos com o e2e e a carga da F8).

| Sinal | Tipo | Peso | O que quer dizer |
| --- | --- | --- | --- |
| `ua_missing` | incoherence | 30 | requisição HTTP sem `User-Agent` |
| `ua_tls_mismatch` | incoherence | 45 | UA de navegador e JA4 fora do conjunto daquela família (base própria e ja4db): o TLS não é o do navegador declarado |
| `ua_h2_mismatch` | incoherence | 30 | UA de navegador e Akamai (SETTINGS e ordem das pseudo-headers do h2) fora da família, ou HTTP/1.1 com ALPN sem `h2` |
| `ua_os_tcp_mismatch` | incoherence | 25 | SO do UA incompatível com o p0f ou o TTL inicial (ex.: Windows com TTL 64) |
| `ua_alpn_mismatch` | incoherence | 15 | ALPN oferecido incompatível com a família (ex.: navegador sem `h2`) |
| `ja4h_library` | incoherence | 20 | JA4H sem `Accept-Language` e com ordem de campos de biblioteca |
| `tunnel_mss` | incoherence | 5 | MSS reduzido ou `mtu_implied` < 1500: túnel ou VPN no caminho (só informativo) |
| `ua_claims_crawler` | incoherence | 60 | UA de robô conhecido vindo de IP fora da lista dele, ou com DNS reverso/direto falho |
| `ua_automation` | list | 70 | UA declara automação (`HeadlessChrome`, `PhantomJS`, `SlimerJS`, `Selenium`, `WebDriver`, `Puppeteer`, `Playwright`, `Cypress`, `HtmlUnit`, sem diferenciar maiúsculas) |
| `library_client` | list | 50 | UA de biblioteca (`curl`, `go`, `python`, `java`, `node`), ou UA vazio/desconhecido com JA4 que a base própria só viu em bibliotecas |
| `ja4db_match` | list | 40 | JA4 rotulado como biblioteca ou ferramenta na ja4db (só com `FS_BOT_JA4DB_ENABLE=true`; desligada por padrão) |
| `known_client` | list | −20 | JA4 + Akamai + JA4T coerentes com um cliente medido na base própria e com o UA |
| `ip_verified_crawler` | list | — | define `good_bot` (`detail` diz `verified by ip list` quando a lista bastou) |
| `ip_cloud` | list | 20 | IP em faixa de nuvem ou datacenter |
| `ip_crawler_list_unverified` | list | 0 | IP numa lista de robô sem chegar a `good_bot` (informativo) |
| `rate_high` | behavior | 25 | mais de `FS_BOT_RATE_HIGH` (120) requisições/min do IP no site |
| `no_reuse` | behavior | 10 | ≥ 10 requisições na última hora, uma conexão por requisição |
| `interval_regular` | behavior | 20 | ≥ 20 intervalos com coeficiente de variação < 0,1 (relógio de máquina) |
| `route_breadth` | behavior | 15 | ≥ 50 caminhos distintos na hora e < 5% de estáticos (varredura) |

Classes esperadas com as listas reais (ja4db desligada, IP residencial, sem comportamento), conferidas pelos goldens
do bot:

| Cliente | Sinais | Score | Classe |
| --- | --- | --- | --- |
| curl, Go `net/http`, python-requests | `ja4h_library`, `library_client` | 70 | `bot` |
| Chrome, Firefox | `known_client` | 0 | `human` |
| Chrome headless | `ua_automation` | 70 | `bot` |
| Googlebot falso (TLS de curl, IP fora da lista) | `ja4h_library`, `ua_claims_crawler` | 80 | `bot` |
| GPTBot de IP da lista da OpenAI | `ja4h_library`, `ip_verified_crawler` | — | `good_bot` |
| python-requests sem UA | `ua_missing`, `ja4h_library`, `library_client` | 100 | `bot` |

### Limitações conhecidas

- **forwardAuth sem JA4H na primeira requisição de cada conexão.** O traefik repassa ao forwardAuth os cabeçalhos do
  visitante, mas não a ordem deles, então o JA4H do pedido de auth não pode ser calculado. O bot usa o JA4H da
  última requisição da mesma conexão que o ingest já trouxe; na primeira não há nenhuma, e `ja4h_library` não
  aparece. Ex.: curl numa conexão nova sai no forwardAuth com 50 (`library_client`, `suspect`) em vez de 70. O
  resumo da requisição chega pelo ingest quando a resposta termina; daí em diante a consulta pela conexão
  (`/bot/v1/verdict/conn/{fs_conn_id}`) devolve o veredito com o JA4H. O feed e o webhook recebem o veredito uma
  vez por requisição, o primeiro que sair (normalmente o do forwardAuth).
- **Automação não declarada de um Chrome real sai `human`.** Selenium sem headless, ou headless com o UA trocado,
  tem TLS, h2 e UA do Chrome: nenhum sinal de incoerência ou de lista dispara. Só os sinais de comportamento
  (`rate_high`, `interval_regular`, `route_breadth`, `no_reuse`) o pegam, quando há tráfego para isso. Desafio em
  JavaScript e CAPTCHA estão fora de escopo (spec 018).
- **Cliente externo com o traefix** (caso c [abaixo](#c-site-externo-com-a-imagem-pública-do-traefix)) não tem a
  visão IP/TCP: `view.tcp` é sempre `false` e os sinais de TCP (`ua_os_tcp_mismatch`, `tunnel_mss`) não aparecem.
- UA fora das tabelas de família tende a `unknown` ou a sinais só de lista.

## Chaves

Emitidas só pelo operador, com a CLI no próprio servidor ([ADR 0051](../specs/decisions/0051-api-de-vereditos-e-chaves.md)
item 2); não há cadastro nem rota de criação na API. Formato `fsk_` + 52 caracteres base32 minúsculos, mostrado uma
vez; o banco guarda só o SHA-256 e um prefixo de 8 caracteres para exibição. Envio:
`Authorization: Bearer fsk_...` (nunca na query string).

No finger-01, como o usuário do serviço (o banco é `FS_BOT_DB`, padrão `/finger-sniffer/var/bot/bot.db`; a CLI
funciona com o serviço rodando):

```console
# sudo -u finger-sniffer /finger-sniffer/bin/finger-sniffer-bot key create --name exemplo \
    --domains example.com,*.example.com --mode observe --webhook-url https://hooks.example.com/fs
id: 01JC1A2B3C4D5E6F7G8H9J0K1M
name: exemplo
domains: example.com,*.example.com
mode: observe
limits: 20/s burst 40, 100000/day
key: fsk_...
webhook: https://hooks.example.com/fs (bot,suspect)
webhook secret: 3f9c...
(shown only once; the key works within 2s)
```

| Opção | Padrão | Efeito |
| --- | --- | --- |
| `--name` | — | nome do cliente (obrigatório) |
| `--domains` | — | domínios autorizados, separados por vírgula: `example.com` (só ele) ou `*.example.com` (subdomínios, sem o próprio `example.com`) |
| `--rate`, `--burst` | 20/s, 40 | balde de fichas por chave |
| `--daily` | 100 000 | cota diária por chave |
| `--mode` | `observe` | `observe` (forwardAuth sempre 200) ou `block` (403 para `class=bot`) |
| `--webhook-url` | — | URL `https` do webhook; gera e imprime o segredo uma vez |
| `--webhook-classes` | `bot,suspect` | classes enviadas ao webhook |

Outros comandos: `key list` (sem segredos), `key revoke <id|prefixo>`, `key rotate <id|prefixo>` (nova chave com o
mesmo id, domínios, limites e webhook; a antiga para de valer em até 2 s), `forget <ip|prefixo>` (direito do
titular, [abaixo](#retenção-e-dados-pessoais)) e `lists refresh [nome]` (baixa as listas de novo pelo serviço;
chega com a task 283).

**Domínios.** O `site` de cada recurso (SNI ou `Host` visto pelo traefix; no probe, o host de `Origin`/`Referer`)
tem de casar com um domínio da chave. Fora deles a resposta é 404 `not_found`, igual a recurso inexistente: a chave
não revela o que existe em outros sites. A exceção é o forwardAuth, que responde 400 `bad_request` (erro de
configuração de quem opera o traefik, ADR 0055 item 6).

**Limites.** Acima do balde ou da cota: 429 `rate_limited` com `Retry-After` em segundos. Globais: 200 conexões na
9002, 64 clientes no feed (acima, 503), lote do ingest até 4 MiB (acima, 413 `payload_too_large`).

**CORS.** `Access-Control-Allow-Origin` só para os domínios da chave e só nas rotas `GET`. A chave fica no backend
do site; consulta pelo navegador não é o uso previsto.

## Rotas

Nos exemplos, `KEY=fsk_...` e `BOT=https://finger-01.badblock.net.br:9002`. Na 9003 (`BOT=http://10.249.255.254:9003`,
de dentro da bridge do traefik) as mesmas chamadas funcionam sem o `Authorization`.

### `GET /bot/v1/health` e `GET /bot/v1/openapi.yaml`

Sem chave.

```console
$ curl -s $BOT/bot/v1/health | jq '{status, version, rules_version, lists_version, lists: .lists[0:2]}'
{
  "status": "ok",
  "version": "v0.4.0-22-gd9a4703",
  "rules_version": "v1.1",
  "lists_version": "91cc382c89a43660",
  "lists": [
    {"name": "known_clients", "entries": 15, "fetched_at": null, "stale": false},
    {"name": "googlebot", "entries": 317, "fetched_at": "2026-11-16T22:49:29.000000000Z", "stale": false}
  ]
}
$ curl -s $BOT/bot/v1/openapi.yaml | head -3
```

`status` vira `degraded` com `reasons`: `list <nome> stale` (lista sem atualização há mais de 72 h), `db space`
(banco acima de 90% de `FS_BOT_MAX_BYTES`), `webhook backlog` (fila de webhook cheia por mais de 60 s),
`store feed silent` (sem `fs.v1.store.connection` por mais de 60 s com o store `ok`; chega com a task 283) e
`index bytes` (despejo do índice por bytes nos últimos 60 s). O mesmo estado aparece em `services.bot` do
`/api/v1/health` do store.

### `GET /bot/v1/auth` (forwardAuth)

Chamada pelo traefix, não pelo site. O sujeito é a requisição descrita por `X-Forwarded-Method`,
`X-Forwarded-Host`, `X-Forwarded-Uri` e pelos `X-Fs-*` que o traefix acrescenta. O bot espera as duas visões até
`FS_BOT_VIEW_WAIT` (100 ms) e decide com o que tiver.

```console
$ curl -si http://10.249.255.254:9003/bot/v1/auth \
    -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Host: www.example.com' -H 'X-Forwarded-Uri: /' \
    -H 'X-Fs-Src-Ip: 198.51.100.23' -H 'X-Fs-Src-Port: 40000' -H 'X-Fs-Dst-Port: 443' \
    -H 'X-Fs-Conn-Id: 01JC0X3K8V2T7Q9F4M6P1R5S10' -H 'X-Fs-Proto: h2' -H 'User-Agent: curl/8.7.1'
HTTP/1.1 200 OK
Content-Type: application/json
X-Fs-Score: 50
X-Fs-Signals: library_client
X-Fs-Verdict: suspect

{"class":"suspect","score":50,...}
```

| Resposta | Quando |
| --- | --- |
| 200 | modo `observe` (padrão, e sempre sem chave), ou `block` com classe diferente de `bot`; cabeçalhos `X-Fs-Verdict`, `X-Fs-Score`, `X-Fs-Signals` (ids separados por vírgula, até 1 KiB) e corpo `Verdict` |
| 403 | chave em modo `block` e `class=bot`; mesmo corpo e cabeçalhos |
| 400 `missing_fork_headers` | falta algum `X-Fs-*` (o pedido não veio do traefix ou a entrada não é coberta) |
| 400 `bad_request` | `X-Fs-*` inválido, ou chave cujos domínios não casam com `X-Forwarded-Host` |
| 401, 429 | chave inválida; limite da chave |

### `GET /bot/v1/verdict?src_ip=&src_port=&site=`

Consulta pelo backend do site com a origem da conexão (os `X-Fs-Src-Ip` e `X-Fs-Src-Port` que o traefix acrescenta,
ou o IP e a porta de origem vistos por quem recebe a conexão direto). Devolve o último veredito da conexão (o da
última requisição dela). `wait=<ms>` (0–1000) espera a visão que falta.

```console
$ curl -s -H "Authorization: Bearer $KEY" \
    "$BOT/bot/v1/verdict?src_ip=198.51.100.23&src_port=40000&site=www.example.com&wait=500" | jq '{class, score}'
{
  "class": "bot",
  "score": 70
}
```

404 `not_found` para conexão desconhecida, expirada (10 min) ou de site fora da chave; 400 sem `site` ou com
`src_ip`/`src_port`/`wait` inválidos.

### `GET /bot/v1/verdict/conn/{fs_conn_id}`

O mesmo, pelo id da conexão no traefix (`X-Fs-Conn-Id`, ULID de 26 caracteres). É a consulta mais direta para o
backend atrás do traefix.

```console
$ curl -s -H "Authorization: Bearer $KEY" "$BOT/bot/v1/verdict/conn/01JC0X3K8V2T7Q9F4M6P1R5S10?wait=500" | jq .class
"bot"
```

### `GET /bot/v1/probes/{id}/verdict`

Veredito sobre as conexões de um probe vistas pelo espelho (TLS e HTTP do web, IP/TCP do store), para sites sem
traefix (caso b [abaixo](#b-site-externo-por-probe)). O domínio é o host de `Origin`/`Referer` das requisições do
probe. 404 sem conexões com requisição ou sem domínio da chave.

```console
$ curl -s -H "Authorization: Bearer $KEY" "$BOT/bot/v1/probes/k3x9q2m7v8w1/verdict?wait=1000" | jq '{class, score, view}'
```

### `GET /bot/v1/ip/{ip}`

Agregados dos últimos 7 dias do IP nos domínios da chave, por dia e site, as listas de IP em que ele está e o robô
verificado (do cache da verificação; sem cache, `null` e a verificação segue em segundo plano).

```console
$ curl -s -H "Authorization: Bearer $KEY" "$BOT/bot/v1/ip/198.51.100.23" | jq .
{
  "ip": "198.51.100.23",
  "days": [
    {"day": "2026-11-16", "site": "www.example.com", "requests": 42, "conns": 40,
     "classes": {"bot": 40, "good_bot": 0, "human": 0, "suspect": 2, "unknown": 0}}
  ],
  "lists": [],
  "crawler_verified": null
}
```

As listas de IP não são redistribuídas: a rota só diz se o IP está nelas (ADR 0053 item 5).

### `GET /bot/v1/fingerprints/{kind}/{value}`

Contagens de 7 dias de uma fingerprint (`kind` = `ja4`, `akamai`, `ja4h` ou `ja4t`; `value` até 512 caracteres),
por dia e família de UA, sem IP; o rótulo na base própria (`known_client`) e na ja4db (`ja4db_label`, `null` com ela
desligada). Os valores não são filtrados pelos domínios da chave.

```console
$ curl -s -H "Authorization: Bearer $KEY" "$BOT/bot/v1/fingerprints/ja4/t13d1517h2_8daaf6152771_cb7bf5808d99" | jq .
{
  "kind": "ja4",
  "value": "t13d1517h2_8daaf6152771_cb7bf5808d99",
  "known_client": "chrome",
  "ja4db_label": null,
  "days": [{"day": "2026-11-16", "ua_family": "chrome", "requests": 310, "ips": 12, "class_bot": 0, "class_human": 310}]
}
```

### `GET /bot/v1/stream` (feed SSE)

Vereditos dos domínios da chave em tempo real, um por requisição. Filtros `class` (classes separadas por vírgula) e
`site`. Sem replay; fila de 1024 eventos por cliente, com descarte e um evento `stream.dropped` com a contagem; ping
(`: ping`) a cada 15 s; até 64 clientes (acima, 503).

```console
$ curl -sN -H "Authorization: Bearer $KEY" "$BOT/bot/v1/stream?class=bot,suspect"
event: verdict
data: {"kind":"verdict","ts":"2026-11-16T12:00:00.060000000Z","verdict":{"class":"bot","score":70,...}}

: ping

event: stream.dropped
data: {"kind":"stream.dropped","ts":"2026-11-16T12:00:31.000000000Z","dropped":12}
```

### `POST /bot/v1/ingest/traefik`

Envio em lote do traefix (`TraefikIngestBatch`, spec 019 RF-05): registros `type=connection` (ClientHello cru e
prefixo do h2 em base64, SNI, ALPN) e `type=request` (resumo de cada requisição, sem valores de cookie,
`Authorization`, query nem corpo). Responde 202 com `accepted` e `rejected`; registro inválido (ou, com chave, de
site fora dela) é contado e ignorado sem rejeitar o lote. Lote acima de 4 MiB: 413. Não é chamado à mão; o traefix
faz isso.

```console
$ curl -s -X POST http://10.249.255.254:9003/bot/v1/ingest/traefik -H 'Content-Type: application/json' \
    -d '{"sender":"v3.6.2-traefix.1","records":[]}'
{"accepted":0,"rejected":0}
```

## Erros

Corpo `{"error": "<código>", "detail": "..."}`:

| Código | Status | Quando |
| --- | --- | --- |
| `invalid_key` | 401 | chave ausente (9002), desconhecida ou revogada |
| `rate_limited` | 429 | balde ou cota diária da chave; `Retry-After` em segundos |
| `not_found` | 404 | desconhecido, expirado (10 min) ou fora dos domínios da chave (indistinguíveis) |
| `bad_request` | 400 | parâmetro inválido; no forwardAuth, também site fora da chave |
| `missing_fork_headers` | 400 | forwardAuth sem os `X-Fs-*` do traefix |
| `payload_too_large` | 413 | lote do ingest acima de 4 MiB |
| `forbidden_origin` | 403 | origem fora das redes permitidas na 9003 |
| `internal` | 500, 503 | falha interna; 503 com mais de 64 clientes no feed |

## Webhook

Opcional por chave (`--webhook-url`, só `https`). Para cada veredito das classes escolhidas (padrão `bot` e
`suspect`) de um site da chave, o bot faz um `POST` com o corpo `VerdictEvent` (o mesmo `data` do feed):

```http
POST /fs HTTP/1.1
Host: hooks.example.com
Content-Type: application/json
X-Fs-Timestamp: 1794830400
X-Fs-Signature: sha256=5d0c...e1
X-Fs-Key-Prefix: fsk_abcdefgh

{"kind":"verdict","ts":"2026-11-16T12:00:00.060000000Z","verdict":{"class":"bot","score":70,...}}
```

- `X-Fs-Signature` = `sha256=` + hex de HMAC-SHA256(segredo, `X-Fs-Timestamp` + `"."` + corpo), com o corpo
  exatamente como chegou (não reserialize o JSON antes de conferir).
- O segredo é o `webhook secret` impresso por `key create`, em hex: a chave do HMAC são os **32 bytes**
  decodificados, não o texto hex.
- `X-Fs-Timestamp` em segundos Unix; recuse envios muito antigos (ex.: mais de 5 min) para não aceitar reenvio.
- `X-Fs-Key-Prefix` diz de qual chave é o envio (o prefixo do `key list`).
- Prazo de 5 s por envio. Erro de rede ou 5xx: até 3 novas tentativas, depois de 1 s, 5 s e 30 s; 4xx não repete;
  qualquer 2xx confirma. Fila de 1000 eventos por chave: cheia, o evento é descartado e contado
  (`fs_bot_webhook_dropped_total`); cheia por mais de 60 s, o health fica `degraded` com `webhook backlog`.

### Verificar a assinatura

Go (só biblioteca padrão: `crypto/hmac`, `crypto/sha256`, `encoding/hex`, `strconv`, `time`):

```go
// verifyFsWebhook confere X-Fs-Signature e X-Fs-Timestamp de um webhook do bot. secretHex é o
// "webhook secret" impresso por `key create`; maxSkew recusa envios antigos (reenvio).
func verifyFsWebhook(secretHex, timestamp, signature string, body []byte, now time.Time, maxSkew time.Duration) bool {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxSkew || d < -maxSkew {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(signature))
}
```

Num handler: leia o corpo inteiro (`io.ReadAll`), chame
`verifyFsWebhook(secret, r.Header.Get("X-Fs-Timestamp"), r.Header.Get("X-Fs-Signature"), body, time.Now(), 5*time.Minute)`
e responda 401 se falhar (4xx não é repetido) ou 204 depois de aceitar.

Python 3 (biblioteca padrão):

```python
import hashlib
import hmac
import time


def verify_fs_webhook(secret_hex, timestamp, signature, body, max_skew=300):
    """Confere X-Fs-Signature e X-Fs-Timestamp; body são os bytes crus do corpo."""
    if abs(time.time() - int(timestamp)) > max_skew:
        return False
    mac = hmac.new(bytes.fromhex(secret_hex), timestamp.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), signature)
```

Shell, com `openssl dgst` (corpo salvo em `body.json`; `SECRET`, `TS` e `SIG` com o segredo e os dois cabeçalhos):

```sh
expected="sha256=$({ printf '%s.' "$TS"; cat body.json; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SECRET" | awk '{print $NF}')"
if [ "$expected" = "$SIG" ]; then echo ok; else echo invalid; fi
```

Os três exemplos são conferidos por `docs/docs_test.go` contra assinaturas geradas pelo pacote do bot
(`internal/bot/webhook`).

## Guia de integração

### a) Site atrás do traefix no finger-01

Os sites do humano no finger-01 ficam atrás do container `traefik-app` (80/443). Com o traefix no lugar dele
(spec 019; a troca começa só observando, task 273), cada conexão das entradas cobertas recebe um `fs_conn_id`, os
dados vão ao bot pelo ingest na 9003, e cada requisição chega ao backend com `X-Fs-Src-Ip`, `X-Fs-Src-Port`,
`X-Fs-Dst-Port`, `X-Fs-Conn-Id` e `X-Fs-Proto`. Os `X-Fs-*` que o visitante mandar são apagados antes de qualquer
middleware, então o backend pode confiar neles.

Configuração estática do traefix (também por flags `--experimental.fingersniffer.*` ou env
`TRAEFIK_EXPERIMENTAL_FINGERSNIFFER_*`):

```yaml
experimental:
  fingerSniffer:
    ingestURL: http://10.249.255.254:9003/bot/v1/ingest/traefik
    entryPoints: [websecure]
    # padrões: queueSize 4096, queueMaxBytes 16777216, batchSize 64, flushInterval 100ms, sendTimeout 2s
```

`10.249.255.254` é o IP do host na bridge `br-net-public` do traefik (`FS_BOT_INTERNAL_LISTEN=10.249.255.254/16`).
O envio é assíncrono: o bot fora do ar nunca atrasa nem derruba uma requisição; o traefix só conta o descarte.

**Só observando** (sem forwardAuth): o backend já recebe os `X-Fs-*` e consulta o veredito quando quiser, de dentro
da bridge, sem chave:

```sh
curl -s "http://10.249.255.254:9003/bot/v1/verdict/conn/$X_FS_CONN_ID?wait=200"
```

**Com forwardAuth** (veredito em cada requisição, nos cabeçalhos): o middleware com `failOpen` (opção do traefix),
por labels do Docker:

```yaml
labels:
  - traefik.http.middlewares.fs-bot.forwardauth.address=http://10.249.255.254:9003/bot/v1/auth
  - traefik.http.middlewares.fs-bot.forwardauth.failOpen=true
  - traefik.http.middlewares.fs-bot.forwardauth.timeout=200ms
  - traefik.http.middlewares.fs-bot.forwardauth.authResponseHeaders=X-Fs-Verdict,X-Fs-Score,X-Fs-Signals
  - traefik.http.routers.meusite.middlewares=fs-bot
```

O backend lê então `X-Fs-Verdict` (`human`, `good_bot`, `bot`, `suspect`, `unknown`), `X-Fs-Score` e
`X-Fs-Signals`. Com `failOpen`, bot fora do ar, prazo de 200 ms vencido ou 5xx deixam a requisição seguir com
`X-Fs-Verdict: unavailable`; trate esse valor como "sem veredito", nunca como `human`. Um 4xx do bot (ex.: 400 por
configuração errada) volta ao visitante, como no traefik upstream.

Sem chave, o forwardAuth na 9003 está sempre em modo `observe`: nunca bloqueia. O 403 só sai para uma chave em modo
`block`, e o pedido de auth precisaria levar `Authorization: Bearer fsk_...`; ligar `block` nos sites do humano é
decisão e ação do humano (spec 019, "Fora de escopo"), não um passo deste guia.

### b) Site externo, por probe

Para um site em qualquer lugar, sem traefix: o navegador do visitante abre uma conexão ao espelho com um probe ID que
o backend do site gera, e o backend consulta o veredito desse probe com a chave. O espelho vê a conexão inteira (IP/
TCP, TLS, HTTP), e o domínio do site é lido do `Referer`/`Origin` dessa requisição, que tem de estar na chave.

1. O backend gera um ID (8 a 32 caracteres `[a-z0-9]`) por visita e o põe na página:

   ```html
   <script>
     fetch("https://k3x9q2m7v8w1.finger-west-01.badblock.net.br:8443/p/k3x9q2m7v8w1/",
           {mode: "no-cors", cache: "no-store"});
   </script>
   ```

   A porta `:8443` é obrigatória (sem ela, a conexão cai no traefik do host). Não mude a política de referrer
   para `no-referrer`: sem `Referer` nem `Origin`, o probe não tem domínio e a consulta dá 404.
2. O backend consulta, com a chave (no servidor, nunca no navegador):

   ```sh
   curl -s -H "Authorization: Bearer $KEY" \
     "https://finger-01.badblock.net.br:9002/bot/v1/probes/k3x9q2m7v8w1/verdict?wait=1000"
   ```

O probe é a conexão do navegador ao espelho, não a do visitante ao site: mostra se quem carregou a página é um
navegador coerente, mas não vê requisições feitas direto ao site por quem não executa a página.

### c) Site externo com a imagem pública do traefix

Um site que roda o próprio traefik pode usar a imagem `tmsoftbrasil/traefix` e mandar a visão de aplicação à 9002
com uma chave cujos domínios cubram os sites dele:

```yaml
experimental:
  fingerSniffer:
    ingestURL: https://finger-01.badblock.net.br:9002/bot/v1/ingest/traefik
    apiKey: fsk_...
    entryPoints: [websecure]
```

O backend consulta pelo `X-Fs-Conn-Id` que o traefix dele acrescenta:

```sh
curl -s -H "Authorization: Bearer $KEY" \
  "https://finger-01.badblock.net.br:9002/bot/v1/verdict/conn/$X_FS_CONN_ID?wait=500"
```

O espelho não vê os pacotes desse site: o veredito tem só TLS, h2 e HTTP (`view.tcp=false`). Registros de sites
fora da chave são recusados no ingest. Não aponte o forwardAuth desse traefix para a 9002: lá a chave é obrigatória,
o pedido de auth não a leva, e o 401 voltaria ao visitante (4xx não é fail-open).

## Retenção e dados pessoais

[ADR 0052](../specs/decisions/0052-dados-pessoais-e-retencao-de-7-dias.md) (provisória até as respostas do humano
sobre base legal e controlador). O IP é dado pessoal.

| Dado | Onde | Retenção |
| --- | --- | --- |
| conexões e requisições (visão do store e do traefix) | memória do bot | 10 min (`FS_BOT_CONN_TTL`) |
| vereditos por requisição | memória, feed e webhook | 10 min |
| agregados por IP e site por hora (requisições, conexões, caminhos distintos, estáticos, intervalos, classes) | disco | 7 dias (`FS_BOT_AGG_RETENTION`, máximo 7 dias) |
| agregados por fingerprint por dia (sem IP) | disco | 7 dias |
| chaves e webhooks; uso diário das chaves | disco | enquanto a chave existir; uso diário 90 dias |
| listas baixadas | disco | até a próxima atualização |

Expurgo de hora em hora: nada com IP passa de 7 dias e 1 hora. O bot não guarda corpo, query string, valores de
cookie nem de `Authorization`; caminhos entram nos agregados só como contagem (hash com sal do dia, descartado com o
dia). Finalidade: segurança e prevenção de abuso dos sites; os agregados não são cedidos fora das chaves com domínio
autorizado.

`finger-sniffer-bot forget <ip|prefixo>` apaga os agregados daquele IP ou prefixo no disco. Com a task 283, o
pedido chega também ao serviço em execução, que apaga a memória (índice, vereditos, acumuladores, caches) e o disco
de novo; até lá a memória expira sozinha em 10 min.

O tráfego que chega ao finger-01, inclusive o dos sites atrás do traefik, continua visível na API aberta do store
por cerca de 10 min ([README](README.md)); a API do bot não muda isso.

## Métricas

As métricas `fs_bot_*` (vereditos por classe e origem, latência do forwardAuth, ingest, índice, listas, webhook,
chaves, banco) estão em [metrics.md](metrics.md#bot).
