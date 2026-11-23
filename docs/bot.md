# API de vereditos de bot

Derivado das specs [018](../specs/018-bot.md) (serviço bot), [019](../specs/019-requisitos-do-traefix.md)
(traefix) e [020](../specs/020-api-de-vereditos.md) (API), das ADRs
[0047](../specs/decisions/0047-fase-de-bots-servico-bot.md)–[0063](../specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md)
e do contrato [cmd/finger-sniffer-bot/openapi.yaml](../cmd/finger-sniffer-bot/openapi.yaml) (OpenAPI 3.1, versão
0.5.0, também em `/bot/v1/openapi.yaml`). Em caso de divergência, valem as specs e o contrato.

O serviço `finger-sniffer-bot` junta a visão IP/TCP do espelho (o que o store viu da conexão: SYN, JA4T, p0f, TTL,
MSS) com a visão de aplicação do **traefix** (o traefik modificado, projeto externo do humano, imagem
`tmsoftbrasil/traefix`: ClientHello cru, prefixo do h2, SYN salvo, resumo de cada requisição), avalia sinais e
devolve um **veredito explicável**: a classe, o score e a lista dos sinais que pesaram. O traefix é usado **como
está** ([ADR 0062](../specs/decisions/0062-traefix-consumido-como-esta.md)): os recursos e formatos são dele,
documentados no projeto traefix; aqui fica só o perfil de configuração usado com o bot ([abaixo](#guia-de-integração)).

> **Uso não comercial** ([ADR 0053](../specs/decisions/0053-uso-nao-comercial-e-licencas.md)). A API e as chaves são
> oferecidas sem cobrança e só para uso não comercial (campo `info.x-terms` do contrato). O JA4 é BSD-3-Clause; JA4H e
> JA4T seguem a FoxIO License 1.1: uso comercial por terceiros exige licença da FoxIO e é responsabilidade deles. Vale
> também para o traefix, que calcula JA4H e JA4T e os põe em `X-Traefix-Ja4h` e `X-Traefix-Ja4t`: a imagem declara
> `MIT AND Apache-2.0 AND LicenseRef-FoxIO-1.1` no rótulo OCI `licenses` e traz o `NOTICE` em
> `/usr/share/licenses/traefix/`. O `p0f.fp` (LGPL) é lido pelo bot em tempo de execução, sem ser embutido.

## Portas

| Porta | Uso | Chave |
| --- | --- | --- |
| `https://finger-01.badblock.net.br:9002` | pública, TLS com os certificados da 9000 (A e B por SNI) | obrigatória em toda rota, exceto `health` e `openapi.yaml` |
| `http://10.249.255.254:9003` | interna, HTTP, só para o traefik do finger-01 e os containers da bridge `br-net-public` (`10.249.0.0/16`) e loopback | opcional |

As duas ficam fora da captura. Na 9003 qualquer origem fora do loopback e de `FS_BOT_INTERNAL_ALLOW` recebe 403
`forbidden_origin`. Sem chave na 9003, o `site` vale para qualquer domínio e os limites são só os globais; um
`Authorization` que não seja `Bearer fsk_...` é ignorado ali, porque um forwardAuth comum repassa os cabeçalhos do
visitante (um `Basic` do próprio site não pode virar 401; [ADR 0055](../specs/decisions/0055-ajustes-da-primeira-onda-da-f8.md)
item 5). O forwardAuth do perfil ([abaixo](#a-site-atrás-do-traefix-no-finger-01)) já não manda o `Authorization`
nem o `Cookie` do visitante, porque `authRequestHeaders` lista só os campos que o bot usa. `Bearer fsk_...` inválida
dá 401 nas duas portas.

## O veredito

Corpo `Verdict` (ADR [0049](../specs/decisions/0049-veredito-e-sinais-v1.md), regras `v1.4` das ADRs 0057,
[0058](../specs/decisions/0058-forwardauth-do-bot-ja4h-chave-e-ja4t-sem-mss.md), [0060](../specs/decisions/0060-ja4h-library-sem-campos-de-contexto-e-probe-fora-do-feed.md) e [0065](../specs/decisions/0065-tempos-do-traefix-relay-e-ttl-em-h3.md)):

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
  "rules_version": "v1.4",
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

`rules_version` é a versão das regras (`v1.4`) e `lists_version` um hash das listas em uso (base própria e listas
de IP; a ja4db só quando ligada). A mesma entrada com as mesmas duas versões dá sempre o mesmo veredito. Mudança de
peso ou de regra é nova `rules_version`.

### Sinais (rules v1.4)

Os ids são estáveis; os pesos são provisórios (revistos com o e2e e a carga da F8).

| Sinal | Tipo | Peso | O que quer dizer |
| --- | --- | --- | --- |
| `ua_missing` | incoherence | 30 | requisição HTTP sem `User-Agent` |
| `ua_tls_mismatch` | incoherence | 45 | UA de navegador e JA4 fora do conjunto daquela família (base própria e ja4db): o TLS não é o do navegador declarado |
| `ua_h2_mismatch` | incoherence | 30 | UA de navegador e Akamai (SETTINGS e ordem das pseudo-headers do h2) fora da família, ou HTTP/1.1 com ALPN sem `h2` |
| `ua_os_tcp_mismatch` | incoherence | 25 | SO do UA incompatível com o p0f ou o TTL inicial (ex.: Windows com TTL 64) |
| `ua_alpn_mismatch` | incoherence | 15 | ALPN oferecido incompatível com a família (ex.: navegador sem `h2`) |
| `ja4h_library` | incoherence | 20 | JA4H sem `Accept-Language` e com ordem de campos de biblioteca; compara também o JA4H sem `Origin` e `Referer`, para o probe (ADR 0060) |
| `tunnel_mss` | incoherence | 5 | MSS reduzido ou `mtu_implied` < 1500: túnel ou VPN no caminho (só informativo) |
| `relay_rtt_gap` | incoherence | 15 | tempos do traefix (`headerDetail: full`): volta TLS bem maior que a TCP e espera longa pelo primeiro byte, sinal de relay SOCKS5/HTTP CONNECT entre o cliente e o traefix (rules `v1.4`, ADR 0065) |
| `ua_claims_crawler` | incoherence | 60 | UA de robô conhecido vindo de IP fora da lista dele, ou com DNS reverso/direto falho |
| `ua_automation` | list | 70 | UA declara automação (`HeadlessChrome`, `PhantomJS`, `SlimerJS`, `Selenium`, `WebDriver`, `Puppeteer`, `Playwright`, `Cypress`, `HtmlUnit`, sem diferenciar maiúsculas) |
| `library_client` | list | 50 | UA de biblioteca (`curl`, `go`, `python`, `java`, `node`), ou UA vazio/desconhecido com JA4 que a base própria só viu em bibliotecas |
| `ua_declares_crawler` | list | 50 | UA que se declara robô (`…bot/`, `crawler`, `spider` ou nome da tabela) sem operador com lista publicada para provar; nunca dá `good_bot` (rules `v1.5`, ADR 0072) |
| `ja4db_match` | list | 40 | JA4 rotulado como biblioteca ou ferramenta na ja4db (só com `FS_BOT_JA4DB_ENABLE=true`; desligada por padrão) |
| `known_client` | list | −20 | JA4 + Akamai + JA4T sem o MSS (janela, opções e escala) coerentes com um cliente medido na base própria e com o UA; nunca com UA que declara automação |
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
| Selenium/headless com pilha real de Chrome e UA com marcador de automação | `ua_automation` | 70 | `bot` |
| Chrome headless | `ua_automation` | 70 | `bot` |
| Googlebot falso (TLS de curl, IP fora da lista) | `ja4h_library`, `ua_claims_crawler` | 80 | `bot` |
| GPTBot de IP da lista da OpenAI | `ja4h_library`, `ip_verified_crawler` | — | `good_bot` |
| python-requests sem UA | `ua_missing`, `ja4h_library`, `library_client` | 100 | `bot` |

### Limitações conhecidas

- **A primeira requisição de cada conexão é julgada pelos cabeçalhos do traefix.** O traefix manda o registro de
  conexão no lote junto com a primeira requisição, e o lote sai a cada 100 ms: no forwardAuth dessa requisição o
  registro quase nunca chegou. O traefik repassa à auth os cabeçalhos do visitante, mas não a ordem deles, então o
  bot usa o que o traefix calculou antes dos middlewares: `X-Traefix-Ja4h`, `X-Traefix-Ja4`, `X-Traefix-Ja3`,
  `X-Traefix-H2`, `X-Traefix-Alpn`, `X-Traefix-Ja4t`, `X-Traefix-Ttl` e, com `headerDetail: full`, `X-Traefix-Timing`,
  `X-Traefix-Ja3n`, `X-Traefix-Ja4r` e `X-Traefix-Ja4o` (spec 019 RF-08, ADR 0065). Sem `X-Traefix-Ja4h` vale o JA4H da última
  requisição da mesma conexão que o ingest já trouxe; sem nenhum dos dois, a requisição fica sem `ja4h_library`
  (curl numa conexão nova sairia com 50, `suspect`, em vez de 70). A origem de cada parte está em
  `fs_bot_auth_ja4h_total{source}` e `fs_bot_auth_fingerprint_total{kind,source}` ([metrics.md](metrics.md#bot)):
  `none` crescendo junto com o tráfego indica um traefix que não manda os cabeçalhos. O feed e o webhook recebem o
  veredito uma vez por requisição, o primeiro que sair (normalmente o do forwardAuth).
- **h3 sem JA4H e sem TCP, mas com TTL.** Com `http3HeaderOrder` desligado (perfil atual), a requisição h3 não tem
  `X-Traefix-Ja4h` nem os cabeçalhos no resumo do ingest; h3 não tem visão TCP (JA4T, p0f), mas tem o TTL do
  primeiro Initial (`udp.ttl`, `X-Traefix-Ttl`), e a parte de TTL do `ua_os_tcp_mismatch` vale em h3 (ADR 0065).
- **Resumo sem cabeçalhos é desconhecido.** O traefix manda o resumo de uma requisição sem router (ex.:
  `/favicon.ico`) ou de h3 sem `http3HeaderOrder` sem `fieldNames`, `fields` e `ja4h`; o bot não o trata como "sem
  User-Agent": a visão HTTP da conexão vem da requisição anterior que tem os cabeçalhos e, sem nenhuma, fica ausente
  (adendo da ADR 0065).
- **Relay pelos tempos.** Com `headerDetail: full`, o veredito traz em `fingerprints` `tcp_rtt_us`, `tls_rtt_us`,
  `rtt_gap_us`, `est_to_first_us` e `timing_source`. Atrás de um relay (SOCKS5, HTTP CONNECT, relay TCP) o traefix
  mede a volta TCP com o relay e a volta TLS com o cliente: `rtt_gap_us` > 15 ms e > 30% de `tcp_rtt_us`, com o
  primeiro byte depois de 5 ms, dá `relay_rtt_gap` (peso 15). Relay perto do cliente ou VPN de camada 3 não aparecem
  (a VPN aparece no MSS); uma conexão só é ruidosa (no finger-01, 2 de 40 conexões diretas por Wi-Fi saíram com o
  sinal); com origem privada os tempos aparecem mas não alimentam o sinal.
- **JA4T medido com o MSS do caminho.** A base própria guarda o JA4T medido inteiro, mas o `known_client` compara
  sem o campo do MSS: um grampo de MSS no caminho (túnel, PPPoE) não tira o −20 de um navegador real; o MSS
  reduzido aparece só em `tunnel_mss`.
- **Automação não declarada de um Chrome real sai `human`.** Selenium sem headless, ou headless com o UA trocado,
  tem TLS, h2 e UA do Chrome: nenhum sinal de incoerência ou de lista dispara. Só os sinais de comportamento
  (`rate_high`, `interval_regular`, `route_breadth`, `no_reuse`) o pegam, quando há tráfego para isso. Desafio em
  JavaScript e CAPTCHA estão fora de escopo (spec 018).
- **Cliente externo com o traefix** (caso c [abaixo](#c-site-externo-com-a-imagem-pública-do-traefix)): o espelho
  não vê os pacotes dele. A visão TCP vem só do `fingerprint.tcp` do traefix ([abaixo](#visão-tcp-do-traefix)); sem
  ela, `view.tcp` é `false` e os sinais de TCP (`ua_os_tcp_mismatch`, `tunnel_mss`) não aparecem.
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
titular, [abaixo](#retenção-e-dados-pessoais)) e `lists refresh [nome]` (baixa as listas de novo pelo serviço em
execução).

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
  "rules_version": "v1.4",
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
`store feed silent` (sem `fs.v1.store.connection` por mais de 60 s com o store `ok`) e
`index bytes` (despejo do índice por bytes nos últimos 60 s). O mesmo estado aparece em `services.bot` do
`/api/v1/health` do store.

### `GET /bot/v1/auth` (forwardAuth)

Chamada pelo traefix, não pelo site. O sujeito é a requisição descrita por `X-Forwarded-Method`,
`X-Forwarded-Host`, `X-Forwarded-Uri` e pelos `X-Traefix-*` que o traefix acrescenta: `Src-Ip`, `Src-Port`,
`Dst-Port`, `Conn-Id` e `Proto` obrigatórios; `Ja4h`, `Ja4`, `Ja3`, `H2`, `Alpn` e `Ja4t` opcionais (malformado ou
repetido é ignorado). De onde vem cada visão:

| Visão | Ordem de preferência |
| --- | --- |
| JA4H | `X-Traefix-Ja4h`; senão a última requisição da conexão no ingest |
| TLS e h2 | registro de conexão do ingest, se já chegou; senão `X-Traefix-Ja4`, `-Ja3`, `-H2` e `-Alpn` (sem `-Alpn`, a lista é vazia se o ALPN do JA4 for `00`, senão `ua_alpn_mismatch` não avalia); `-Ja3n`, `-Ja4r` e `-Ja4o` só no `fingerprints` |
| TCP e TTL | conexão casada no store (espelho); senão o `tcp` (ou, em h3, o `udp`) do registro do traefix; senão o JA4T de `X-Traefix-Ja4t` com o TTL de `X-Traefix-Ttl` (em h3, só o TTL); origem privada descarta |
| Tempos | `timing` do registro do ingest; senão `X-Traefix-Timing` |

Na 9003 o bot espera até `FS_BOT_VIEW_WAIT` (100 ms) pelas visões que faltam (com `X-Traefix-Ja4`, só pela do
store); na 9002 não espera o store, que nunca vê a conexão de um site externo.

Os `X-Fs-*` antigos (`X-Fs-Src-Ip`, ..., `X-Fs-Ja4h`) são **obsoletos**: só valem quando não veio `X-Traefix-Conn-Id`
e nunca se misturam com os `X-Traefix-*` ([ADR 0063](../specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md)
item 1). Saem numa `/bot/v2`.

```console
$ curl -si http://10.249.255.254:9003/bot/v1/auth \
    -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Host: www.example.com' -H 'X-Forwarded-Uri: /' \
    -H 'X-Traefix-Src-Ip: 198.51.100.23' -H 'X-Traefix-Src-Port: 40000' -H 'X-Traefix-Dst-Port: 443' \
    -H 'X-Traefix-Conn-Id: 01JC0X3K8V2T7Q9F4M6P1R5S10' -H 'X-Traefix-Proto: h2' \
    -H 'X-Traefix-Ja4h: ge20nn020000_5594a17e7e7e_000000000000_000000000000' -H 'User-Agent: curl/8.7.1'
HTTP/1.1 200 OK
Content-Type: application/json
X-Fs-Score: 70
X-Fs-Signals: ja4h_library,library_client
X-Fs-Verdict: bot
X-Traefix-Score: 70
X-Traefix-Signals: ja4h_library,library_client
X-Traefix-Verdict: bot

{"class":"bot","score":70,...}
```

| Resposta | Quando |
| --- | --- |
| 200 | modo `observe` (padrão, e sempre sem chave), ou `block` com classe diferente de `bot`; cabeçalhos `X-Traefix-Verdict`, `X-Traefix-Score`, `X-Traefix-Signals` (ids separados por vírgula, até 1 KiB), os `X-Fs-*` equivalentes (obsoletos) e corpo `Verdict` |
| 403 | chave em modo `block` e `class=bot`; mesmo corpo e sempre os cabeçalhos `X-Traefix-Verdict`, `X-Traefix-Score` e `X-Traefix-Signals` (e os `X-Fs-*` equivalentes) |
| 400 `missing_fork_headers` | falta algum `X-Traefix-*` obrigatório (o pedido não veio do traefix ou a entrada não tem o bloco `fingerprint`) |
| 400 `bad_request` | `X-Traefix-*` obrigatório inválido, ou chave cujos domínios não casam com `X-Forwarded-Host` |
| 401 `invalid_key`, 403 `forbidden_origin`, 429 `rate_limited` | chave inválida ou revogada; origem fora da rede permitida na 9003; limite da chave |

Nenhuma resposta de erro (400, 401, 403 `forbidden_origin`, 429, 5xx) traz `X-Traefix-Verdict` nem `X-Fs-Verdict`: é o que o traefix usa
para separar o bloqueio (403 do modo `block`, que volta ao visitante) de uma falha de configuração (fail-open,
[abaixo](#a-site-atrás-do-traefix-no-finger-01)).

### `GET /bot/v1/verdict?src_ip=&src_port=&site=`

Consulta pelo backend do site com a origem da conexão (os `X-Traefix-Src-Ip` e `X-Traefix-Src-Port` que o traefix acrescenta,
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

O mesmo, pelo id da conexão no traefix (`X-Traefix-Conn-Id`, ULID de 26 caracteres). É a consulta mais direta para o
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
(`: ping`) a cada 15 s; até 64 clientes (acima, 503). O veredito por probe não vai ao feed nem ao webhook: consulte
`GET /bot/v1/probes/{id}/verdict` (ADR 0060).

```console
$ curl -sN -H "Authorization: Bearer $KEY" "$BOT/bot/v1/stream?class=bot,suspect"
event: verdict
data: {"kind":"verdict","ts":"2026-11-16T12:00:00.060000000Z","verdict":{"class":"bot","score":70,...}}

: ping

event: stream.dropped
data: {"kind":"stream.dropped","ts":"2026-11-16T12:00:31.000000000Z","dropped":12}
```

### `POST /bot/v1/ingest/traefik`

Envio em lote do traefix, assíncrono (nunca atrasa nem falha uma requisição). Dois esquemas na mesma rota,
escolhidos pelo campo `schema` do lote ([ADR 0062](../specs/decisions/0062-traefix-consumido-como-esta.md) item 2):

| `schema` | Formato |
| --- | --- |
| `traefix.fingerprint/v1` | `TraefixFingerprintBatch`, o lote do traefix atual (registros `connection` e `request` em camelCase; tradução da cópia do esquema publicado pelo traefix, [`traefix-fingerprint-v1.schema.json`](../cmd/finger-sniffer-bot/traefix-fingerprint-v1.schema.json)) |
| ausente | `TraefikIngestBatch`, o formato anterior, mantido em `/bot/v1` para o simulador do e2e, a carga e clientes antigos |
| outro valor | 400 `bad_request`, o lote inteiro |

O registro `connection` traz o ClientHello e o prefixo do h2 (e o SYN, com `tcp`) em base64 quando `rawBytes` está
ligado, além das fingerprints prontas; o `request` traz o resumo de cada requisição, sem valores de cookie,
`Authorization`, query nem corpo. Com os bytes crus, vale a fingerprint calculada pelo bot (a base própria foi medida
com esse código), e a divergência com a pronta conta em `fs_bot_ingest_fingerprint_mismatch_total{kind}`; sem eles,
valem as prontas. Campos e tipos de registro desconhecidos são ignorados (`fs_bot_ingest_ignored_total{type}`), sem
rejeitar o lote.

Responde 202 com `accepted` e `rejected`; registro inválido (ou, com chave, de site fora dela) é contado e ignorado
sem rejeitar o lote. Lote acima de 4 MiB: 413. Não é chamado à mão; o traefix faz isso.

```console
$ curl -s -X POST http://10.249.255.254:9003/bot/v1/ingest/traefik -H 'Content-Type: application/json' \
    -d '{"schema":"traefix.fingerprint/v1","sender":"traefix/fork-point-218-g9f480d2e7",
         "entryPoint":"websecure","sentAt":"2026-11-18T12:00:00.000000000Z","records":[]}'
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
| `missing_fork_headers` | 400 | forwardAuth sem os `X-Traefix-*` do traefix |
| `payload_too_large` | 413 | lote do ingest acima de 4 MiB |
| `forbidden_origin` | 403 | origem fora das redes permitidas na 9003 |
| `internal` | 500, 503 | falha interna; 503 com mais de 64 clientes no feed |

## Webhook

Opcional por chave (`--webhook-url`, só `https`). Os cabeçalhos do webhook continuam `X-Fs-*`: não passam pelo
traefix. Para cada veredito das classes escolhidas (padrão `bot` e
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

O perfil de configuração abaixo é o da [spec 019](../specs/019-requisitos-do-traefix.md) (RF-03 e RF-04). As opções
são do traefix (`entryPoints.<nome>.fingerprint` e o `failOpen` do `forwardAuth`), documentadas no próprio projeto;
aqui só o que o bot espera delas.

### a) Site atrás do traefix no finger-01

Os sites do humano no finger-01 ficam atrás do container `traefik-app` (80/443). Com o traefix no lugar dele
(a troca começa só observando, tasks 273 e 306), cada conexão das entradas cobertas (as que têm o bloco
`fingerprint`) recebe um `connId`, os dados vão ao bot pelo ingest na 9003, e cada requisição chega ao backend com
`X-Traefix-Src-Ip`, `X-Traefix-Src-Port`, `X-Traefix-Dst-Port`, `X-Traefix-Conn-Id`, `X-Traefix-Proto`
(`h1`|`h2`|`h3`), `X-Traefix-Ja4h`, `X-Traefix-Ja3`, `X-Traefix-Ja4`, `X-Traefix-H2` (só em h2), `X-Traefix-Alpn`
(só com TLS), `X-Traefix-Ja4t` e `X-Traefix-Ttl` (com `tcp`) e, com `headerDetail: full` (padrão), os cabeçalhos de
detalhe da página "Fingerprint Signals" do traefix (`X-Traefix-Timing`, `-Tls`, `-Tls-Hello`, `-H2-Detail`, `-H3`,
`-Header-Order`, `-Cookie-Names`, `-Transport` e outros): medido no finger-01, ~3,2–3,4 KB de `X-Traefix-*` por
requisição h1/h2 com `full` e ~1,1 KB com `basic` (task 313).

**Os backends leem só `X-Traefix-*`, nunca `X-Fs-*`.** O traefix remove do cliente, antes de qualquer middleware,
todo cabeçalho com o prefixo dele (`X-Traefix-`, em qualquer caixa e também com `_` no lugar de `-`), e só esse
prefixo: um `X-Fs-Verdict` ou `X-Fs-Src-Ip` que chega ao backend pode ter sido forjado pelo visitante
([ADR 0063](../specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md) item 1). Por isso o perfil
não usa `headerPrefix` e fica no prefixo padrão.

Configuração estática do traefix (por entrada; também por flags `--entrypoints.websecure.fingerprint.*` ou env
`TRAEFIK_ENTRYPOINTS_WEBSECURE_FINGERPRINT_*`):

```yaml
entryPoints:
  websecure:
    address: ":443"
    http3: {}
    fingerprint:
      tcp: true                  # visão TCP pelo SYN salvo (só Linux)
      headerDetail: full         # padrão; obrigatório para os tempos (relay_rtt_gap); com basic não há timing
      export:
        url: http://10.249.255.254:9003/bot/v1/ingest/traefik
        # headers:
        #   Authorization: "Bearer fsk_..."   # opcional na 9003
        rawBytes: true           # ClientHello, prefixo h2 e SYN crus: o bot calcula como o espelho
        # padrões do traefix, iguais aos usados pelo bot:
        # fields: [User-Agent, Accept, Accept-Language, Accept-Encoding, "Sec-CH-UA*", "Sec-Fetch-*"]
        # queueSize: 4096, queueMaxBytes: 16777216, batchSize: 64, flushInterval: 100ms, sendTimeout: 2s
      # http3HeaderOrder: false  # desligado até a medida de custo da task 273
```

`10.249.255.254` é o IP do host na bridge `br-net-public` do traefik (`FS_BOT_INTERNAL_LISTEN=10.249.255.254/16`).
O envio é assíncrono, uma tentativa por lote: o bot fora do ar nunca atrasa nem derruba uma requisição; o traefix só
conta o descarte (`traefik_fingerprint_export_dropped_total`). `allowSensitiveFields` nunca é ligado.

**Só observando** (sem forwardAuth): o backend já recebe os `X-Traefix-*` e consulta o veredito quando quiser, de
dentro da bridge, sem chave:

```sh
curl -s "http://10.249.255.254:9003/bot/v1/verdict/conn/$X_TRAEFIX_CONN_ID?wait=200"
```

**Com forwardAuth** (veredito em cada requisição, nos cabeçalhos), configuração dinâmica:

```yaml
http:
  middlewares:
    bot:
      forwardAuth:
        address: http://10.249.255.254:9003/bot/v1/auth
        timeout: 200ms                   # obrigatório: o padrão do traefix é 30 s
        authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]   # nunca vazio
        requestHeaders:
          Authorization: "Bearer fsk_..."  # chave do site; para block, uma chave --mode block
        authResponseHeaders: [X-Traefix-Verdict, X-Traefix-Score, X-Traefix-Signals]
        failOpen:
          denyRequiresResponseHeader: X-Traefix-Verdict
          header: { name: X-Traefix-Verdict, value: unavailable }
  routers:
    meusite:
      middlewares: [bot]
```

Por labels do Docker, as mesmas opções em `traefik.http.middlewares.bot.forwardauth.*` (sintaxe na documentação do
traefix, `forwardauth-failopen.md`) e `traefik.http.routers.meusite.middlewares=bot`.

| Opção | O que o bot espera |
| --- | --- |
| `timeout` | 200 ms; sem ele vale o padrão de 30 s do traefix e um bot lento seguraria o site |
| `authRequestHeaders` | só os campos do visitante que o bot usa; **nunca vazio**: vazio mandaria o `Cookie` e o `Authorization` do visitante à auth. Os `X-Traefix-*` vão à auth sempre |
| `requestHeaders.Authorization` | a chave, uma por middleware (cada site com os próprios domínios e modo). Na 9003 é opcional, mas sem ela o modo é sempre `observe`; na 9002 é obrigatória. O traefix recusa a carga com chave vazia (ou só `Bearer `) e com a chave num `http://` público |
| `authResponseHeaders` | os três cabeçalhos do veredito copiados para o backend |
| `failOpen.denyRequiresResponseHeader` | só uma negação que traz `X-Traefix-Verdict` volta ao visitante; qualquer outra falha segue ao backend |
| `failOpen.header` | o cabeçalho posto pelo traefix quando não há veredito: `X-Traefix-Verdict: unavailable` |

Os cabeçalhos do visitante na auth são só os de `authRequestHeaders`: o `Cookie` e o `Authorization` do visitante
nunca vão ao bot (só ao backend). Os `X-Traefix-*` do fingerprint dão ao bot o JA4H, o TLS, o h2, o ALPN e o JA4T
já na primeira requisição de cada conexão.

O backend lê então `X-Traefix-Verdict` (`human`, `good_bot`, `bot`, `suspect`, `unknown` ou `unavailable`),
`X-Traefix-Score` e `X-Traefix-Signals`. O que acontece com cada resposta do bot:

| Resposta do bot | O que o traefix faz | O visitante vê |
| --- | --- | --- |
| 200 | copia `authResponseHeaders` e segue ao backend | o site |
| 403 **com** `X-Traefix-Verdict` (modo `block`, `class=bot`) | devolve o 403 do bot | o 403 |
| 4xx **sem** `X-Traefix-Verdict` (401 `invalid_key`, 403 `forbidden_origin`, 400, 429) | segue com `X-Traefix-Verdict: unavailable`, conta `traefik_forwardauth_failopen_total{reason="http_4xx"}` e loga no máximo uma linha por minuto por middleware | o site |
| 5xx, erro de rede, prazo vencido | segue com `X-Traefix-Verdict: unavailable` (`reason` = `http_5xx`, `network`, `timeout`) | o site |

Uma chave revogada, um domínio fora da chave ou o limite da chave estourado são falhas de quem opera o site, não
decisões sobre o visitante: o site continua no ar, sem veredito, e o contador `http_4xx` do traefix mostra o problema.
Trate `unavailable` como "sem veredito", nunca como `human`. Sem `failOpen`, o forwardAuth se comporta como no
traefik upstream (qualquer falha volta ao visitante), o que serve para outro servidor de auth, não para o bot.

O 403 sai só para uma chave em modo `block` (`key create --mode block`) posta em `requestHeaders.Authorization`;
ligar forwardAuth ou `block` nos sites do humano é decisão e ação do humano (spec 019, "Fora de escopo"), não um
passo deste guia.

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

Um site que roda o próprio traefik pode usar a imagem `tmsoftbrasil/traefix:latest` e mandar a visão de aplicação à
9002 com uma chave cujos domínios cubram os sites dele. O perfil é o mesmo do caso a, com a 9002 e a chave
obrigatória:

```yaml
entryPoints:
  websecure:
    address: ":443"
    fingerprint:
      tcp: true                  # recomendado: é a única visão TCP desse site
      export:
        url: https://finger-01.badblock.net.br:9002/bot/v1/ingest/traefik
        headers:
          Authorization: "Bearer fsk_..."
        rawBytes: true           # recomendado: sem o SYN cru não há palpite de SO
```

O backend consulta pelo `X-Traefix-Conn-Id` que o traefix dele acrescenta:

```sh
curl -s -H "Authorization: Bearer $KEY" \
  "https://finger-01.badblock.net.br:9002/bot/v1/verdict/conn/$X_TRAEFIX_CONN_ID?wait=500"
```

Registros de sites fora da chave são recusados no ingest. O espelho não vê os pacotes desse site: o veredito tem
TLS, h2 e HTTP do traefix e, com `tcp: true`, a visão TCP dele ([abaixo](#visão-tcp-do-traefix)).

Para ter o veredito em cada requisição, o forwardAuth desse traefix aponta para a 9002 com a chave em
`requestHeaders.Authorization` (a mesma do ingest ou outra, desde que os domínios cubram o site):

```yaml
http:
  middlewares:
    bot:
      forwardAuth:
        address: https://finger-01.badblock.net.br:9002/bot/v1/auth
        timeout: 200ms
        authRequestHeaders: [User-Agent, Accept, Accept-Language, Accept-Encoding]
        requestHeaders:
          Authorization: "Bearer fsk_..."
        authResponseHeaders: [X-Traefix-Verdict, X-Traefix-Score, X-Traefix-Signals]
        failOpen:
          denyRequiresResponseHeader: X-Traefix-Verdict
          header: { name: X-Traefix-Verdict, value: unavailable }
```

Na 9002 a chave é obrigatória. Com o `failOpen`, um 401 de chave revogada ou um 429 de limite seguem ao backend com
`X-Traefix-Verdict: unavailable` (`http_4xx`) e não chegam ao visitante; só o 403 do modo `block` volta a ele. Na
9002 o bot não espera o store. O prazo de 200 ms inclui a ida e volta pela internet até o finger-01: meça antes de
ligar `block`.

### Visão TCP do traefix

Com `fingerprint.tcp: true` (só Linux), o traefix guarda o SYN de cada conexão e manda no registro de conexão o
`tcp.ja4t`, o `tcp.p0f` (`raw_sig` do p0f v3), o TTL recebido, o RTT e, com `rawBytes`, o SYN cru; o JA4T vai
também em `X-Traefix-Ja4t`. O bot tira daí o JA4T, o TTL inicial, o MSS e seus derivados (como o store, spec 013) e
o palpite de SO do p0f pelo SYN cru, com o mesmo `p0f.fp` do store (`FS_BOT_P0F_DB`). Isso alimenta
`ua_os_tcp_mismatch`, `tunnel_mss` e `known_client` ([ADR 0063](../specs/decisions/0063-cabecalhos-x-traefix-e-visao-tcp-do-traefix.md)
item 5).

- No finger-01 a visão do **store** vence quando a conexão casa (o espelho vê todos os pacotes); a do traefix fica
  como reserva e conferência, e um JA4T diferente conta em `fs_bot_ingest_fingerprint_mismatch_total{kind="ja4t"}`.
- Para site externo é a única visão TCP: `view.tcp` passa a `true`.
- Só o JA4T do cabeçalho (registro de conexão ainda não chegou): JA4T e MSS, sem TTL nem SO.
- Descartada quando `src.ip` do registro é loopback, link-local ou privado: o SYN é de um proxy local (ex.:
  `docker-proxy`), não do cliente. Atrás de LB ou CDN o SYN é o do LB.
- Não funciona com `proxyProtocol` na entrada, nem em h3, nem com SYN cookies.

### Imagem, versão e o processo de andar juntos

O traefix e o finger-sniffer **andam juntos** ([ADR 0062](../specs/decisions/0062-traefix-consumido-como-esta.md)
itens 7 e 8, decisão do humano):

- Roda-se sempre `tmsoftbrasil/traefix:latest`, no container de teste e no `traefik-app`, sem fixar tag nem digest.
  A atualização da `latest` no finger-01 é do humano. Cada teste, e2e ou troca registra o digest e o `sender` vistos
  (`traefix/fork-point-<n>-g<sha>`, também em `traefik version`), para diagnóstico.
- Toda necessidade nova do finger-sniffer que dependa do traefix entra na seção "Pedidos ao traefix" da
  [spec 019](../specs/019-requisitos-do-traefix.md) como um pedido `PT-nn` (estado `pedido` ou `entregue`), pelo
  architect, e é avisada ao humano, que a implementa na `latest`.
- O bot trata cada pedido como opcional até ele aparecer no dado (campo, cabeçalho, métrica): nunca falha sem ele, e
  ignora campos e tipos de registro desconhecidos.
- Mudança incompatível no lote ou nos cabeçalhos só com `schema` novo (`traefix.fingerprint/v2`, ...), combinado
  antes (PT-01); campo, tipo de registro, cabeçalho ou valor novo mantém `v1`. O bot passa a aceitar o esquema novo
  antes de o traefix publicá-lo.
- Como a `latest` muda sem aviso a este repositório, `rejected`, `fs_bot_ingest_parse_errors_total` ou
  `fs_bot_ingest_fingerprint_mismatch_total` subindo junto com um `sender` novo é regressão do traefix, reportada ao
  humano.

### Métricas do traefix

Qualquer backend de métricas do traefik as expõe; são as que importam para a integração (spec 019 RF-10):

| Métrica | O que mostra |
| --- | --- |
| `traefik_fingerprint_export_records_total{entrypoint,type}` | registros enviados ao bot |
| `traefik_fingerprint_export_dropped_total{entrypoint,reason}` | descartes: `queue_full`, `send_error`, `http_4xx`, `http_5xx`, `too_large` |
| `traefik_fingerprint_export_batches_total{entrypoint,code}` | lotes por código de resposta (`error` sem resposta) |
| `traefik_fingerprint_export_queue_records{entrypoint}` | registros na fila |
| `traefik_fingerprint_export_send_seconds{entrypoint}` | duração do envio de cada lote |
| `traefik_fingerprint_capture_truncated_total{entrypoint,part}` | capturas truncadas: `client_hello`, `h2_prefix`, `headers` |
| `traefik_forwardauth_failopen_total{middleware,reason}` | fail-open do forwardAuth: `timeout`, `network`, `http_5xx`, `http_4xx` |

Do lado do bot, `fs_bot_auth_fingerprint_total{kind,source}` e `fs_bot_ingest_fingerprint_mismatch_total{kind}`
mostram de onde veio cada visão e se as fingerprints prontas do traefix batem com as calculadas
([metrics.md](metrics.md#bot)).

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

`finger-sniffer-bot forget <ip|prefixo>` apaga os agregados daquele IP ou prefixo no disco e grava o pedido para
o serviço em execução, que em até 2 s apaga a memória (índice, vereditos, acumuladores, caches) e o disco de novo; a
CLI espera até 10 s pela confirmação.

O tráfego que chega ao finger-01, inclusive o dos sites atrás do traefik, continua visível na API aberta do store
por cerca de 10 min ([README](README.md)); a API do bot não muda isso.

## Métricas

As métricas `fs_bot_*` (vereditos por classe e origem, latência do forwardAuth, origem do JA4H em
`fs_bot_auth_ja4h_total{source}` e de cada visão em `fs_bot_auth_fingerprint_total{kind,source}`, ingest com
`fs_bot_ingest_fingerprint_mismatch_total{kind}`, índice, listas, webhook, chaves, banco) estão em
[metrics.md](metrics.md#bot); as do traefix, [acima](#métricas-do-traefix).
