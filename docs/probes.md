# Como sondar o espelho

Derivado das specs [005](../specs/005-web.md) (web), [006](../specs/006-raw.md) (portas cruas),
[007](../specs/007-dns.md) (DNS), [008](../specs/008-tls-e-fingerprints.md) a [013](../specs/013-analise-ip-tcp.md)
(TLS, HTTP/1, h2, h3, WebSocket, IP/TCP) e [017](../specs/017-verificacao.md) (matriz de testes), e das ADRs
[0021](../specs/decisions/0021-date-nas-respostas.md) (`Date`) e [0022](../specs/decisions/0022-prova-do-mvp-no-espelho.md)
(receitas para o xProxy). Em caso de divergência, valem as specs e o contrato
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml).

As saídas são reais (vps602, caminho direto), resumidas, com o IP do cliente trocado por `203.0.113.10` e o
probe ID trocado por `k3x9q2mz7a`. Os comandos pelos proxies (squid 1080, go-xproxy 4128 e 4443) não foram
executados pelo projeto do espelho, que não tem acesso ao `xproxy03` (ADR 0022): são o ponto de partida do script
do xProxy.

## Probe ID

Um probe ID amarra num só registro tudo o que uma sondagem gerou: a consulta DNS, as conexões TCP/UDP, o TLS e as
requisições. Regras:

- 8 a 32 caracteres `[a-z0-9]`, aleatório, um por sondagem e por caminho (por exemplo `k3x9q2mz7a`);
- usado como **rótulo mais à esquerda** do nome (`k3x9q2mz7a.dns-monitor.tmsoft.com.br`) e no **caminho**
  (`/p/k3x9q2mz7a/`); nas portas cruas, na linha `PROBE`;
- o store associa a conexão ao probe assim que o ID aparece (SNI, `Host`, caminho, DNS ou `PROBE`).

Depois, tudo sai em `GET /api/v1/probes/<id>` ([api.md](api.md)). Para comparar execuções, use probe IDs **do
mesmo tamanho**: o ID entra no SNI, no `Host` e no caminho, e um tamanho diferente muda `head_size`, `padding_len`
do ClientHello e o tamanho dos segmentos.

## Portas capturadas

| Porta | Serviço |
| --- | --- |
| TCP 80, 443, 8080, 8443 | web: HTTP/1.x, h2, h2c, WebSocket, TLS em qualquer uma (o protocolo vem dos primeiros bytes, não da porta) |
| UDP 443 | QUIC / HTTP/3 |
| TCP 7 | eco |
| TCP 21, 22, 25, 587, 110, 143 | banner (o servidor fala primeiro), depois sink |
| TCP 993 | TLS, depois banner IMAP |
| UDP e TCP 53 | DNS autoritativo de `dns-monitor.tmsoft.com.br` |

O espelho **nunca fecha uma conexão por conta própria antes de `FS_IDLE_DEFAULT` (120 s)** sem atividade: todo
fechamento observado vem do cliente ou de quem está no caminho (exceto quando a sondagem pede, com `close=`,
`rst=`, `idle=`, `frame=close`, `Connection: close` na requisição, o modo `source`, quando o cliente encerra o TLS
com `close_notify`, que o espelho responde fechando, ou depois da troca de closes do WebSocket, caso 9). O controle
`conn=close` não está nessa lista: ele só escreve o campo na resposta.

As portas cruas (raw) escutam só nos IPs públicos do espelho (`FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`, ADR 0001), como
o web e o dns: sonde pelo nome ou por esses IPs.

## Respostas do espelho

```console
$ curl -s https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/
conn_id: 01M6ZHDDRFGPZS1EQHR779F73Q
request: 0
stream_id: 1
probe_id: k3x9q2mz7a
```

- O corpo traz o `conn_id` da conexão (ou `conn_id: unknown` se o store não respondeu em 250 ms), o índice da
  requisição e, em h2/h3, o `stream_id`. `?inline=1` devolve o JSON da própria requisição (depuração).
- `--http1.1`, `--http2` e `--http3-only` escolhem o protocolo; `http://` na porta 80 ou 8080 dá HTTP em claro.
  h2c: `curl --http2-prior-knowledge http://<id>.dns-monitor.tmsoft.com.br/p/<id>/`.
- Respostas h1/h2 em portas TLS anunciam `Alt-Svc: h3=":443"; ma=60` enquanto o servidor h3 está de pé
  (desligável por `?alt_svc=0`), e o DNS publica um registro HTTPS com `alpn="h3,h2"`. Detalhes do h3 em
  [http3.md](http3.md).
- Caminhos fora de `/p/`, `/r` e `/.well-known/acme-challenge/` servem o site estático (ou 404).
- Os bytes exatos que o espelho mandou ficam em `http[].response_sent_b64` (h1) e no fluxo
  `/raw?dir=out` ([api.md](api.md)). Comparar o que o cliente **recebeu** com isso mostra o que o caminho mudou
  na resposta.

### `Date`

Toda resposta final de HTTP/1.x, h2 e h3 leva `Date` (IMF-fixdate, UTC), inclusive 4xx/5xx do próprio espelho
(400 de controle inválido, 431, 426); as respostas 1xx (100, 103, 101 do WebSocket) não levam. Posição: no
HTTP/1, o primeiro campo depois da linha de status; no h2 e no h3, o primeiro campo depois de `:status`
(ADR 0021).

- `h=Date:<valor>` substitui o automático (vale o literal, na caixa pedida, na posição do `h=`).
- `date=0` omite o `Date`: serve para ver se o caminho acrescenta um (um intermediário conforme acrescenta, RFC
  9110 §6.6.1). Qualquer outro valor de `date` dá 400.

```console
$ curl -si --http1.1 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/' | head -3
HTTP/1.1 200 OK
Date: Mon, 09 Nov 2026 09:03:32 GMT
Content-Type: text/plain; charset=utf-8
$ curl -si --http1.1 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?date=0' | grep -ci '^date:'
0
$ curl -si --http1.1 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?h=Date:x' | head -4
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Cache-Control: no-store
Date: x
$ curl -si 'http://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?date=1' | head -2
HTTP/1.1 400 Bad Request
Date: Mon, 09 Nov 2026 09:03:33 GMT
```

O mesmo vale para h2 (`date` logo depois de `:status`) e h3 (`--http3-only`, com e sem `?date=0`), conferidos na
vps602.

### Controles de resposta: `/p/<id>/r?...`

A resposta pode ser moldada por parâmetros, registrados no evento como `controls` (`params` com o que foi pedido,
`clamped` quando um teto foi aplicado e `invalid` quando um valor foi recusado). `/r?...` sem probe também
funciona.

| Parâmetro | Efeito | h1 | h2 | h3 |
| --- | --- | --- | --- | --- |
| `status=NNN` | código de status (inclusive 1xx; `103` Early Hints antes da final) | sim | sim | sim |
| `size=N` | tamanho do corpo (máx. 64 MiB) | sim | sim | sim |
| `delay_head=ms`, `delay_body=ms` | atrasos (máx. 60 s) | sim | sim | sim |
| `h=Nome:Valor` (repetível) | campos extras, caixa e ordem exatas | sim | sim | sim |
| `alt_svc=0` | não anunciar h3 | sim | sim | sim |
| `date=0` | omitir o `Date` | sim | sim | sim |
| `idle=s` | ociosidade mantida pelo servidor (padrão 120 s, máx. 600 s) | sim | sim | 400 |
| `close=after\|before-body\|mid-body` | fecha após a resposta, antes do corpo ou no meio | sim | GOAWAY; antes/no meio do corpo, RST_STREAM | 400 |
| `rst=1` | fecha com RST em vez de FIN | sim | RST_STREAM no stream | 400 |
| `chunk=N`, `trailers=1` | tamanho de cada pedaço; trailers | sim (com `frame=chunked`) | tamanho de cada DATA; trailers | 400 |
| `frame=cl\|chunked\|close` | Content-Length, chunked ou até o fechamento | sim | só registrado | 400 |
| `ver=1.0\|1.1` | versão da linha de status | sim | só registrado | 400 |
| `conn=keep\|close\|none` | `Connection: keep-alive`, `close` ou nenhum; **só o campo**, o espelho não fecha (para isso, `close=after`) | sim | só registrado | 400 |
| `ka=timeout,max` | `Keep-Alive: timeout=..., max=...` | sim | só registrado | 400 |
| `hsize=N` | cabeçalho de resposta grande (máx. 1 MiB) | sim | só registrado | 400 |
| `continue=send\|skip\|late` | tratamento de `Expect: 100-continue` | sim | só registrado | 400 |
| `upgrade=ws` | 101 e WebSocket em eco | sim | RFC 8441 (`:protocol websocket`) | 400 |

"Só registrado": o parâmetro não existe em h2 e fica apenas em `controls.params` do registro. Em h3 os controles
que não se aplicam respondem **400** com explicação (spec 011). Valor inválido em qualquer protocolo: 400 com o
motivo em texto, registrado em `controls.invalid`.

```console
$ curl -s 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?size=abc'
invalid response controls:
size=abc: must be a decimal integer
```

## Receita comum

O script do xProxy (`go-xproxy/tests/nao-interferencia.sh`) repete cada caso por caminhos diferentes e compara o
que o espelho viu (spec 017, ADR 0022). Para cada caso, caminho e sufixo:

1. **Gerar** um probe ID novo, aleatório, sempre do mesmo tamanho.
2. **Resolver e conectar** pelo caminho em teste, usando o nome `<id>.dns-monitor.tmsoft.com.br` e o caminho
   `/p/<id>/` (ou `/p/<id>/r?...`); nas portas cruas, `PROBE <id>` na primeira linha. Por proxy, use o **nome**
   (não o IP), para que a resolução feita pelo proxy também apareça no registro.
3. **Fechar** a conexão do lado do cliente quando o caso terminar (o espelho não fecha antes de 120 s).
4. **Coletar**: `GET https://vps602.tmsoft.com.br:9000/api/v1/probes/<id>?wait=10s`. A resposta vem quando há ao
   menos uma conexão e todas fecharam, ou no fim do prazo (`all_closed: false` se o proxy ainda segura a conexão).
5. **Comparar** com a execução direta os campos estáveis do caso, descontando as diferenças esperadas do caminho.
6. Opcional: `DELETE /api/v1/probes/<id>` para não deixar o registro público até expirar.

```sh
api=https://vps602.tmsoft.com.br:9000/api/v1
id=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 12)
curl -s "https://$id.dns-monitor.tmsoft.com.br/p/$id/" >/dev/null                         # direto
# curl -s -x http://xproxy03:1080  "https://$id.dns-monitor.tmsoft.com.br/p/$id/"         # squid
# curl -s -x http://xproxy03:4128  "https://$id.dns-monitor.tmsoft.com.br/p/$id/"         # go-xproxy
# curl -s -x https://xproxy03:4443 "https://$id.dns-monitor.tmsoft.com.br/p/$id/"         # go-xproxy HTTPS-proxy
curl -s "$api/probes/$id?wait=10s" |
  jq '{all_closed, conns: [.connections[] | {proto, src: .src.ip, ja4t: .tcp.ja4t, ja4: .tls.ja4, close}],
       resolvers: [.dns[].resolver.ip]}'
```

### Caminhos

| Caminho | Como o cliente fala | Para `http://` | Para `https://`, `wss://` e portas cruas |
| --- | --- | --- | --- |
| direto | com o espelho | — | — |
| squid 1080 | HTTP com o proxy | o proxy reescreve e encaminha a requisição | túnel `CONNECT` |
| go-xproxy 4128 | HTTP com o proxy | idem | túnel `CONNECT` |
| go-xproxy 4443 | TLS com o proxy (HTTPS-proxy), HTTP dentro | idem | túnel `CONNECT` dentro do TLS com o proxy |

Os sufixos `-random` e `-session-X` são do go-xproxy; o espelho só vê o efeito: com `-random` cada requisição
chega numa conexão nova (outra porta de origem, talvez outro IP de saída); com `-session-X` as requisições da
mesma sessão saem pelo mesmo IP e podem reaproveitar a conexão, como no sufixo fixo.

### Quem aparece em cada camada

O que o espelho vê em cada camada vem de quem a abriu. É isso que define as diferenças esperadas:

| Camada (campos) | direto | proxy, `http://` | proxy, túnel `CONNECT` |
| --- | --- | --- | --- |
| DNS (`dns[].resolver`, EDNS, ECS) | resolvedor do cliente | resolvedor do proxy | resolvedor do proxy |
| IP e TCP (`src`, `ip.*`, `tcp.*`, `ja4t`, `p0f`, RTT) | cliente | proxy | proxy |
| TLS (`tls.*`, ClientHello, JA3/JA4) | cliente | — (em claro até o espelho) | cliente, intacto |
| HTTP/1 (`http[]`) | cliente | proxy (reescrito) | cliente, intacto |
| h2 (`http2.*`, Akamai) | cliente | — (o proxy fala HTTP/1 com o espelho) | cliente, intacto |
| WebSocket (`websocket.*`) | cliente | proxy, se ele repassar o `Upgrade` | cliente, intacto |
| fechamento (`close`, `times.*_fin`) | cliente | proxy | proxy (repassando ou não o fim do cliente) |
| HTTP/3 (`http3.*`) | cliente | não passa (proxies HTTP não carregam QUIC) | não passa |

### Campos estáveis e o que sempre varia

**Estáveis** são os campos iguais entre execuções do mesmo cliente pelo mesmo caminho; são eles que se comparam
entre caminhos. A lista de cada caso diz quais importam ali; a tabela abaixo é a referência por camada.

| Camada | Estáveis (mesmo cliente) | Sempre variam (ignorar) |
| --- | --- | --- |
| IP | `ip.ttl`, `ip.ttl_initial`, `ip.hops`, `ip.df`, `ip.ip_id_pattern`, `ip.tos`/`dscp`/`ecn`, `family` | `ip.ip_id_syn` (exceto padrão `zero`/`constant`) |
| TCP | `tcp.syn.window`, `tcp.syn.flags`, `tcp.syn.options` (tipos, ordem e valores, menos o TSval), `tcp.ja4t`, `tcp.p0f`, `tcp.os_guess`, `tcp.ts_clock_hz` (aproximado) | `src.port`, `tcp.syn.isn`, TSval, `tcp.ts_initial`, `tcp.ts_clock_group` (é um ID; compare igualdade só dentro da mesma execução), RTT e séries de tempo |
| TLS | `tls.record_version`, `handshake_version`, `session_id_len`, `cipher_suites`, `compression_methods`, tipos e dados das extensões (menos as voláteis), `sni`, `alpn`, `supported_groups`, `signature_algorithms`, `supported_versions`, grupos e tamanhos de `key_share`, `ja3n`, `ja4`, `ja4_r`, `ja4_stable`, `negotiated` (versão, cifra, grupo, ALPN) | `random_hex`, bytes do session ID, chaves de `key_share`, binder/ticket de PSK, carga do ECH, `handshake_ms` |
| TLS, cliente que embaralha extensões (Chrome) | os de cima; a **ordem** das extensões não | `ja3`, `ja3_md5`, `ja4_o` e a ordem de `extensions` |
| HTTP/1 | `request_line` (método, forma, versão, terminador), `fields` (nome com caixa, separador, valor, terminador, ordem), `duplicates`, `field_count`, `head_size`, `obs_fold`, `ja4h`, `body` (enquadramento, tamanho, SHA-256, pedaços e extensões, trailers), `expect_continue.waited`, `pipelined`, `upgrade`, `proxy_signals` | `t_first_byte_ms`, `t_since_prev_response_ms`, `expect_continue.wait_ms`, valores com probe ID ou `conn_id` |
| h2 | `http2.mode`, `settings` (ordem e valores), `window_update`, `priorities`, `akamai`, `streams[].pseudo_order`, ordem dos campos, `repr`/`huffman_*` do HPACK, `ja4h` | `t_ms` dos frames, índices da tabela dinâmica entre conexões diferentes |
| h3 | `http3.version`, `initial_datagram_size`, `padded_to_1200`, `client_hello_datagrams`, ids e ordem de `transport_params` (e valores, menos os de CID), `client_hello.ja4` (prefixo `q`), `h3_control_stream_seen`, `h3_settings`, `requests[].pseudo_order` | `dcid_hex`, `scid_hex`, `token_*`, `initial_frames` (o curl/ngtcp2 fragmenta o CRYPTO de forma aleatória), valor de `initial_source_connection_id` |
| WebSocket | `websocket.over`, `extensions`, `subprotocol`, opcodes, FIN, RSV, `masked` e tamanhos dos frames, `close.code`/`reason` | `mask_key_hex`, `t_ms` |
| DNS | sequência de `qtype`, `flags` (`rd`, `cd`, `ad`), `edns.udp_size`, `edns.do`, códigos de `edns.options`, presença de cookie, ECS (presença e `source_prefix`), uso de 0x20 | `id`, porta do resolvedor, a caixa de cada letra do `qname` (0x20 é aleatório), o IP do resolvedor num pool anycast |
| raw | `raw.mode`, `banner`, `probe_line`, total de bytes lidos e escritos, `half_close.server_sent_after_client_fin` | quantidade e tamanho de cada leitura (segmentação), tempos |
| fim | `close.by` e `close.how` nos casos determinísticos (o caso diz) | `close.idle_before_close_ms` e `times.*` |

Sempre variam também: `conn_id`, `ts`, `started`/`ended`, `degraded` sob carga.

`times` é a linha do tempo **TCP**. Num registro UDP o primeiro datagrama é o `started` e o fim é o `ended`, e
`times` vem `null`; no QUIC, `times` traz só `tls_done` (spec 013 RF-01, ADR 0023). Uma consulta DNS por UDP não
vira conexão do probe: o fluxo UDP da porta 53 fica `proto: udp`, sem `probe_id`, e a consulta aparece em `dns[]`
do probe e em `/api/v1/dns` (caso 10).

### Diferenças esperadas por proxy

Valem para todos os casos; cada caso acrescenta as suas.

- **`http://` por proxy**: o proxy recebe `absolute-form` (`GET http://host/p/<id>/`) e entrega ao espelho
  `origin-form` (`request_line.form: "origin"`; se chegar `absolute`, o espelho marca `absolute-form-direct` em
  `proxy_signals`); `Proxy-Connection` e `Proxy-Authorization` somem (se chegarem, viram sinal de proxy, o
  segundo como vazamento); campos hop-by-hop (`Connection`, `Keep-Alive`, `TE`, `Upgrade`) podem ser consumidos.
  Um proxy que não interfere não acrescenta campos: `Via`, `X-Forwarded-For`, `Forwarded`, `X-Squid*`,
  `X-xproxy-*` e afins aparecem em `http[].proxy_signals` e são achados, não ruído (o squid acrescenta `Via` e
  `X-Forwarded-For` se não estiver configurado com `via off` e `forwarded_for delete`).
- **Túnel `CONNECT`**: tudo acima do TCP chega como no direto (ClientHello byte a byte, h2, HTTP/1, WebSocket).
- **Sempre, por proxy**: `src`, `ip.*`, `tcp.*` (JA4T, p0f, TTL, opções, RTT, relógio) e `dns[].resolver` são do
  proxy, não do cliente; o critério aí é consistência entre execuções do mesmo proxy e entre os IPs de saída
  (caso 11).
- **`-random`**: uma conexão nova por requisição; casos com várias requisições por conexão (2, 3, 5) aparecem
  como várias conexões de uma requisição cada, e `request` volta a 0 no corpo.
- **Resposta**: por túnel, o que o cliente recebe é igual a `response_sent_b64`/`/raw?dir=out`; por proxy HTTP,
  diferenças na resposta (campos acrescentados, `Date` acrescentado com `date=0`, `Connection` trocado) são do
  proxy.

## Casos da matriz

Os 13 casos da spec 017. Em cada um: o comando pelo caminho direto, o que procurar no registro, os campos
estáveis e as diferenças esperadas pelos proxies. `$id` é um probe ID novo, `$H` é `$id.dns-monitor.tmsoft.com.br`
e `$api` é `https://vps602.tmsoft.com.br:9000/api/v1`.

### Caso 1: HTTP/1.1 com caixa, ordem, duplicatas e espaços

```console
$ printf "GET /p/$id/ HTTP/1.1\r\nhost: $H\r\nX-lower-UPPER:   spaced  value  \r\nAccept: */*\r\nX-Dup: 1\r\nX-Dup: 2\r\nUser-Agent: case1\r\n\r\n" |
    nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[0].http[0] | {request_line, duplicates, field_count, ja4h, proxy_signals}, .fields[]'
{"request_line":{"method":"GET","target":"/p/k3x9q2mz7a/","form":"origin","version":"HTTP/1.1","terminator":"crlf"},"duplicates":["x-dup"],"field_count":6,"ja4h":"ge11nn060000_09a43066ffd4_000000000000_000000000000","proxy_signals":[]}
["host",": ","k3x9q2mz7a.dns-monitor.tmsoft.com.br","crlf"]
["X-lower-UPPER",":   ","spaced  value  ","crlf"]
["Accept",": ","*/*","crlf"]
["X-Dup",": ","1","crlf"]
["X-Dup",": ","2","crlf"]
["User-Agent",": ","case1","crlf"]
```

- **Procurar**: `http[0].fields` sem normalização (caixa do nome, separador literal com os espaços, valor com os
  espaços finais, terminador), na ordem; `duplicates`; `raw_head_b64` é o cabeçalho exato.
- **Estáveis**: `request_line`, `fields` inteiros, `duplicates`, `field_count`, `head_size`, `ja4h`,
  `proxy_signals` vazio.
- **Diferenças esperadas** (`http://` por proxy): `form` `origin` (o cliente mandou `absolute`), `Proxy-*`
  ausentes. Um proxy que não interfere preserva caixa, ordem, duplicatas, separadores e espaços; normalizar caixa
  (`host` → `Host`), juntar duplicatas, aparar espaços ou reordenar é interferência. Por túnel (`https://`):
  idêntico ao direto.

### Caso 2: HTTP/1.0 sem e com `Connection: keep-alive`

```console
$ printf "GET /p/$id/ HTTP/1.0\r\nHost: $H\r\n\r\n" | nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
$ (printf "GET /p/$id/ HTTP/1.0\r\nHost: $H\r\nConnection: keep-alive\r\n\r\n"; sleep 1
   printf "GET /p/$id/ HTTP/1.0\r\nHost: $H\r\n\r\n"; sleep 1) | nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, requests, close: .close|{by,how},
    reqs: [.http[] | {v: .request_line.version, conn: [.fields[] | select(.[0] | ascii_downcase == "connection") | .[2]]}]}'
{"proto":"http1.0","requests":1,"close":{"by":"client","how":"fin"},"reqs":[{"v":"HTTP/1.0","conn":[]}]}
{"proto":"http1.0","requests":2,"close":{"by":"client","how":"fin"},"reqs":[{"v":"HTTP/1.0","conn":["keep-alive"]},{"v":"HTTP/1.0","conn":[]}]}
```

- **Procurar**: `proto` `http1.0`, `request_line.version`, o `Connection` de cada requisição, `requests` por
  conexão e quem fechou.
- **Estáveis**: versões, presença e valor de `Connection`, `requests`, `close.by`/`close.how`.
- **Diferenças esperadas**: um proxy pode falar HTTP/1.1 com o espelho mesmo quando o cliente fala 1.0 (aparece
  em `request_line.version`) e trocar `Connection: keep-alive` pelo seu próprio controle de conexão; o número de
  requisições por conexão passa a refletir o pool do proxy, não o cliente. Com `-random`, uma conexão por
  requisição.

### Caso 3: várias requisições por conexão, `Connection: close` e pipelining

```console
$ curl -s --http1.1 "https://$H/p/$id/" "https://$H/p/$id/" "https://$H/p/$id/" "https://$H/p/$id/" "https://$H/p/$id/" >/dev/null
$ curl -s --http1.1 -H 'Connection: close' "https://$H/p/$id/" >/dev/null
$ printf "GET /p/$id/ HTTP/1.1\r\nHost: $H\r\n\r\nGET /p/$id/ HTTP/1.1\r\nHost: $H\r\n\r\nGET /p/$id/ HTTP/1.1\r\nHost: $H\r\nConnection: close\r\n\r\n" |
    nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, requests, close: .close|{by,how}, pipelined: [.http[].pipelined]}'
{"proto":"tls/http1.1","requests":5,"close":{"by":"server","how":"fin"},"pipelined":[false,false,false,false,false]}
{"proto":"tls/http1.1","requests":1,"close":{"by":"server","how":"fin"},"pipelined":[false]}
{"proto":"http1.1","requests":3,"close":{"by":"client","how":"fin"},"pipelined":[false,true,true]}
```

- **Procurar**: `requests` por conexão, `http[].index`, `http[].pipelined` (a requisição chegou antes de a
  resposta anterior terminar), `t_since_prev_response_ms`, `close`. Na primeira conexão o curl encerra o TLS com
  `close_notify` ao sair e o espelho responde fechando (`close.by: server`, `idle_before_close_ms` de poucas
  dezenas de ms); na segunda, o espelho fecha porque o cliente pediu `Connection: close`.
- **Estáveis**: número de conexões e de requisições em cada uma, `pipelined`, `close.by`/`close.how`.
- **Diferenças esperadas**: por proxy HTTP, as 5 requisições podem chegar em menos ou mais conexões (pool do
  proxy) e o pipelining costuma ser desfeito (`pipelined: false`); com `-random`, 5 conexões de 1 requisição.
  Por túnel, igual ao direto, exceto o fechamento (o proxy pode fechar o lado do espelho de outro jeito).

### Caso 4: corpo com Content-Length, chunked com extensões e trailers, `Expect: 100-continue`

```console
$ curl -s --http1.1 "https://$H/p/$id/" --data-binary 'hello=world' >/dev/null
$ printf "POST /p/$id/ HTTP/1.1\r\nHost: $H\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\nConnection: close\r\n\r\n5;name=a\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 42\r\n\r\n" |
    nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
$ head -c 3000 /dev/urandom > body.bin
$ curl -s --http1.1 -H 'Expect: 100-continue' --data-binary @body.bin "https://$H/p/$id/" >/dev/null
$ curl -s --http1.1 -H 'Expect: 100-continue' --expect100-timeout 0.5 --data-binary @body.bin "https://$H/p/$id/r?continue=skip" >/dev/null
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[].http[] | {body: .body|{framing,size,chunks,trailers}, expect_continue}'
{"body":{"framing":"content-length","size":11,"chunks":null,"trailers":null},"expect_continue":null}
{"body":{"framing":"chunked","size":11,"chunks":[{"size":5,"size_literal":"5","ext":";name=a"},{"size":6,"size_literal":"6","ext":null},{"size":0,"size_literal":"0","ext":null}],"trailers":[["X-Sum",": ","42","crlf"]]},"expect_continue":null}
{"body":{"framing":"content-length","size":3000,"chunks":null,"trailers":null},"expect_continue":{"waited":true,"wait_ms":19.248859}}
{"body":{"framing":"content-length","size":3000,"chunks":null,"trailers":null},"expect_continue":{"waited":true,"wait_ms":506.160271}}
```

- **Procurar**: `body.framing`, `size`, `sha256` (sempre do corpo inteiro), `chunks` (tamanho literal e
  extensão de cada pedaço), `trailers`, `expect_continue` (o cliente esperou o 100? quanto?). Com
  `continue=skip` o espelho não manda 100 e o curl manda o corpo depois do seu prazo (0,5 s).
- **Estáveis**: `framing`, `size`, `sha256`, `chunks` (tamanhos, `size_literal`, `ext`), `trailers`,
  `expect_continue.waited`.
- **Diferenças esperadas**: por proxy HTTP, rechunking (`chunks` com outros tamanhos), extensões de pedaço
  removidas, trailers descartados ou chunked trocado por Content-Length são interferência, mas comuns: o
  `sha256` e o `size` precisam bater sempre. O proxy pode responder o 100 ele mesmo (`expect_continue.waited`
  muda) ou remover o `Expect`. Por túnel, igual ao direto.

### Caso 5: respostas provocadas

```console
$ B="http://$H/p/$id/r"
$ curl -si "$B?status=103&h=Link:%3C/s.css%3E;rel=preload" | head -3
HTTP/1.1 103 Early Hints

HTTP/1.1 200 OK
$ curl -si "$B?frame=close&size=20"
$ curl -si "$B?conn=close&ka=5,10&ver=1.0"
$ curl -s "$B?rst=1&close=mid-body&size=50000" -o /dev/null -w '%{http_code} %{size_download} exit=%{exitcode}\n'
200 12600 exit=56
$ curl -s "$B?delay_head=300&delay_body=200" -o /dev/null -w '%{time_starttransfer} %{time_total}\n'
0.345523 0.546787
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {close: .close|{by,how}, req: [.http[] | {status, controls, size: .response_sent_size}]}'
{"close":{"by":"client","how":"fin"},"req":[{"status":200,"controls":{"params":{"h":"Link:</s.css>;rel=preload","status":"103"}},"size":266}]}
{"close":{"by":"server","how":"fin"},"req":[{"status":200,"controls":{"params":{"frame":"close","size":"20"}},"size":141}]}
{"close":{"by":"client","how":"fin"},"req":[{"status":200,"controls":{"params":{"conn":"close","ka":"5,10","ver":"1.0"}},"size":260}]}
{"close":{"by":"server","how":"rst"},"req":[{"status":200,"controls":{"params":{"close":"mid-body","rst":"1","size":"50000"}},"size":25144}]}
{"close":{"by":"client","how":"fin"},"req":[{"status":200,"controls":{"params":{"delay_body":"200","delay_head":"300"}},"size":210}]}
```

- **Procurar**: `controls.params` de cada requisição, `status`, `response_sent_b64`/`response_sent_size` (bytes
  exatos que saíram, 1xx incluídos) e `close` (com `rst=1` e `close=mid-body`, o espelho manda RST no meio do
  corpo: `close.how: rst`, `times.server_rst`).
- **`conn=close` × `close=after`**: `conn=close` só escreve `Connection: close`; o espelho mantém a conexão até
  `idle` ou até o cliente fechar, para mostrar se o cliente (ou o proxy) obedece ao campo. É um desvio deliberado
  da RFC 9112 §9.6 (ADR 0023). Na saída acima o curl obedeceu e fechou (`close.by: client`). Para o espelho fechar
  depois da resposta, use `close=after` (`close.by: server`, `idle_before_close_ms` < 1 ms):

  ```console
  $ curl -s "$B?conn=close" -o /dev/null; curl -s "$B?close=after" -o /dev/null
  $ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {req: [.http[].controls.params], close: .close|{by,how,idle_before_close_ms}}'
  {"req":[{"conn":"close"}],"close":{"by":"client","how":"fin","idle_before_close_ms":21.32288}}
  {"req":[{"close":"after"}],"close":{"by":"server","how":"fin","idle_before_close_ms":0.129082}}
  ```
- **Estáveis**: `controls`, `status`, `response_sent_size` (para o mesmo probe ID, tamanho fixo e com `Date` do
  mesmo tamanho), `close.by`/`close.how` dos casos que o espelho provoca (`frame=close`, `rst=1`).
- **Diferenças esperadas**: aqui o que importa é a **resposta que o cliente recebe** comparada com
  `response_sent_b64`. Por proxy HTTP: o 103 pode ser descartado, `frame=close` vira Content-Length ou chunked,
  `Connection`/`Keep-Alive` são do proxy, o RST no meio do corpo chega ao cliente como fechamento ou erro do
  proxy, e os atrasos somam o do proxy. Com `date=0`, um proxy conforme acrescenta `Date`. Por túnel, os bytes
  recebidos são iguais a `response_sent_b64`; o RST do espelho chega ao proxy, que fecha o túnel.

### Caso 6: ociosidade (30, 90 e 180 s)

```console
$ (printf "GET /p/$id/ HTTP/1.1\r\nHost: $H\r\n\r\n"; sleep 30) | nc vps602.tmsoft.com.br 80 >/dev/null
$ (printf "GET /p/$id/r?idle=5 HTTP/1.1\r\nHost: $H\r\n\r\n"; sleep 30) | nc vps602.tmsoft.com.br 8080 >/dev/null
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {port: .dst.port, close}'
{"port":80,"close":{"by":"client","how":"fin","idle_before_close_ms":29975.008946,"half_close":false}}
{"port":8080,"close":{"by":"server","how":"fin","idle_before_close_ms":5000.600455,"half_close":false}}
```

- **Procurar**: `close.by`, `close.how`, `close.idle_before_close_ms` e `times.client_fin`/`server_fin`. Sem
  `idle=`, o espelho mantém a conexão por 120 s: com 30 e 90 s quem fecha é o cliente; com 180 s, o espelho fecha
  aos 120 s (`by: server`, `idle_before_close_ms` ≈ 120000). `idle=5` mostra o espelho fechando aos 5 s.
- **Estáveis**: `close.by` e `close.how`; `idle_before_close_ms` dentro de ±1 s do tempo pedido. Repita a
  execução direta para confirmar.
- **Diferenças esperadas**: este caso mede o proxy. Um proxy com ociosidade menor que a do cliente fecha antes
  (`by: client` do ponto de vista do espelho, com `idle_before_close_ms` igual ao timeout do proxy); um proxy
  que não repassa o fim do cliente deixa a conexão aberta até os 120 s do espelho. Ambos são achados; compare
  com o direto e entre execuções.

### Caso 7: HTTPS por `CONNECT` com curl, OpenSSL, Go e um cliente que imita o Chrome

```console
$ curl -s --http2 "https://$H/p/$id/" >/dev/null
$ printf "GET /p/$id/ HTTP/1.1\r\nHost: $H\r\nConnection: close\r\n\r\n" |
    openssl s_client -connect vps602.tmsoft.com.br:443 -servername "$H" -alpn http/1.1 -quiet 2>/dev/null >/dev/null
$ go run ./client.go "https://$H/p/$id/"      # http.Get da biblioteca padrão
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, ja3: .tls.ja3_md5, ja4: .tls.ja4, ja4_stable: .tls.ja4_stable, akamai: .http2.akamai}'
{"proto":"tls/h2","ja3":"9ff5f7c88ab8372852860f487a8b1dc5","ja4":"t13d3012h2_1d37bd780c83_581742d1f3c4","ja4_stable":"t13d3012h2_1d37bd780c83_581742d1f3c4","akamai":"3:100;4:65536;2:0|1048510465|0|m,s,a,p"}
{"proto":"tls/http1.1","ja3":"0dcde0fb73b656fd510af1874f13fb8b","ja4":"t13d4908h1_0d8feac7bc37_460f73f9cefb","ja4_stable":"t13d4907h1_0d8feac7bc37_7395dae3b2f3","akamai":null}
{"proto":"tls/h2","ja3":"03117a8ed39ef02427ebbc39f121275c","ja4":"t13d1312h2_f57a46bbacb6_f50d94e863eb","ja4_stable":"t13d1312h2_f57a46bbacb6_f50d94e863eb","akamai":"2:0;4:4194304;5:1048576;6:10485760|1073741824|0|a,m,p,s"}
```

(curl 8.23 com OpenSSL 4, OpenSSL do macOS e Go 1.27; os valores dependem da versão de cada cliente.) Por
proxy: `curl -x http://xproxy03:4128 …`, `openssl s_client -proxy xproxy03:4128 …`, `HTTPS_PROXY=… go run …`.

Dois casos de h2 em que o registro difere do de um cliente comum, e é o esperado:

- **h2c por `Upgrade: h2c`** (`curl --http2 http://…`): o stream 1 é a própria requisição HTTP/1 do upgrade, sem
  frame HEADERS, então sem outro stream a parte `PS` (ordem dos pseudo-campos) do Akamai sai **vazia** (spec 010
  RF-03). Por prior knowledge (`--http2-prior-knowledge`) o `PS` vem do primeiro HEADERS, como em `tls/h2`.

  ```console
  $ curl -s --http2 "http://$H/p/$id/" >/dev/null
  $ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, mode: .http2.mode, akamai: .http2.akamai}'
  {"proto":"h2c","mode":"upgrade","akamai":"3:100;4:10485760;2:0|1048510465|0|"}
  ```

- **SETTINGS com id repetido**: o registro guarda os SETTINGS na ordem em que chegaram, **com as repetições**
  (em `http2.settings` e no Akamai), mas o servidor h2 (`x/net/http2`) responde GOAWAY PROTOCOL_ERROR e não
  processa os HEADERS: o GOAWAY aparece em `http2.frames` (o código de erro está nos bytes de `/raw?dir=out`) e
  não há `streams[]` (spec 010, ADR 0023). Sem HEADERS o probe ID não chega; procure a conexão por `src_ip` e
  `dst_port`.

  ```console
  $ printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00\x03\x00\x00\x00\x64\x00\x04\x00\x02\x00\x00' |
      nc -w 3 vps602.tmsoft.com.br 80 >/dev/null
  $ curl -s "$api/connections?src_ip=203.0.113.10&dst_port=80&limit=1" | jq -r '.[0].conn_id' |
      xargs -I{} curl -s "$api/connections/{}" | jq -c '{proto, settings: .http2.settings, akamai: .http2.akamai,
      frames: [.http2.frames[] | [.dir, .type]], streams: (.http2.streams | length), close: .close|{by,how}}'
  {"proto":"h2c","settings":[[4,65536],[3,100],[4,131072]],"akamai":"4:65536;3:100;4:131072|00|0|","frames":[["in","SETTINGS"],["out","SETTINGS"],["out","GOAWAY"]],"streams":0,"close":{"by":"server","how":"fin"}}
  ```

- **Procurar**: `tls.client_hello_b64` (ClientHello cru) e o analisado (`cipher_suites`, `extensions`,
  `supported_groups`, `key_share`…), `ja3`/`ja3n`/`ja4`/`ja4_r`/`ja4_o`/`ja4_stable`, `negotiated`;
  `http2.settings`, `window_update`, `priorities`, `akamai` e `streams[].pseudo_order` nas conexões h2.
- **Estáveis**: a tabela de TLS e de h2 em [Campos estáveis](#campos-estáveis-e-o-que-sempre-varia). O
  ClientHello cru é comparável byte a byte depois de mascarar `random`, os bytes do session ID, as chaves de
  `key_share`, binders de PSK e a carga do ECH. Para o Chrome (e imitadores), que embaralha a ordem das
  extensões a cada conexão, compare `ja4`, `ja3n` e o conjunto de extensões, não `ja3`, `ja4_o` nem a ordem.
- **Diferenças esperadas**: nenhuma acima do TCP. Por túnel `CONNECT`, ClientHello, JA3/JA4, ALPN, SETTINGS h2 e
  Akamai têm de ser iguais aos do direto; qualquer diferença é TLS refeito pelo caminho (interceptação). Por
  4443 também: o TLS com o proxy é outro, e o do espelho continua sendo o do cliente. TCP e DNS são do proxy.

### Caso 8: `CONNECT` para portas baixas em `banner` e `echo`, com meio-fechamento

```console
$ printf "PROBE $id\r\nhello\r\n" | nc -w 3 vps602.tmsoft.com.br 7
hello
half-close test
$ printf "PROBE $id\r\nEHLO x\r\nQUIT\r\n" | nc -w 3 vps602.tmsoft.com.br 25
220 finger-sniffer ESMTP ready
half-close test
$ printf "PROBE $id mode=echo\r\nping\r\n" | openssl s_client -connect vps602.tmsoft.com.br:993 -quiet 2>/dev/null
* OK finger-sniffer IMAP ready
ping
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, port: .dst.port, raw: .raw|{mode,banner,half_close}, close: .close|{by,how,half_close}}'
{"proto":"raw","port":7,"raw":{"mode":"echo","banner":null,"half_close":{"server_sent_after_client_fin":true,"bytes":17}},"close":{"by":"client","how":"fin","half_close":true}}
{"proto":"raw","port":25,"raw":{"mode":"banner","banner":"220 finger-sniffer ESMTP ready\r\n","half_close":{"server_sent_after_client_fin":true,"bytes":17}},"close":{"by":"client","how":"fin","half_close":true}}
{"proto":"tls/raw","port":993,"raw":{"mode":"echo","banner":"* OK finger-sniffer IMAP ready\r\n","half_close":null},"close":{"by":"server","how":"fin","half_close":true}}
```

Por proxy (o túnel até a porta crua): `nc -X connect -x xproxy03:4128 vps602.tmsoft.com.br 7` (o `nc` do BSD/macOS),
ou `curl -p -x http://xproxy03:4128 telnet://vps602.tmsoft.com.br:7`; para 4443, `curl -p -x https://xproxy03:4443
telnet://…`.

- **Procurar**: `raw.mode`, `raw.banner`, `raw.probe_line`, `raw.reads_in`/`writes_out` (`[t_ms, bytes]`),
  `raw.half_close` (depois do FIN do cliente, o espelho manda `half-close test\r\n`) e `close.half_close`. A
  primeira linha `PROBE` não é ecoada. `half_close.server_sent_after_client_fin` é `true` **só quando o cliente
  confirmou o recebimento** (ACK dos bytes) da mensagem; se a conexão leva RST depois do envio ou o ACK não chega
  em 2 s, fica `false`, e `half_close.bytes` diz quantos bytes o espelho escreveu (task 083). Um `false` com
  `bytes: 17` quer dizer "o espelho mandou, mas o caminho não entregou".
- **Estáveis**: `mode`, `banner`, `probe_line`, total de bytes em cada sentido,
  `half_close.server_sent_after_client_fin`, `close.half_close`.
- **Diferenças esperadas**: TCP e DNS do proxy. Um túnel que não repassa o meio-fechamento (fecha os dois
  sentidos quando o cliente manda FIN) aparece como `half_close: null`, `server_sent_after_client_fin: false` ou
  `close.how: rst`, e o cliente não recebe `half-close test`: é um achado. A segmentação (`reads_in`) pode mudar; o total de bytes, não.

### Caso 9: WebSocket `ws://` e `wss://`

```console
$ for u in "ws://$H/p/$id/ws" "wss://$H/p/$id/r?upgrade=ws"; do
    node -e "const ws = new WebSocket('$u'); ws.onopen = () => ws.send('hello');
      ws.onmessage = (m) => { console.log(m.data); ws.close(1000, 'bye'); }; ws.onclose = () => process.exit(0)"
  done
hello
hello
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, over: .websocket.over, ext: .websocket.extensions,
    close: .websocket.close, frames: [.websocket.frames[] | [.dir, .opcode, .length, .masked]]}'
{"proto":"http1.1/ws","over":"http1.1","ext":"permessage-deflate; client_no_context_takeover; server_no_context_takeover","close":{"by":"client","code":1000,"reason":"bye"},"frames":[["in",1,5,true],["out",1,5,false],["in",8,5,true],["out",8,5,false]]}
{"proto":"tls/h2/ws","over":"h2","ext":"permessage-deflate; client_no_context_takeover; server_no_context_takeover","close":{"by":"client","code":1000,"reason":"bye"},"frames":[["in",1,5,true],["out",1,5,false],["in",8,5,true],["out",8,5,false]]}
```

(node 26: o `wss://` usa WebSocket sobre h2, RFC 8441; com node 22–25 ou navegadores sem RFC 8441, `over` é
`http1.1`.)

- **Procurar**: `websocket.over`, `path`, `extensions`, `subprotocol`, os frames (opcode, FIN, RSV, máscara,
  tamanho, sentido) e `websocket.close` (código, razão, quem fechou); a resposta 101 em `response_sent_b64`.
- **Fechamento**: `websocket.close` é o close de **quem iniciou** (`by`, `code`, `reason`); o close de resposta do
  outro lado fica só em `frames[]` (`dir`, opcode 8, tamanho), sem código nem razão (spec 012 RF-06). Depois da
  troca de closes o espelho fecha o TCP primeiro (RFC 6455 §7.1.1, exceção da spec 005 RF-08), então o TCP mostra
  `close.by: server` com `websocket.close.by: client`, e isso é o esperado:

  ```console
  $ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, ws: .websocket.close, tcp: .close|{by,how}}'
  {"proto":"http1.1/ws","ws":{"by":"client","code":1000,"reason":"bye"},"tcp":{"by":"server","how":"fin"}}
  ```
- **Estáveis**: a linha de WebSocket da [tabela](#campos-estáveis-e-o-que-sempre-varia), mais os campos do
  `Upgrade` da requisição (caso 1).
- **Diferenças esperadas**: `ws://` por proxy HTTP depende de o proxy repassar o `Upgrade` (squid e muitos
  outros não repassam, e aí o cliente recebe erro do proxy e o espelho não vê `/ws`); quando repassa, as
  extensões oferecidas podem mudar. `wss://` por túnel é igual ao direto (inclusive o h2 da RFC 8441).

### Caso 10: DNS

```console
$ dig +short @vps602.tmsoft.com.br $H A
172.233.24.85
$ dig +short @vps602.tmsoft.com.br +subnet=198.51.100.0/24 $H AAAA
2600:3c0d::f03c:93ff:fe26:8fd9
$ dig +short @vps602.tmsoft.com.br $H TYPE65
\# 41 0001000001000602683302683200040004ACE918550006001026003C 0D00000000F03C93FFFE268FD9
$ dig +short @8.8.8.8 $H A
172.233.24.85
$ dig +short +tcp @vps602.tmsoft.com.br $H A
172.233.24.85
$ curl -s "$api/dns?probe=$id" | jq -c '.[] | {resolver: .resolver.ip, proto, qname, qtype, flags, ecs: .edns.ecs, udp: .edns.udp_size, rcode: .response.rcode}'
{"resolver":"203.0.113.10","proto":"tcp","qname":"k3x9q2mz7a.dns-monitor.tmsoft.com.br.","qtype":"A","flags":{"ad":true,"cd":false,"rd":true},"ecs":null,"udp":4096,"rcode":"NOERROR"}
{"resolver":"172.253.92.93","proto":"udp","qname":"K3x9Q2mz7A.dnS-MoNItOr.TMSOFt.cOM.br.","qtype":"A","flags":{"ad":false,"cd":true,"rd":false},"ecs":{"address":"203.0.113.0","family":1,"scope_prefix":0,"source_prefix":24},"udp":1400,"rcode":"NOERROR"}
{"resolver":"203.0.113.10","proto":"udp","qname":"k3x9q2mz7a.dns-monitor.tmsoft.com.br.","qtype":"HTTPS","flags":{"ad":true,"cd":false,"rd":true},"ecs":null,"udp":4096,"rcode":"NOERROR"}
{"resolver":"203.0.113.10","proto":"udp","qname":"k3x9q2mz7a.dns-monitor.tmsoft.com.br.","qtype":"AAAA","flags":{"ad":true,"cd":false,"rd":true},"ecs":{"address":"198.51.100.0","family":1,"scope_prefix":0,"source_prefix":24},"udp":4096,"rcode":"NOERROR"}
{"resolver":"203.0.113.10","proto":"udp","qname":"k3x9q2mz7a.dns-monitor.tmsoft.com.br.","qtype":"A","flags":{"ad":true,"cd":false,"rd":true},"ecs":null,"udp":4096,"rcode":"NOERROR"}
```

A consulta pelo `8.8.8.8` chega do Google Public DNS, com 0x20 no `qname`, ECS com o /24 do cliente e sem
`rd`. (O `dig` 9.10 do macOS não conhece o mnemônico `HTTPS`; use `TYPE65`.)

Rótulos de controle, em qualquer posição à direita do probe ID:

| Rótulo | Efeito |
| --- | --- |
| `noh3` | sem registro HTTPS |
| `v4` | só A (AAAA vazio) |
| `v6` | só AAAA |
| `nodata` | NOERROR sem respostas |
| `nx` | NXDOMAIN |

Qualquer nome da zona resolve para o espelho (A/AAAA, TTL 5 s) e tem um registro HTTPS (tipo 65) com
`alpn="h3,h2"` e dicas de IP. Nomes fora da zona recebem `REFUSED`; acima de 20 respostas/s por IP de origem, o
servidor responde com TC=1 (UDP) ou descarta (`rate_limited: true`).

- **Procurar**: `dns[]` do probe (ou `/api/v1/dns?probe=`): `resolver` (quem perguntou), `proto`, `qname` com a
  caixa original, `qtype`, `flags`, `edns` (tamanho UDP, DO, cookie, ECS, opções), `response`.
- **Estáveis**: a linha de DNS da [tabela](#campos-estáveis-e-o-que-sempre-varia). O IP do resolvedor é estável
  para um resolvedor unicast; para um pool anycast, compare a rede (ou o ASN), não o IP.
- **Diferenças esperadas**: por proxy, quem resolve é o resolvedor do proxy (o cliente não consulta nada);
  `dns[]` vazio no caminho com proxy significa que o proxy usou cache (TTL 5 s) ou outro nome. ECS presente
  revela a rede de quem pediu ao resolvedor; com proxy, deve ser a do proxy.

### Caso 11: TCP, JA4T/p0f/TTL, RTT e relógio de timestamps

```console
$ for i in 1 2 3; do curl -s "http://$H/p/$id/" >/dev/null; sleep 1; done
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {ttl: .ip.ttl, hops: .ip.hops, ja4t: .tcp.ja4t, p0f: .tcp.p0f,
    os: .tcp.os_guess, rtt: .tcp.rtt_handshake_ms, app: .tcp.rtt_app_ms}'
{"ttl":46,"hops":18,"ja4t":"65535_2-1-3-1-1-8-4-0-0_1412_6","p0f":"4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0","os":"Mac OS X","rtt":21.239,"app":null}
{"ttl":46,"hops":18,"ja4t":"65535_2-1-3-1-1-8-4-0-0_1412_6","p0f":"4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0","os":"Mac OS X","rtt":19.195,"app":null}
{"ttl":46,"hops":18,"ja4t":"65535_2-1-3-1-1-8-4-0-0_1412_6","p0f":"4:46+18:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0","os":"Mac OS X","rtt":20.196,"app":null}
```

- **Procurar**: `ip.ttl`, `ip.ttl_initial`, `ip.hops`, `ip.df`, `ip.ip_id_pattern`, `tcp.syn` (janela, flags,
  opções na ordem), `tcp.ja4t`, `tcp.p0f`, `tcp.os_guess`, `tcp.rtt_handshake_ms` × `tcp.rtt_app_ms` (menor intervalo entre um
  dado do espelho e o próximo dado do cliente que o confirma: Finished do TLS, próxima requisição na mesma
  conexão; nulo quando o cliente não manda nada depois da resposta, como numa só requisição HTTP/1 em claro),
  `tcp.ts_clock_hz`, `tcp.ts_initial`, `tcp.ts_clock_group`. O relógio só é estimado em conexões que duram alguns
  segundos com tráfego (`ts_clock_hz` nulo nas curtas). `ts_clock_group` junta as conexões cujo TSval é explicado
  por um único relógio (mesma frequência e mesmo deslocamento extrapolado). Sistemas modernos deslocam o TSval:
  o macOS (`net.inet.tcp.randomize_timestamps=1`) **por conexão** e o Linux (≥ 4.10, `tcp_timestamps=1`) **por par
  de endereços**. Por isso três conexões seguidas do mesmo Mac dão três grupos, e um Linux só repete o grupo pelo
  mesmo par de IPs; grupos distintos nesses casos são o esperado, não erro (spec 013 RF-10, ADR 0023). Só um host
  que não desloca o TSval aparece no mesmo grupo saindo por IPs diferentes.
- **Estáveis**: a linha de IP e de TCP da [tabela](#campos-estáveis-e-o-que-sempre-varia). O RTT é estável só
  em ordem de grandeza (±20%). `ts_initial` e TSval mudam por conexão em Linux e macOS (deslocamento aleatório),
  por isso o agrupamento por relógio usa a frequência e a evolução, não o valor inicial.
- **Diferenças esperadas**: por proxy, todos esses campos são do proxy: o critério é consistência entre execuções
  e entre os IPs de saída do mesmo proxy (mesmo JA4T/p0f/TTL; mesmo `ts_clock_group` em saídas diferentes revela
  o mesmo host, mas grupos diferentes não provam hosts diferentes se o proxy roda Linux ou macOS). O RTT do handshake passa a ser o do proxy até o espelho; um `rtt_app_ms`
  bem maior que `rtt_handshake_ms` mostra espera no caminho de aplicação (o proxy esperando o cliente).

### Caso 12: HTTP/3 (só caminho direto)

```console
$ curl -si --http3-only "https://$H/p/$id/" | head -4
HTTP/3 200
date: Mon, 09 Nov 2026 09:03:32 GMT
content-type: text/plain; charset=utf-8
cache-control: no-store
$ curl -s --http3-only "https://$H/p/$id/r?close=after" -o /dev/null -w '%{http_code}\n'
400
$ curl -s "$api/probes/$id?wait=10s" | jq -c '.connections[] | {proto, close: .close|{by,how}, h3: .http3|{version, padded_to_1200,
    client_hello_datagrams, tp: [.transport_params[] | .[1]], ja4: .client_hello.ja4, h3_settings, close: .close|{by,how},
    reqs: [.requests[] | {stream_id, pseudo_order, status, controls}]}}'
{"proto":"quic/h3","close":{"by":"client","how":"quic_close"},"h3":{"version":"00000001","padded_to_1200":true,"client_hello_datagrams":2,"tp":["initial_source_connection_id","initial_max_stream_data_bidi_local","initial_max_stream_data_bidi_remote","initial_max_stream_data_uni","initial_max_data","initial_max_streams_bidi","initial_max_streams_uni","version_information"],"ja4":"q13d0311h3_55b375c5d22e_df5ee7f3ca36","h3_settings":[[6,4611686018427387903],[1,0],[7,0]],"close":{"by":"client","how":"connection_close"},"reqs":[{"stream_id":0,"pseudo_order":[":method",":scheme",":authority",":path"],"status":200,"controls":null}]}}
{"proto":"quic/h3","close":{"by":"client","how":"quic_close"},"h3":{"version":"00000001","padded_to_1200":true,"client_hello_datagrams":2,"tp":["initial_source_connection_id","initial_max_stream_data_bidi_local","initial_max_stream_data_bidi_remote","initial_max_stream_data_uni","initial_max_data","initial_max_streams_bidi","initial_max_streams_uni","version_information"],"ja4":"q13d0311h3_55b375c5d22e_df5ee7f3ca36","h3_settings":[[6,4611686018427387903],[1,0],[7,0]],"close":{"by":"client","how":"connection_close"},"reqs":[{"stream_id":0,"pseudo_order":[":method",":scheme",":authority",":path"],"status":400,"controls":{"params":{"close":"after"},"invalid":["close"]}}]}}
```

O curl precisa ser compilado com HTTP/3 (ngtcp2 ou quiche; `curl --version` lista `HTTP3`). Detalhes do
registro em [http3.md](http3.md).

O registro QUIC fecha na folga de `FS_TCP_CLOSE_GRACE` (100 ms) depois do `http3.connection` com `close` (o
CONNECTION_CLOSE visto pelo web), como o TCP (task 090), então o `?wait` de um probe h3 responde poucas centenas de
ms depois de o cliente terminar. Datagramas que chegam depois entram no mesmo registro. A meta é a mesma do TCP,
p95 ≤ 500 ms (ADR 0026); na carga oficial o QUIC ficou em p95 252 ms. Mantenha `wait` de 10 s: ele só limita a
espera.

- **Procurar**: `http3` (Initial, `transport_params` na ordem, `client_hello` com JA4 `q`, `h3_control_stream_seen` e `h3_settings`,
  `close`), `close.how: quic_close`, as requisições com `pseudo_order` e `controls` (os controles que não se
  aplicam a h3 dão 400 com `invalid`). Para navegadores: Alt-Svc numa primeira conexão h1/h2 (ou o registro HTTPS
  do DNS) e a conexão `quic/h3` seguinte.
- **Estáveis**: a linha de h3 da [tabela](#campos-estáveis-e-o-que-sempre-varia).
- **Diferenças esperadas**: não se aplica; proxies HTTP não carregam QUIC. Pelo proxy, o cliente cai para h2 ou
  h1 por TCP (o Alt-Svc chega, mas o UDP não passa), e isso aparece como conexão `tls/h2` sem `quic/h3`.

### Caso 13: tempo real e site

```console
$ curl -sN --max-time 4 "https://vps602.tmsoft.com.br:9000/api/v1/stream?probe=$id" > feed.sse &
$ sleep 1; curl -s "https://$H/p/$id/" >/dev/null; wait
$ grep '^event' feed.sse | sort | uniq -c
   1 event: connection.closed
   2 event: connection.updated
   1 event: dns.query
   1 event: http.request
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://vps602.tmsoft.com.br:9000/api/v1/stream?kind=nope'
400
```

- **Procurar**: os eventos do probe no `/stream` (SSE) e no `/ws` (filtros `probe`, `src_ip`, `dst_port`,
  `kind`), `stream.dropped` para um cliente que não lê, 503 acima de 64 clientes, 400 para filtro inválido. A
  página `https://<id>.dns-monitor.tmsoft.com.br/` num navegador headless mostra a própria sondagem no feed em
  menos de 1 s, sem requisições a terceiros (só a origem da página e a 9000). Detalhes em
  [realtime.md](realtime.md).
- **Estáveis**: os tipos de evento por sondagem (para o mesmo tipo de cliente): `connection.updated` e
  `connection.closed` por conexão, um `http.request` por requisição, um `dns.query` por consulta. O `ts` de cada
  evento é o instante do fato; o `packet.stray` decidido por ociosidade (fluxo UDP ou SYN sem resposta) leva `ts`
  = instante em que o store decidiu, como o `connection.closed` por ociosidade, e não aparece ~30 s atrasado
  em relação ao `ts`; os instantes dos pacotes ficam no `data` e em
  `/api/v1/packets` (ADR 0026 §5, openapi 0.3.5).
- **Diferenças esperadas**: a 9000 não é capturada; vista por um proxy, a conexão com a API é só mais um
  `CONNECT`. O feed mostra as conexões do proxy (outro `src_ip`), por isso filtre por `probe`, não por `src_ip`.
