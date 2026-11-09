# Como sondar o espelho

Derivado das specs [005](../specs/005-web.md) (web), [006](../specs/006-raw.md) (portas cruas),
[007](../specs/007-dns.md) (DNS), [011](../specs/011-http3-quic.md) (HTTP/3) e [012](../specs/012-websocket.md)
(WebSocket). As saídas são reais (vps602), resumidas, com IPs de cliente trocados por IPs de documentação.

## Probe ID

Um probe ID amarra num só registro tudo o que uma sondagem gerou: a consulta DNS, as conexões TCP/UDP, o TLS e as
requisições. Regras:

- 8 a 32 caracteres `[a-z0-9]`, aleatório, um por sondagem (por exemplo `k3x9q2mz7a`);
- usado como **rótulo mais à esquerda** do nome (`k3x9q2mz7a.dns-monitor.tmsoft.com.br`) e no **caminho**
  (`/p/k3x9q2mz7a/`); nas portas cruas, na linha `PROBE`;
- o store associa a conexão ao probe assim que o ID aparece (SNI, `Host`, caminho, DNS ou `PROBE`).

Depois, tudo sai em `GET /api/v1/probes/<id>` ([api.md](api.md)).

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
fechamento observado vem do cliente ou de quem está no caminho (exceto quando a sondagem pede, com `close=`/`rst=`
ou o modo `source`).

## HTTP/1, h2 e h3

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

### Controles de resposta: `/p/<id>/r?...`

A resposta pode ser moldada por parâmetros, registrados no evento como `controls` (com `clamped` quando um teto
foi aplicado e `invalid` quando um valor foi recusado). `/r?...` sem probe também funciona.

| Parâmetro | Efeito | h1 | h2 | h3 |
| --- | --- | --- | --- | --- |
| `status=NNN` | código de status (inclusive 1xx; `103` Early Hints antes da final) | sim | sim | sim |
| `size=N` | tamanho do corpo (máx. 64 MiB) | sim | sim | sim |
| `delay_head=ms`, `delay_body=ms` | atrasos (máx. 60 s) | sim | sim | sim |
| `h=Nome:Valor` (repetível) | campos extras, caixa e ordem exatas | sim | sim | sim |
| `alt_svc=0` | não anunciar h3 | sim | sim | sim |
| `idle=s` | ociosidade mantida pelo servidor (padrão 120 s, máx. 600 s) | sim | sim | 400 |
| `close=after\|before-body\|mid-body` | fecha após a resposta, antes do corpo ou no meio | sim | GOAWAY; antes/no meio do corpo, RST_STREAM | 400 |
| `rst=1` | fecha com RST em vez de FIN | sim | RST_STREAM no stream | 400 |
| `chunk=N`, `trailers=1` | tamanho de cada pedaço; trailers | sim (com `frame=chunked`) | tamanho de cada DATA; trailers | 400 |
| `frame=cl\|chunked\|close` | Content-Length, chunked ou até o fechamento | sim | só registrado | 400 |
| `ver=1.0\|1.1` | versão da linha de status | sim | só registrado | 400 |
| `conn=keep\|close\|none` | `Connection: keep-alive`, `close` ou nenhum | sim | só registrado | 400 |
| `ka=timeout,max` | `Keep-Alive: timeout=..., max=...` | sim | só registrado | 400 |
| `hsize=N` | cabeçalho de resposta grande (máx. 1 MiB) | sim | só registrado | 400 |
| `continue=send\|skip\|late` | tratamento de `Expect: 100-continue` | sim | só registrado | 400 |
| `upgrade=ws` | 101 e WebSocket em eco | sim | RFC 8441 (`:protocol websocket`) | 400 |

"Só registrado": o parâmetro não existe em h2 e fica apenas em `controls.params` do registro. Em h3 os controles
que não se aplicam respondem **400** com explicação (spec 011). Valor inválido em qualquer protocolo: 400 com o
motivo em texto, registrado.

```console
$ curl -si 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?status=204&conn=close'
HTTP/2 204
cache-control: no-store
content-type: text/plain; charset=utf-8
date: Mon, 09 Nov 2026 06:54:05 GMT

$ curl -s 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?size=abc'
invalid response controls:
size=abc: must be a decimal integer
```

Outros exemplos:

```console
$ curl 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?size=100000&frame=chunked' --http1.1
$ curl 'https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?delay_head=500&h=X-Test:1'
$ curl 'http://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?close=mid-body&size=50000'
```

## WebSocket

Upgrade em `/p/<id>/r?upgrade=ws` ou em qualquer `/p/<id>/ws`, por HTTP/1.1 ou sobre h2 (RFC 8441, quando o cliente
oferece). O espelho devolve cada frame (eco). O registro traz a resposta 101 byte a byte e, por frame, opcode, FIN,
RSV, máscara e chave, tamanho e tempo, além das extensões e do fechamento (código, razão, quem fechou).

Com o node 22 ou mais novo (que tem `WebSocket` global; o node 26 já usa WebSocket sobre h2):

```console
$ node -e "const ws = new WebSocket('wss://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/ws');
  ws.onopen = () => ws.send('hello'); ws.onmessage = (m) => { console.log(m.data); ws.close(1000); }"
hello
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/probes/k3x9q2mz7a | jq -c '.connections[] | {proto,
    over: .websocket.over, ext: .websocket.extensions, frames: [.websocket.frames[] | [.dir, .opcode, .length]]}'
{"proto":"tls/h2/ws","over":"h2","ext":"permessage-deflate; client_no_context_takeover; server_no_context_takeover","frames":[["in",1,5],["out",1,5],["in",8,2],["out",8,2]]}
```

No navegador:

```js
const ws = new WebSocket("wss://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/r?upgrade=ws");
ws.onopen = () => ws.send("hello");
ws.onmessage = (m) => { console.log(m.data); ws.close(1000); };
```

## Portas cruas (raw)

A primeira linha, opcional, `PROBE <id>[ mode=echo|banner|sink|source][ n=N]\r\n` associa o probe e troca o modo; ela
não é ecoada. Modos: `echo` devolve o que chega; `banner` fala primeiro e depois só recebe; `sink` só recebe;
`source` manda `n` bytes (padrão 1 MiB) e fecha. TLS em qualquer porta crua é terminado antes (análise completa do
ClientHello) e o modo vale dentro do túnel.

Depois do FIN do cliente o servidor ainda manda `half-close test\r\n` e então fecha; o registro diz se isso chegou
(`raw.half_close.server_sent_after_client_fin`).

```console
$ printf 'PROBE k3x9q2mz7a\r\nhello\r\n' | nc -w 2 vps602.tmsoft.com.br 7
hello
half-close test
$ printf 'PROBE k3x9q2mz7a mode=source n=1000\r\n' | nc -w 2 vps602.tmsoft.com.br 21 | wc -c
    1030
```

No segundo exemplo chegam o banner FTP (30 bytes) e exatamente 1000 bytes.

## DNS

O servidor é autoritativo de `dns-monitor.tmsoft.com.br` (UDP e TCP 53), sem recursão. Qualquer nome da zona
resolve para o espelho (A/AAAA, TTL 5 s) e tem um registro HTTPS (tipo 65) com `alpn="h3,h2"` e dicas de IP.

Rótulos de controle, em qualquer posição à direita do probe ID:

| Rótulo | Efeito |
| --- | --- |
| `noh3` | sem registro HTTPS |
| `v4` | só A (AAAA vazio) |
| `v6` | só AAAA |
| `nodata` | NOERROR sem respostas |
| `nx` | NXDOMAIN |

```console
$ dig +short @vps602.tmsoft.com.br k3x9q2mz7a.dns-monitor.tmsoft.com.br A
172.233.24.85
$ dig +noall +comments @vps602.tmsoft.com.br k3x9q2mz7a.v4.dns-monitor.tmsoft.com.br AAAA | grep -E 'status|ANSWER:'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32725
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
$ dig @vps602.tmsoft.com.br k3x9q2mz7a.nx.dns-monitor.tmsoft.com.br A | grep status
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 46407
$ dig +short @vps602.tmsoft.com.br k3x9q2mz7a.dns-monitor.tmsoft.com.br TYPE65
```

(O `dig` 9.10 do macOS não conhece o mnemônico `HTTPS`; use `TYPE65`.)

Cada consulta vira um registro em `/api/v1/dns` com o resolvedor que perguntou, o `qname` com a caixa original
(0x20), flags, EDNS e ECS. Nomes fora da zona recebem `REFUSED`; acima de 20 respostas/s por IP de origem, o
servidor responde com TC=1 (UDP) ou descarta.

## Receita do go-xproxy (teste de não-interferência)

O script do xProxy (`go-xproxy/tests/nao-interferencia.sh`) compara o que o espelho vê por caminhos diferentes
(direto, squid, go-xproxy). Para cada caso:

1. **Gerar** um probe ID novo, aleatório, por caso e por caminho.
2. **Resolver e conectar** pelo caminho em teste, usando o nome `<id>.dns-monitor.tmsoft.com.br` e o caminho
   `/p/<id>/` (ou `/p/<id>/r?...` para provocar respostas); nas portas cruas, `PROBE <id>` na primeira linha.
   Por proxy, use o nome (não o IP), para que a resolução feita pelo proxy também apareça no registro.
3. **Fechar** a conexão do lado do cliente quando o caso terminar (o espelho não fecha antes de 120 s).
4. **Coletar**: `GET https://vps602.tmsoft.com.br:9000/api/v1/probes/<id>?wait=10s`. A resposta vem quando há ao
   menos uma conexão e todas fecharam, ou no fim do prazo (`all_closed: false` se o proxy ainda segura a conexão).
5. **Comparar** os campos entre caminhos: `dns[].resolver` (quem resolveu), `tcp.ja4t`/`tcp.p0f`/`ip.ttl` (quem
   abriu o TCP), `tls.ja4` e o ClientHello (quem fez o TLS), `http[].fields` e `raw_head_b64` (o que mudou nos
   cabeçalhos), `close` (quem fechou e como), `http[].proxy_signals` (sinais de proxy detectados).
6. Opcional: `DELETE /api/v1/probes/<id>` para não deixar o registro público até expirar.

```sh
id=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 12)
curl -s -x http://xproxy03:4128 "https://$id.dns-monitor.tmsoft.com.br/p/$id/" >/dev/null
curl -s "https://vps602.tmsoft.com.br:9000/api/v1/probes/$id?wait=10s" |
  jq '{all_closed, conns: [.connections[] | {proto, src: .src.ip, ja4t: .tcp.ja4t, ja4: .tls.ja4, close}],
       resolvers: [.dns[].resolver.ip]}'
```

Diferenças esperadas por proxy HTTP: `absolute-form` vira `origin-form` e campos `Proxy-*` somem; com o sufixo
`-random` o go-xproxy abre conexão nova por requisição. HTTP/3 só pelo caminho direto (proxies HTTP não carregam
QUIC).
