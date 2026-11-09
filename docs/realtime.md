# Tempo real: `/api/v1/stream` e `/api/v1/ws`

Derivado da [spec 004](../specs/004-store-e-api.md) ("Tempo real"), da
[ADR 0020](../specs/decisions/0020-tempo-real-sem-replay.md) e do schema `LiveEvent` do
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml).

O store empurra para os clientes um evento a cada coisa nova que **já foi gravada** (o que aparece no feed já está
na API de consulta), em menos de 1 s. Sem filtros, é o **feed global**: as sondagens de todo mundo.

| Transporte | URL |
| --- | --- |
| SSE | `https://vps602.tmsoft.com.br:9000/api/v1/stream` (ou `http://…:9001/api/v1/stream`) |
| WebSocket | `wss://vps602.tmsoft.com.br:9000/api/v1/ws` (ou `ws://…:9001/api/v1/ws`) |

Os dois aceitam qualquer `Origin` (a API é aberta; a página do site vem de outra origem).

## Regras

- **Sem replay**: o cliente recebe só o que acontecer depois de conectar; não há `Last-Event-ID`. Para o passado,
  use a [API de consulta](api.md).
- **Melhor esforço**: cada cliente tem uma fila de `FS_LIVE_BUFFER` (1024) eventos. Se ela encher (cliente lento),
  os eventos seguintes são **descartados para aquele cliente** e, quando houver espaço, ele recebe um
  `stream.dropped` com a contagem. O ingest nunca espera por cliente.
- Até `FS_LIVE_MAX_CLIENTS` (64) clientes simultâneos, somando SSE e WebSocket; acima disso, **503** com
  `{"error": …}`. Ao desconectar, a vaga é liberada.
- `connection.updated` é agregado: no máximo um por conexão a cada 250 ms (vale o último estado).

## Filtros

Aplicados no servidor, antes de enfileirar. Filtro inválido → **400** antes do upgrade ou do stream.

| Parâmetro | Casa com |
| --- | --- |
| `probe` | `probe_id` do evento (`[a-z0-9]{8,32}`) |
| `src_ip` | IP do cliente; em `dns.query`, o IP do resolvedor |
| `dst_port` | porta do espelho; `dns.query` conta como 53 |
| `kind` | lista separada por vírgula de tipos (abaixo) |

## Eventos

Cada evento é um `LiveEvent`:

```json
{"kind": "http.request", "ts": "2026-11-09T07:00:00.123456789Z",
 "conn_id": "01M6ZHCVJ2XJERJMZ4XJD7HGRG", "probe_id": "k3x9q2mz7a", "data": {}}
```

| `kind` | Quando | `data` |
| --- | --- | --- |
| `connection.opened` | conexão criada (por pacotes ou só por eventos) | `ConnectionSummary` |
| `connection.updated` | camada de aplicação fundida no registro aberto (até 1 a cada 250 ms) | `ConnectionSummary` |
| `connection.closed` | registro finalizado e gravado | `ConnectionSummary` |
| `http.request` | cada requisição HTTP/1, stream h2 ou requisição h3 | `HTTP1Request`, `HTTP2Stream` ou `HTTP3Request` |
| `dns.query` | cada consulta DNS gravada | `DNSQuery` |
| `packet.stray` | cada pacote avulso gravado | `StrayPacket` |
| `stream.dropped` | só para o cliente que perdeu eventos | `{"dropped": N}` |

`conn_id` e `probe_id` vêm preenchidos quando existem. Em `http.request`, o tipo de `data` sai do protocolo da
conexão: `request_line` existe só em HTTP/1; h2 e h3 trazem `fields` (com pseudo-cabeçalhos `:method`, `:path`…)
e o h3 traz `body_len`. Para saber IP e porta de uma requisição, guarde o `ConnectionSummary` do
`connection.opened` com o mesmo `conn_id`.

## SSE com curl

Cada evento tem `event: <kind>` e `data: <LiveEvent>`; um comentário `: ping` chega a cada 15 s.

<!-- SSE_EXAMPLE -->

## WebSocket

Uma mensagem de texto por evento; o servidor manda ping a cada 30 s, ignora mensagens do cliente e fecha com 1001
quando o store desliga.

<!-- WS_EXAMPLE -->

## Exemplo em JavaScript (navegador)

WebSocket primeiro; se não abrir em 3 s, SSE; se cair, reconecta com espera crescente. É o que a página do site faz
(`htdocs/app.mjs`).

```js
const API = "https://vps602.tmsoft.com.br:9000";
const KINDS = ["connection.opened", "connection.updated", "connection.closed",
               "http.request", "dns.query", "packet.stray", "stream.dropped"];
let attempt = 0;

function onEvent(ev) {
  if (ev.kind === "stream.dropped") console.warn(`${ev.data.dropped} events lost`);
  else console.log(ev.kind, ev.conn_id, ev.data);
}

function retry() {
  const wait = Math.min(30000, 1000 * 2 ** attempt++);
  setTimeout(connect, wait);
}

function sse() {
  const es = new EventSource(`${API}/api/v1/stream?kind=http.request,dns.query`);
  es.onopen = () => { attempt = 0; };
  for (const k of KINDS) es.addEventListener(k, (m) => onEvent(JSON.parse(m.data)));
  es.onerror = () => { es.close(); retry(); };
}

function connect() {
  const ws = new WebSocket(`${API.replace("https:", "wss:")}/api/v1/ws?kind=http.request,dns.query`);
  let opened = false;
  const timer = setTimeout(() => { if (!opened) { ws.onclose = null; ws.close(); sse(); } }, 3000);
  ws.onopen = () => { opened = true; attempt = 0; clearTimeout(timer); };
  ws.onmessage = (m) => onEvent(JSON.parse(m.data));
  ws.onclose = () => { clearTimeout(timer); if (opened) retry(); else sse(); };
}

connect();
```

Para acompanhar só uma sondagem, gere o probe ID antes, abra o feed com `?probe=<id>` e só então faça as
requisições (não há replay).

## Erros

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/stream?dst_port=abc'
<!-- ERR_EXAMPLE -->
```

O 503 (`TooManyLiveClients`) aparece com 64 clientes conectados; feche conexões que não usa.
