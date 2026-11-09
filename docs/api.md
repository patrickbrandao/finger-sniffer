# API de consulta

Derivado da [spec 004](../specs/004-store-e-api.md) e do contrato
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) (versão 0.3.3, servido também em
`/api/v1/openapi.yaml`). Este guia mostra o uso; os campos de cada objeto estão no contrato.

As saídas abaixo foram obtidas na vps602 e resumidas; o IP do cliente foi trocado por um IP de documentação
(`203.0.113.10`).

## Portas e acesso

| Porta | Protocolo | Uso |
| --- | --- | --- |
| 9000 | HTTPS (mesmo certificado do espelho) | API, `/api/v1/stream`, `/api/v1/ws` |
| 9001 | HTTP | a mesma API em claro e `/metrics` (Prometheus) |

- As portas 9000 e 9001 **não são capturadas**: consultar a API não gera registros novos.
- Sem autenticação (ADR 0007), CORS `*`, JSON com nomes em inglês. Tempos em RFC 3339 UTC com nanossegundos;
  durações relativas em milissegundos (`float`), contadas a partir de `times.syn` (TCP) ou do primeiro datagrama
  (UDP).
- `/api/v1` só recebe mudanças aditivas: campos novos podem aparecer; os existentes não mudam de sentido.

> **Os dados são públicos.** Todo o tráfego que chega às portas capturadas fica legível por qualquer pessoa na
> API, inclusive cabeçalhos, cookies e corpos de requisição. Não mande segredos ao espelho.

## Retenção

- Os registros duram `FS_RETENTION` (10 minutos) ou até o banco chegar a `FS_STORE_MAX_BYTES` (2 GiB); o primeiro
  limite atingido apaga os registros mais antigos (ADR 0012). Depois disso a API responde 404.
- `DELETE /api/v1/probes/{id}` apaga antes do prazo o probe, suas conexões e suas consultas DNS (204).
- Não há histórico além da retenção nem paginação por cursor: as listas aceitam só `limit` (1 a 1000, padrão 100)
  e vêm das mais novas para as mais antigas.

## Rotas

| Método e caminho | Retorno |
| --- | --- |
| `GET /api/v1/health` | saúde de cada serviço, host, certificados e banco |
| `GET /api/v1/probes/{id}?wait=10s` | todas as conexões (completas) e consultas DNS do probe |
| `DELETE /api/v1/probes/{id}` | apaga o probe (204) |
| `GET /api/v1/connections?src_ip=&dst_port=&since=&until=&probe=&limit=` | lista resumida (`ConnectionSummary`) |
| `GET /api/v1/connections/{conn_id}` | registro completo (`Connection`) |
| `GET /api/v1/connections/{conn_id}/pcap` | pcap da conexão, os dois sentidos |
| `GET /api/v1/connections/{conn_id}/raw?dir=in\|out` | bytes de aplicação de um sentido |
| `GET /api/v1/dns?probe=&since=&limit=` | consultas DNS da zona |
| `GET /api/v1/packets?since=&until=&src_ip=&limit=` | pacotes avulsos (sem conexão) |
| `GET /api/v1/stream`, `GET /api/v1/ws` | tempo real, ver [realtime.md](realtime.md) |
| `GET /api/v1/openapi.yaml` | o contrato |
| `GET /metrics` (só 9001) | métricas, ver [metrics.md](metrics.md) |

### Filtros

| Parâmetro | Formato | Observação |
| --- | --- | --- |
| `probe` | `[a-z0-9]{8,32}` | probe ID |
| `src_ip` | IPv4 ou IPv6 | IP do cliente (em `/dns`, não existe: filtre por `probe`) |
| `dst_port` | 0–65535 | porta do espelho em que a conexão chegou |
| `since`, `until` | RFC 3339 | janela de tempo |
| `limit` | 1–1000 | padrão 100 |

## Probe: `GET /api/v1/probes/{id}`

Junta tudo o que foi associado ao probe ID: conexões (pelo SNI, `Host`, caminho `/p/<id>/`, linha `PROBE` ou DNS) e
consultas DNS (pelo rótulo mais à esquerda). Como sondar: [probes.md](probes.md).

### Long-poll `wait`

`wait` é uma duração em `ms` ou `s` (por exemplo `500ms`, `10s`); acima de 60 s vale 60 s:

- responde assim que o probe tem **ao menos uma conexão** e **todas estão fechadas** (`all_closed: true`);
- só consultas DNS (ou nada) ainda não bastam: a espera continua até a primeira conexão chegar e fechar — é o caso
  de um proxy que resolveu o nome mas ainda não conectou;
- no fim do prazo: 200 com o estado atual (`all_closed` diz se ainda há conexão aberta) ou 404 se o probe não tem
  nada;
- sem `wait`: responde na hora.

Só DNS, sem conexão no prazo, e probe sem nada:

```console
$ dig +short @vps602.tmsoft.com.br k3x9q2mz7a.dns-monitor.tmsoft.com.br A
172.233.24.85
$ time curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/probes/k3x9q2mz7a?wait=3s' | jq -c '{all_closed,
    connections: (.connections | length), dns: (.dns | length)}'
{"all_closed":true,"connections":0,"dns":1}
real    0m3.114s
$ curl -s -w ' %{http_code}\n' 'https://vps602.tmsoft.com.br:9000/api/v1/probes/nadaaquinada?wait=2s'
{
  "error": "not found or expired"
}
 404
```

Conexões mantidas abertas pelo cliente (keep-alive de navegador, h2 e h3 ociosos) só fecham por iniciativa dele: o
espelho nunca fecha antes de `FS_IDLE_DEFAULT` (120 s). Nesses casos o `wait` volta no fim do prazo com
`all_closed: false`, e o registro da conexão aberta já traz tudo o que chegou até ali.

```console
$ curl -s https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/ >/dev/null
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/probes/k3x9q2mz7a?wait=10s' | jq '{probe_id, all_closed,
    connections: [.connections[] | {conn_id, proto, src, dst, requests, close}], dns: [.dns[] | {qname, qtype, resolver}]}'
{
  "probe_id": "k3x9q2mz7a",
  "all_closed": true,
  "connections": [
    {
      "conn_id": "01M6ZHCVJ2XJERJMZ4XJD7HGRG",
      "proto": "tls/http1.1",
      "src": { "ip": "203.0.113.10", "port": 59976 },
      "dst": { "ip": "172.233.24.85", "port": 443 },
      "requests": 1,
      "close": { "by": "client", "how": "fin", "idle_before_close_ms": null, "half_close": true }
    }
  ],
  "dns": [
    {
      "qname": "k3x9q2mz7a.dns-monitor.tmsoft.com.br.",
      "qtype": "A",
      "resolver": { "ip": "2001:db8:728:1024::ac45:a44", "port": 19423 }
    }
  ]
}
```

## Conexões

### Lista

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/connections?dst_port=443&src_ip=203.0.113.10&limit=1'
[
  {
    "conn_id": "01M6ZHCVJ2XJERJMZ4XJD7HGRG",
    "probe_id": "k3x9q2mz7a",
    "proto": "tls/http1.1",
    "l4": "tcp",
    "family": 4,
    "src": { "ip": "203.0.113.10", "port": 59976 },
    "dst": { "ip": "172.233.24.85", "port": 443 },
    "started": "2026-11-09T06:54:40.685158753Z",
    "ended": "2026-11-09T06:54:40.778503592Z",
    "requests": 1,
    "degraded": false
  }
]
```

`proto` descreve a pilha detectada: `tcp`/`udp` (sem camada de aplicação), `http1.1`, `h2c`, `tls/http1.1`,
`tls/h2`, `tls/http1.1/ws`, `quic/h3`, `quic`, `raw`, `tls/raw`, `raw/unknown`, `dns` (regra completa na spec 004).
`dns` vale só para fluxos **TCP** da porta 53; um fluxo UDP da 53 fica `udp` e sem `probe_id`, e a consulta em si
está em `/api/v1/dns` (com `probe_id`), como na seção [DNS e pacotes avulsos](#dns-e-pacotes-avulsos) (ADR 0023).
`degraded: true` indica que o espelho estava acima de 200 conexões simultâneas ou 50 novas/s e não guardou pcap
nem bytes crus dessa conexão.

### Registro completo

`GET /api/v1/connections/{conn_id}` traz o resumo mais as camadas que existirem: `times` e `close` (spec 013),
`totals`, `ip`, `tcp` (SYN, JA4T, p0f, RTT, janela), `tls` (ClientHello cru e analisado, JA3/JA4, negociação),
`http` (HTTP/1), `http2`, `http3`, `websocket` e `raw`. `times` é a linha do tempo TCP: num fluxo UDP o primeiro
datagrama é o `started` e o fim é o `ended`, e `times` vem `null`, exceto no QUIC, em que traz só `tls_done`
(spec 013 RF-01, ADR 0023). Trecho real de uma conexão `tls/http1.1` feita com curl:

```console
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRG | jq '{
    ttl: .ip.ttl, hops: .ip.hops, ja4t: .tcp.ja4t, os: .tcp.os_guess, rtt: .tcp.rtt_handshake_ms,
    sni: .tls.sni, ja4: .tls.ja4, ja3: .tls.ja3_md5, negotiated: .tls.negotiated,
    request: .http[0].request_line, fields: .http[0].fields, ja4h: .http[0].ja4h}'
{
  "ttl": 46,
  "hops": 18,
  "ja4t": "65535_2-1-3-1-1-8-4-0-0_1412_6",
  "os": "Mac OS X",
  "rtt": 21.015,
  "sni": "k3x9q2mz7a.dns-monitor.tmsoft.com.br",
  "ja4": "t13d4907h1_0d8feac7bc37_7395dae3b2f3",
  "ja3": "375c6162a492dfbf2795909110ce8424",
  "negotiated": { "version": "TLS 1.3", "cipher": "TLS_CHACHA20_POLY1305_SHA256", "group": "X25519",
                  "alpn": "http/1.1", "resumed": false },
  "request": { "method": "GET", "target": "/p/k3x9q2mz7a/", "form": "origin", "version": "HTTP/1.1",
               "terminator": "crlf" },
  "fields": [
    ["Host", ": ", "k3x9q2mz7a.dns-monitor.tmsoft.com.br", "crlf"],
    ["User-Agent", ": ", "curl/8.7.1", "crlf"],
    ["Accept", ": ", "*/*", "crlf"]
  ],
  "ja4h": "ge11nn030000_fe444ad14866_000000000000_000000000000"
}
```

Os campos HTTP/1 vêm **sem normalização**: `[nome na caixa original, separador literal, valor, terminador]`, na
ordem em que chegaram. `raw_head_b64` traz o cabeçalho exato e `response_sent_b64` os bytes exatos que o espelho
mandou. Campos `*_truncated` indicam cortes por teto de tamanho (ADR 0018); os bytes completos ficam em `/raw`.

### pcap

```console
$ curl -s -o c.pcap https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRG/pcap
$ tshark -r c.pcap | head -4
    1 0.000000000 203.0.113.10 → 172.233.24.85 TCP 78 59976 → 443 [SYN, ECN, CWR] Seq=0 Win=65535 Len=0 MSS=1412 WS=64 TSval=2740120680 TSecr=0 SACK_PERM=1
    2 0.000015230 172.233.24.85 → 203.0.113.10 TCP 74 443 → 59976 [SYN, ACK, ECN] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM=1 TSval=2185652127 TSecr=2740120680 WS=4096
    3 0.021030459 203.0.113.10 → 172.233.24.85 TCP 66 59976 → 443 [ACK] Seq=1 Ack=1 Win=131648 Len=0 TSval=2740120699 TSecr=2185652127
    4 0.022716665 203.0.113.10 → 172.233.24.85 TLSv1 410 Client Hello
```

- Formato libpcap com nanossegundos, `Content-Type: application/vnd.tcpdump.pcap`, os dois sentidos.
- Teto de `FS_PCAP_MAX_BYTES_PER_CONN` (16 MiB): acima disso os pacotes ficam só com os cabeçalhos e o registro
  marca `pcap_truncated: true`.
- Conexão `degraded` ou criada só por eventos (o capture estava fora do ar) não tem pcap: 404.

### Bytes crus: `/raw?dir=in|out`

`in` é o que o cliente mandou e `out` o que o espelho mandou, depois do TLS quando houver
(`application/octet-stream`). `in_offset`/`out_offset` de cada requisição apontam onde ela começa nesses fluxos.

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRG/raw?dir=in'
GET /p/k3x9q2mz7a/ HTTP/1.1
Host: k3x9q2mz7a.dns-monitor.tmsoft.com.br
User-Agent: curl/8.7.1
Accept: */*

$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRG/raw?dir=out'
HTTP/1.1 200 OK
Date: Mon, 09 Nov 2026 06:54:40 GMT
Content-Type: text/plain; charset=utf-8
Cache-Control: no-store
Content-Length: 69

conn_id: 01M6ZHCVJ2XJERJMZ4XJD7HGRG
request: 0
probe_id: k3x9q2mz7a
```

Cada sentido guarda até `FS_RAW_STREAM_MAX_BYTES`; acima disso o registro marca `raw_truncated.in`/`.out`.

## DNS e pacotes avulsos

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/dns?probe=k3x9q2mz7a&limit=1' | jq '.[0] | {ts, resolver, proto,
    qname, qtype, flags, edns: {udp_size: .edns.udp_size, do: .edns.do, ecs: .edns.ecs}, response}'
{
  "ts": "2026-11-09T06:54:40.652944080Z",
  "resolver": { "ip": "2001:db8:728:1024::ac45:a44", "port": 19423 },
  "proto": "udp",
  "qname": "k3x9q2mz7a.dns-monitor.tmsoft.com.br.",
  "qtype": "A",
  "flags": { "ad": false, "cd": false, "rd": false },
  "edns": { "udp_size": 1452, "do": true, "ecs": null },
  "response": {
    "answers": [ { "data": "172.233.24.85", "name": "k3x9q2mz7a.dns-monitor.tmsoft.com.br.", "ttl": 5, "type": "A" } ],
    "rcode": "NOERROR",
    "truncated": false
  }
}
```

`qname` mantém a caixa original (0x20 dos resolvedores), e `edns.ecs` mostra o Client Subnet quando o resolvedor
manda. `raw_b64` traz a mensagem crua.

Pacotes avulsos são os que não formam conexão: SYN sem resposta, RST solto, ICMP, UDP sem resposta.

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/packets?limit=1'
[
  {
    "dir": "in",
    "dst": { "ip": "172.233.24.85", "port": 55121 },
    "family": 4,
    "frame_b64": "8jyTJo/Z/v//////CABFQAAo…",
    "l4": "tcp",
    "length": 54,
    "src": { "ip": "198.51.100.58", "port": 47212 },
    "summary": "tcp 198.51.100.58 > 172.233.24.85 [R]",
    "tcp_flags": "R",
    "ts": "2026-11-09T06:54:51.699385654Z"
  }
]
```

## Saúde

```console
$ curl -s http://vps602.tmsoft.com.br:9001/api/v1/health | jq '{ok, version, versions_match,
    services: (.services | map_values(.status)), store: .host.store}'
{
  "ok": true,
  "version": "b82ead7",
  "versions_match": false,
  "services": { "capture": "ok", "dns": "ok", "raw": "ok", "store": "ok", "web": "ok" },
  "store": {
    "db_bytes": 9748272,
    "max_bytes": 2147483648,
    "retention": "10m",
    "connections": 175,
    "oldest": "2026-11-09T07:09:16.712379952Z"
  }
}
```

`versions_match: false` aparece quando um serviço foi reimplantado sozinho (`make deploy SVC=…`) e os demais
rodam outro commit.

`ok` é `false` se algum serviço estiver `down` (sem heartbeat há 15 s). `host` traz kernel, offloads e sysctls
efetivos, certificados (emissor e validade), NTP e o uso do banco (`db_bytes`, `retention`, `oldest`).

## Erros

Os erros vêm em JSON `{"error": "<texto>"}`, com os códigos declarados em cada rota do contrato (0.3.3):

| Código | Quando |
| --- | --- |
| 400 | parâmetro de consulta **ou de caminho** fora do formato do contrato: `conn_id` que não é ULID, probe ID fora de `[a-z0-9]{8,32}`, `limit` fora de 1–1000, `dir` ausente ou diferente de `in`/`out`, `wait` mal formado, filtro de tempo real inválido |
| 404 | ID no formato certo mas desconhecido ou expirado (retenção), e qualquer rota inexistente |
| 503 | só em `/stream` e `/ws`: acima de `FS_LIVE_MAX_CLIENTS` (64) clientes ao vivo |
| 500 | erro interno nas rotas de consulta |

`OPTIONS` em qualquer caminho responde **204** sem corpo (pré-voo CORS, com `Access-Control-Allow-Origin: *` e
`Access-Control-Allow-Methods: GET, DELETE, OPTIONS`).

```console
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/connections?limit=abc'
{
  "error": "invalid limit \"abc\" (1..1000)"
}
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/probes/XY
{
  "error": "invalid probe id \"XY\""
}
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/connections/NOTULID
{
  "error": "invalid conn_id \"NOTULID\""
}
$ curl -s 'https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRG/raw'
{
  "error": "dir must be in or out"
}
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZHCVJ2XJERJMZ4XJD7HGRA
{
  "error": "not found or expired"
}
$ curl -s -w '%{http_code}\n' https://vps602.tmsoft.com.br:9000/api/v1/nada
{
  "error": "not found"
}
404
$ curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS https://vps602.tmsoft.com.br:9000/api/v1/connections
204
```
