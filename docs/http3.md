# HTTP/3 e QUIC

Derivado da [spec 011](../specs/011-http3-quic.md), da [ADR 0019](../specs/decisions/0019-http3-eventos-e-fim-quic.md)
e dos schemas `HTTP3Info`, `HTTP3Request` e `QPACKField` do
[openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml).

O espelho atende QUIC/HTTP/3 em **UDP 443** com o mesmo certificado do TCP. Além do que o servidor h3 vê, o web lê
cada datagrama antes da pilha QUIC e decifra o Initial do cliente (as chaves Initial derivam do DCID), então o
registro mostra o **primeiro voo do QUIC como chegou**: cabeçalho, frames, parâmetros de transporte na ordem e o
ClientHello de dentro.

## Como forçar h3

| Cliente | Como |
| --- | --- |
| curl (com HTTP/3) | `curl --http3-only https://<id>.dns-monitor.tmsoft.com.br/p/<id>/` |
| navegador | a primeira resposta h1/h2 traz `Alt-Svc: h3=":443"; ma=60`; a requisição seguinte à mesma origem vai por h3. O registro HTTPS do DNS (`alpn="h3,h2"`) permite h3 já na primeira |
| quic-go | `http3.Transport` direto para `<id>.dns-monitor.tmsoft.com.br:443` |

- `?alt_svc=0` tira o `Alt-Svc` da resposta; o rótulo DNS `noh3` (`<id>.noh3.dns-monitor.tmsoft.com.br`) tira o
  registro HTTPS. Os dois juntos mantêm o navegador em h1/h2.
- O `Alt-Svc` só é anunciado enquanto o listener UDP 443 está de pé; sem ele, o web fica `degraded` no health
  (`h3_listener_down`).
- Por proxy HTTP não há h3: proxies não carregam QUIC.

Saída real (curl 8.23 com ngtcp2/nghttp3; o curl do macOS não tem HTTP/3, use o do Homebrew):

```console
$ curl -si --http3-only https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/
HTTP/3 200
date: Mon, 09 Nov 2026 09:03:32 GMT
content-type: text/plain; charset=utf-8
cache-control: no-store
content-length: 81

conn_id: 01M6ZM07Y12Q61G2GYYXJV6C49
request: 0
stream_id: 0
probe_id: k3x9q2mz7a
$ curl -sI https://k3x9q2mz7a.dns-monitor.tmsoft.com.br/p/k3x9q2mz7a/ | grep -i alt-svc
alt-svc: h3=":443"; ma=60
$ dig +short @vps602.tmsoft.com.br k3x9q2mz7a.dns-monitor.tmsoft.com.br TYPE65
\# 41 0001000001000602683302683200040004ACE918550006001026003C 0D00000000F03C93FFFE268FD9
```

O registro HTTPS em hex é `priority 1`, alvo `.`, `alpn="h3,h2"`, `ipv4hint=172.233.24.85` e `ipv6hint`
(o `dig` 9.10 não decodifica o tipo 65; versões novas mostram os campos).

## O que o registro traz

Uma conexão QUIC aparece com `l4: "udp"` e `proto: "quic/h3"` (ou `quic` quando houve Initial mas não h3: versão
desconhecida, handshake falho, outro ALPN). O `tls` do registro é o ClientHello do Initial, mas o `proto` não
ganha o prefixo `tls/`. O campo `http3`:

| Campo | Conteúdo |
| --- | --- |
| `version` | versão QUIC do primeiro Initial, em hex (`00000001` = v1, `6b3343cf` = v2) |
| `dcid_hex`, `scid_hex` | connection IDs de destino e de origem do primeiro Initial |
| `token_len`, `token_hex` | token do Initial (o espelho não usa Retry, então costuma vir vazio) |
| `initial_length`, `initial_packet_number` | campo Length e número do primeiro pacote Initial |
| `initial_datagram_size`, `padded_to_1200` | tamanho do datagrama e se o cliente completou até 1200 bytes |
| `coalesced_packets` | quantos pacotes QUIC vieram no primeiro datagrama |
| `client_hello_datagrams` | quantos datagramas Initial foram precisos para o ClientHello (2 com ML-KEM, por exemplo) |
| `initial_frames` | tipos de frame dos Initials até o ClientHello completo, na ordem (`CRYPTO`, `PADDING`, `PING`…) |
| `transport_params` | `[id, nome, valor_hex]` na ordem recebida, GREASE incluído (nome `GREASE`) |
| `client_hello` | o ClientHello decifrado, no mesmo formato do `tls` do TCP; `ja4` começa com `q` |
| `h3_settings` | `[id, valor]` do SETTINGS do cliente, na ordem |
| `close` | fim visto pelo web: `by`, `how` (`connection_close`, `application_close`, `idle_timeout`, `stateless_reset`, `handshake_failed`), `error_code`, `reason`; `null` enquanto aberta |
| `requests` | uma entrada por requisição (`HTTP3Request`) |

Cada `HTTP3Request` traz `stream_id`, `pseudo_order` (ordem dos pseudo-cabeçalhos), `fields` na ordem com a
**representação QPACK** de cada linha, `ja4h`, `body_len` (bytes de DATA recebidos), `status` e `controls`.
`QPACKField`:

| Campo | Conteúdo |
| --- | --- |
| `name`, `value` | campo decodificado |
| `repr` | `indexed`, `indexed-post-base`, `literal-name-ref`, `literal-post-base-name-ref` ou `literal` (RFC 9204 4.5) |
| `static` | referência à tabela estática (`true`) ou dinâmica (`false`) |
| `index` | índice na tabela, quando houver |
| `never_indexed` | bit N das representações literais |
| `huffman_name`, `huffman_value` | se o nome/valor vieram em Huffman |

O servidor anuncia `QPACK_MAX_TABLE_CAPACITY = 0`, então clientes corretos não usam a tabela dinâmica; uma
referência dinâmica aparece com `static: false` e sem valor resolvido.

Trecho real do registro da conexão acima (listas encurtadas):

```console
$ curl -s https://vps602.tmsoft.com.br:9000/api/v1/connections/01M6ZM07Y12Q61G2GYYXJV6C49 | jq '{proto, l4, close,
    http3: (.http3 | {version, dcid_hex, token_len, initial_datagram_size, padded_to_1200, coalesced_packets,
    client_hello_datagrams, initial_frames: .initial_frames[0:5], transport_params: .transport_params[0:3],
    ja4: .client_hello.ja4, negotiated: .client_hello.negotiated, h3_settings, close,
    request: (.requests[0] | {stream_id, pseudo_order, field: .fields[2], ja4h, status})})}'
{
  "proto": "quic/h3",
  "l4": "udp",
  "close": { "by": "client", "how": "quic_close", "idle_before_close_ms": null, "half_close": false },
  "http3": {
    "version": "00000001",
    "dcid_hex": "c971f00d583474c033b5128bc61a219e086889eb",
    "token_len": 0,
    "initial_datagram_size": 1200,
    "padded_to_1200": true,
    "coalesced_packets": 1,
    "client_hello_datagrams": 2,
    "initial_frames": ["CRYPTO", "PING", "CRYPTO", "CRYPTO", "PADDING"],
    "transport_params": [
      [15, "initial_source_connection_id", "e0044b096db5565dcafc8091e9dec57717ebeec2"],
      [5, "initial_max_stream_data_bidi_local", "80008000"],
      [6, "initial_max_stream_data_bidi_remote", "80008000"]
    ],
    "ja4": "q13d0311h3_55b375c5d22e_df5ee7f3ca36",
    "negotiated": { "alpn": "h3", "cipher": "TLS_AES_128_GCM_SHA256", "group": "X25519MLKEM768",
                    "resumed": false, "version": "TLS 1.3" },
    "h3_settings": [[6, 4611686018427388000], [1, 0], [7, 0]],
    "close": { "by": "client", "error_code": 0, "how": "connection_close", "reason": "" },
    "request": {
      "stream_id": 0,
      "pseudo_order": [":method", ":scheme", ":authority", ":path"],
      "field": { "name": ":authority", "value": "k3x9q2mz7a.dns-monitor.tmsoft.com.br", "repr": "literal-name-ref",
                 "static": true, "index": 0, "never_indexed": false, "huffman_name": null, "huffman_value": true },
      "ja4h": "ge30nn020000_5594a17e7e7e_000000000000_000000000000",
      "status": 200
    }
  }
}
```

O ClientHello com ML-KEM (`X25519MLKEM768`) não coube num datagrama: `client_hello_datagrams: 2`. Os valores dos
parâmetros de transporte vêm em hex como estão no fio (varint QUIC: `80008000` = 32768).

**Atenção a inteiros grandes**: valores de SETTINGS e de parâmetros podem chegar a 2^62-1. Em JavaScript
(`JSON.parse`) e em `jq` antigos (antes do 1.7), números acima de 2^53 perdem precisão. A API devolve o
inteiro exato (no exemplo acima o curl mandou `SETTINGS_MAX_FIELD_SECTION_SIZE = 4611686018427387903`); quem lê em
JavaScript precisa de um parser que preserve inteiros grandes (por exemplo `JSON.parse` com `reviver` e
`context.source`, ou BigInt).

## Fim da conexão

QUIC não tem FIN. O web é a fonte da verdade sobre o fim: quando ele vê o CONNECTION_CLOSE (ou um stateless reset,
ou a ociosidade), o store fecha o registro 2 s depois com `close.how = "quic_close"` (ou `"timeout"` quando o web
informou `idle_timeout`). Uma conexão encerrada pelo cliente aparece fechada em até 3 s. O servidor não fecha por
ociosidade antes de `FS_IDLE_DEFAULT` (120 s); navegadores costumam manter a conexão QUIC aberta por bastante tempo,
então o `wait` do probe pode voltar no prazo com `all_closed: false`.

As requisições não esperam o fim da conexão: cada uma vira um evento `http.request` (e entra no registro) quando a
resposta termina, como no h2.

## Controles de resposta em h3

Valem `status`, `size`, `delay_head`, `delay_body`, `h=`, `alt_svc` e `date`. Os demais (`ver`, `frame`, `conn`, `ka`,
`close`, `rst`, `idle`, `hsize`, `continue`, `upgrade`) respondem **400** com explicação, registrado. Detalhes em
[probes.md](probes.md#controles-de-resposta-pidr).

## Limitações conhecidas

- Sem 0-RTT, sem migração de conexão e sem Retry (spec 011 RF-06).
- O QUIC do espelho roda sem GSO, GRO e ECN, para a captura ver os datagramas como estão no fio (ADR 0019).
- Uma conexão QUIC nova na mesma 5-tupla depois de um `close` (DCID novo) vira um registro novo.
