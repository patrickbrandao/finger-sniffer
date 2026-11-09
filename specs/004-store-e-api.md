# 004 — Serviço store e API

Status: aprovada
Depende de: 001, 003, 013

## Contexto
Dono de todos os registros. Consome o NATS, correlaciona pacotes e eventos de aplicação no mesmo `conn_id`,
calcula a análise IP/TCP (spec 013), monta o pcap de cada conexão, guarda em SQLite com retenção curta e serve a
API JSON, o tempo real e as métricas agregadas em portas não capturadas.

## Requisitos
- RF-01: consumidor durável `store` do stream JetStream `FS_EVENTS`; cria/ajusta o stream no start
  (`MemoryStorage`, `max_age` 60 s, `max_bytes` 32 MiB, `DiscardOld` — ADR 0016), com a lista explícita de subjects
  de eventos da ADR 0017 (request/reply fica fora).
- RF-02: correlação por 5-tupla + janela de tempo → `conn_id` (ULID); QUIC pela 5-tupla UDP, e um Initial com
  DCID novo depois do fim da conexão QUIC anterior abre conexão nova (ADR 0019); associação ao probe assim que o
  ID aparecer (SNI, Host, caminho, DNS, `PROBE`).
- RF-02a: responde o request/reply `fs.v1.store.conn_id` (ADR 0017): devolve o ID da conexão aberta com a 5-tupla
  ou reserva um ULID por 30 s para a próxima conexão criada pelos pacotes com essa 5-tupla.
- RF-03: pacotes que não formam conexão (SYN sem resposta, RST avulso, ICMP, UDP solto) ficam como "pacotes
  avulsos", consultáveis por janela de tempo. Regra: fluxo TCP que nunca completou o handshake (sem SYN-ACK — inclui
  SYN recusado com RST e varreduras) e fluxo UDP sem nenhuma resposta viram avulsos quando terminam.
- RF-04: pcap por conexão (dois sentidos), teto `FS_PCAP_MAX_BYTES_PER_CONN` (16 MiB); acima disso guarda só os
  cabeçalhos dos pacotes e marca `pcap_truncated`.
- RF-05: persistência em SQLite (modernc, WAL) — registros, índices e **BLOBs** (pcap, bytes crus de cada sentido).
  Schema em [database/sqlite/migrations/](../database/sqlite/migrations/) aplicado por goose embutido no start.
- RF-06: retenção `FS_RETENTION` (10 min) e teto `FS_STORE_MAX_BYTES` (2 GiB): o primeiro atingido expurga o mais
  antigo, em lotes, com `incremental_vacuum`.
- RF-07: API em 9000 (HTTPS, certificado de `FS_CERT_DIR` com recarga a quente por `pkg/certs`, spec 015 RF-04)
  e 9001 (HTTP), CORS `*`, sem autenticação, JSON, nomes em inglês.
- RF-08: tempo real: SSE `GET /api/v1/stream` e WebSocket `GET /api/v1/ws`, filtros `probe`, `src_ip`,
  `dst_port`, `kind`; sem filtro = feed global. Hub em memória após o commit, sem replay, fila por cliente
  `FS_LIVE_BUFFER` (1024) com descarte e `stream.dropped`, até `FS_LIVE_MAX_CLIENTS` (64) clientes (ADR 0020).
  Detalhes em "Tempo real".
- RF-09: health agregado: heartbeat de cada serviço (5 s; `down` após 15 s sem heartbeat), versões
  (acusa desencontro), sysctls e offloads efetivos, estado do certificado, uso de disco/SQLite, NTP.
- RF-10: `/metrics` (Prometheus, `prometheus/client_golang`) em 9001 com as métricas próprias do store (lista em
  "Métricas") e as recebidas no heartbeat dos demais.
- RF-11: modo degradado (RNF-01): acima de 200 conexões simultâneas ou 50 novas/s, mantém o resumo, para de
  guardar pcap/bytes crus das novas conexões e marca `degraded=true`.
- RNF-01: `GET` de conexão/probe p95 < 100 ms; registro completo ≤ 500 ms após o fim (p95); evento ao vivo < 1 s
  (p99), medidos como na ADR 0022. Referência da F4 (task 060): evento isolado 430–570 ms do `ts` ao feed; a
  150 req/s, p95 ~0,6 s e máximo ~1,1 s.

## Comportamento
- Fim de conexão: FIN dos dois lados, RST, ou ociosidade > `idle` + 30 s sem pacotes.
- Eventos de aplicação (`fs.v1.web.*`, `fs.v1.raw.*`, `fs.v1.dns.query`) são associados pela `flow` do envelope à
  conexão com a mesma 5-tupla cujo intervalo contém o `ts` do evento (com folga de 2 s antes do início, porque o
  evento pode chegar antes do lote de pacotes do SYN):
  - evento sem conexão ainda: espera até 2 s numa fila pendente; depois disso, cria a conexão só com os dados do
    evento (sem pacotes: `times.syn` nulo, sem `ip`/`tcp`, sem pcap) — é o caso do capture fora do ar;
  - evento de conexão já finalizada (até `FS_RETENTION`): atualiza o registro gravado;
  - todo evento é guardado em `app_events`; os fluxos (`stream.bytes`, `raw.read`) vão para `raw_streams`.
- Montagem do registro a partir dos eventos:

| Evento | Campo do registro | Regra |
| --- | --- | --- |
| `web.tls.client_hello` | `tls` (ClientHello) | substitui; `client_hello_segments` calculado pelo store a partir dos segmentos do cliente que cobrem o ClientHello |
| `web.tls.handshake` | `tls.negotiated`, `tls.handshake_ms`, `tls.alerts`, `times.tls_done` | funde no `tls` |
| `web.http1.request` | `http[]` | acrescenta, ordenado por `index`; `requests` = total h1+h2+h3 |
| `web.http2.connection` | `http2` (nível de conexão) | a última versão vale; preserva `streams` |
| `web.http2.stream` | `http2.streams[]` | acrescenta ou substitui por `stream_id` |
| `web.http3.connection` | `http3` (nível de conexão), `tls` (= `http3.client_hello`), `times.tls_done` | a última versão vale; preserva `requests`; com `close` preenchido, fecha a conexão 2 s depois (ADR 0019) |
| `web.http3.request` | `http3.requests[]` | acrescenta ou substitui por `stream_id`; conta em `requests` |
| `web.websocket.frame` | `websocket` | o primeiro frame com `upgrade` preenche `over/path/extensions/subprotocol`; frames acrescentados (teto da ADR 0018, `frames_truncated`); `close` preenche `websocket.close` |
| `raw.session`, `web.raw.session` | `raw` | substitui |
| `web.stream.bytes`, `raw.read` | `raw_streams`, `raw_truncated` | grava o pedaço pelo `offset`; `truncated` marca o sentido |
| `dns.query` | tabela `dns_queries` | `conn_id` preenchido quando `proto=tcp` e houver conexão |

- `proto` da conexão, derivado dos eventos: `tls/` como prefixo quando houve `client_hello`; depois `http1.0` ou
  `http1.1` (versão da primeira requisição), `h2` (ALPN) ou `h2c` (prior knowledge/Upgrade), `ws` acrescentado como
  sufixo quando houve Upgrade (ex. `tls/http1.1/ws`), `raw` (raw), `raw/unknown` (web sem protocolo reconhecido),
  `dns` (fluxo da porta 53 com `dns.query`), `quic/h3` (`http3.connection` com ALPN `h3` negociado) ou `quic`
  (Initial analisado sem h3: versão desconhecida, handshake falho, outro ALPN). Sem evento de aplicação: `tcp` ou
  `udp`.
- Fim de conexão QUIC (ADR 0019): `http3.connection` com `close` → `end` 2 s depois, `close.by` do web,
  `close.how = quic_close` (ou `timeout` quando o web informa `idle_timeout`). O `tls` do registro QUIC é o ClientHello do Initial, mas
  o `proto` não ganha o prefixo `tls/`. Fluxo UDP com evento h3 e sem
  `close` usa ociosidade `FS_IDLE_DEFAULT` + 30 s, não a de UDP.
- `probe_id` da conexão: o primeiro `probe_id` não nulo dos envelopes da conexão; a tabela `probes` é atualizada
  (`first_seen`/`last_seen`) a cada conexão ou consulta DNS com probe.
- Long-poll `GET /api/v1/probes/{id}?wait=10s` (máx 60 s): responde quando o probe tem **ao menos uma conexão** e
  todas estão fechadas, ou no fim do prazo. Só consultas DNS (ou nada) não bastam: a espera continua até a
  primeira conexão aparecer e fechar (ex.: o xProxy resolveu o nome, mas a conexão ainda não chegou). No fim do
  prazo: 200 com o estado atual (`all_closed` = nenhuma conexão aberta) ou 404 se o probe não tem nada. Sem
  `wait`, responde na hora como antes.
- Reinício: o índice vem do SQLite; o consumidor durável retoma do último ack.

### Tempo real (RF-08, ADR 0020)
- Eventos, emitidos depois do commit do lote que os produziu:

| `kind` | Quando | `data` |
| --- | --- | --- |
| `connection.opened` | conexão criada (pacotes ou só eventos) | `ConnectionSummary` |
| `connection.updated` | camada de aplicação fundida no registro aberto; no máximo 1 por conexão a cada 250 ms | `ConnectionSummary` |
| `connection.closed` | registro finalizado e gravado | `ConnectionSummary` |
| `http.request` | cada `http1.request`, `http2.stream`, `http3.request` | `HTTP1Request`, `HTTP2Stream`, `HTTP3Request` |
| `dns.query` | cada consulta gravada | `DNSQuery` |
| `packet.stray` | cada pacote avulso gravado | `StrayPacket` |
| `stream.dropped` | só para o cliente que perdeu eventos, quando a fila volta a ter espaço | `LiveDropped` |

- `conn_id` e `probe_id` do envelope do `LiveEvent` preenchidos quando houver. Filtros: `probe` (= `probe_id`),
  `src_ip` (cliente; para `dns.query`, o resolvedor), `dst_port` (porta do espelho; `dns.query` = 53), `kind`
  (lista por vírgula). Filtro inválido → 400 antes do upgrade/stream.
- SSE: `event: <kind>`, `data: <JSON>`, comentário `: ping` a cada 15 s, `Cache-Control: no-store`, flush por
  evento. WS: uma mensagem de texto por evento, ping a cada 30 s, mensagens do cliente ignoradas, fecha com 1001
  no desligamento.
- Mais de `FS_LIVE_MAX_CLIENTS` clientes → 503. A latência ingest → cliente entra na métrica
  `fs_store_live_delay_seconds` (`ts` do evento de origem até o envio).

### Métricas (RF-10)
Próprias do store, além das gauges `fs_<métrica>{service=...}` recebidas no heartbeat e `fs_service_up`:
`fs_service_info{service,version}`, `fs_store_events_ingested_total{subject}`, `fs_store_ingest_lag_seconds`
(histograma: `ts` do envelope → commit), `fs_store_connections_open`, `fs_store_connections_total{l4,proto}`,
`fs_store_connections_degraded_total`, `fs_store_stray_packets_total`, `fs_store_dns_queries_total`,
`fs_store_purged_total{reason=age|size}`, `fs_store_db_bytes`, `fs_store_record_ready_seconds` (histograma: fim →
registro gravado), `fs_store_live_clients{transport=sse|ws}`, `fs_store_live_events_total{kind}`,
`fs_store_live_dropped_total`, `fs_store_live_delay_seconds` (histograma),
`fs_store_api_requests_total{route,code}` e `fs_store_api_request_duration_seconds{route}` (histograma; `route` =
padrão do mux, nunca o caminho com IDs).

## Interfaces e contratos
Contrato: [cmd/finger-sniffer-store/openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) (servido em
`/api/v1/openapi.yaml`). Rotas:

| Método e caminho | Retorno |
| --- | --- |
| `GET /api/v1/health` | `{"ok":true,"version":"...","services":{...},"host":{...}}` |
| `GET /api/v1/probes/{id}?wait=10s` | todas as conexões e consultas DNS do probe, completas |
| `GET /api/v1/connections?src_ip=&dst_port=&since=&until=&probe=&limit=` | lista resumida |
| `GET /api/v1/connections/{conn_id}` | registro completo (specs 008–013) |
| `GET /api/v1/connections/{conn_id}/pcap` | pcap da conexão (`application/vnd.tcpdump.pcap`) |
| `GET /api/v1/connections/{conn_id}/raw?dir=in\|out` | bytes de aplicação de cada sentido (`out` = o que o espelho mandou) |
| `GET /api/v1/dns?probe=&since=` | consultas DNS |
| `GET /api/v1/packets?since=&until=&src_ip=` | pacotes avulsos |
| `DELETE /api/v1/probes/{id}` | apaga o probe e suas conexões |
| `GET /api/v1/stream` | SSE |
| `GET /api/v1/ws` | WebSocket |
| `GET /api/v1/openapi.yaml` | contrato |
| `GET /metrics` (só 9001) | Prometheus |

Formato do registro (resumo; o completo está no openapi.yaml):
```json
{
  "conn_id": "01JC0X3K8V2T7Q9N4M6P1R5S8W", "probe_id": "t1a2b3c4", "proto": "tls/http1.1",
  "src": {"ip": "45.170.76.49", "port": 41234}, "dst": {"ip": "172.233.24.85", "port": 443},
  "family": 4, "l4": "tcp", "degraded": false,
  "times": {"syn": "2026-11-07T12:00:00.000000123Z", "established": "...", "first_data": "...", "end": "..."},
  "close": {"by": "client", "how": "fin", "idle_before_close_ms": 15000, "half_close": false},
  "ip": {}, "tcp": {}, "tls": {}, "http": [], "http2": {}, "http3": {}, "websocket": {}, "raw": {}
}
```

Consome: os subjects de eventos do stream (ADR 0017). Responde: `fs.v1.store.conn_id`. Publica: nada além do push
para clientes da API.

## Dados
Tabelas (migration [00001_initial.sql](../database/sqlite/migrations/00001_initial.sql)): `probes`, `connections`
(registro completo em `record_json`), `packets` (BLOB por pacote até a conexão fechar), `pcaps` (BLOB),
`app_events`, `raw_streams` (BLOB), `dns_queries`, `stray_packets`. Tabelas filhas com `ON DELETE CASCADE`
sobre `connections`, para o expurgo apagar tudo de uma vez. Retenção conforme RF-06. O store abre o banco com
`foreign_keys=ON`, `journal_mode=WAL` e `auto_vacuum=INCREMENTAL`.

## Critérios de aceite
- [ ] Uma sondagem por probe aparece completa em `GET /api/v1/probes/{id}` em ≤ 500 ms após o fechamento.
- [ ] Após 10 min sem tráfego, `GET` do mesmo probe devolve 404.
- [ ] Com 2 GiB atingidos, o mais antigo é expurgado e o banco não passa de 2,2 GiB.
- [ ] O pcap baixado abre no tshark e mostra os dois sentidos.
- [ ] Respostas de todas as rotas validam contra o openapi.yaml (teste de contrato).
- [ ] Parar o capture faz `/api/v1/health` mostrar `capture: down` em ≤ 15 s.
- [ ] `?wait=10s` num probe com só consultas DNS espera a primeira conexão e responde quando ela fecha.
- [ ] Feed global pelo `/ws` e pelo `/stream`: evento de uma requisição h1/h2/h3 chega em < 1 s; cliente que não lê
      recebe `stream.dropped` e não atrasa o ingest; 65º cliente recebe 503.
- [ ] Conexão `quic/h3` encerrada pelo cliente fecha no store em ≤ 3 s, com `close.how = quic_close`.
- [ ] `/metrics` traz as métricas da seção "Métricas" e passa no lint do `prometheus/testutil` (`GatherAndLint`).

## Fora de escopo
- Autenticação, paginação por cursor (só `limit`), histórico além da retenção.

## Decisões relacionadas
- specs/decisions/0005-sqlite-com-blobs.md
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0012-retencao-curta.md
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0017-request-reply-e-conn-id.md
- specs/decisions/0018-tamanho-dos-eventos.md
- specs/decisions/0019-http3-eventos-e-fim-quic.md
- specs/decisions/0020-tempo-real-sem-replay.md
- specs/decisions/0022-prova-do-mvp-no-espelho.md
