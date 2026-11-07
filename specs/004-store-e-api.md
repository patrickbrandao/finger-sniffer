# 004 — Serviço store e API

Status: aprovada
Depende de: 001, 003, 013

## Contexto
Dono de todos os registros. Consome o NATS, correlaciona pacotes e eventos de aplicação no mesmo `conn_id`,
calcula a análise IP/TCP (spec 013), monta o pcap de cada conexão, guarda em SQLite com retenção curta e serve a
API JSON, o tempo real e as métricas agregadas em portas não capturadas.

## Requisitos
- RF-01: consumidor durável `store` do stream JetStream `FS_EVENTS`; cria/ajusta o stream no start
  (`max_age` 60 s, `max_bytes` 64 MiB).
- RF-02: correlação por 5-tupla + janela de tempo → `conn_id` (ULID); QUIC por 4-tupla + DCID; associação ao
  probe assim que o ID aparecer (SNI, Host, caminho, DNS, `PROBE`).
- RF-03: pacotes que não formam conexão (SYN sem resposta, RST avulso, ICMP, UDP solto) ficam como "pacotes
  avulsos", consultáveis por janela de tempo.
- RF-04: pcap por conexão (dois sentidos), teto `FS_PCAP_MAX_BYTES_PER_CONN` (16 MiB); acima disso guarda só os
  cabeçalhos dos pacotes e marca `pcap_truncated`.
- RF-05: persistência em SQLite (modernc, WAL) — registros, índices e **BLOBs** (pcap, bytes crus de cada sentido).
  Schema em [database/sqlite/migrations/](../database/sqlite/migrations/) aplicado por goose embutido no start.
- RF-06: retenção `FS_RETENTION` (10 min) e teto `FS_STORE_MAX_BYTES` (2 GiB): o primeiro atingido expurga o mais
  antigo, em lotes, com `incremental_vacuum`.
- RF-07: API em 9000 (HTTPS, certificado de `FS_CERT_DIR` com recarga a quente) e 9001 (HTTP), CORS `*`, sem
  autenticação, JSON, nomes em inglês.
- RF-08: tempo real: SSE `GET /api/v1/stream` e WebSocket `GET /api/v1/ws`, filtros `probe`, `src_ip`,
  `dst_port`, `kind`; sem filtro = feed global.
- RF-09: health agregado: heartbeat de cada serviço (5 s; `down` após 15 s sem heartbeat), versões
  (acusa desencontro), sysctls e offloads efetivos, estado do certificado, uso de disco/SQLite, NTP.
- RF-10: `/metrics` (Prometheus) em 9001 com as métricas do store e as recebidas no heartbeat dos demais.
- RF-11: modo degradado (RNF-01): acima de 200 conexões simultâneas ou 50 novas/s, mantém o resumo, para de
  guardar pcap/bytes crus das novas conexões e marca `degraded=true`.
- RNF-01: `GET` de conexão/probe p95 < 100 ms; registro completo ≤ 500 ms após o fim; evento ao vivo < 1 s.

## Comportamento
- Fim de conexão: FIN dos dois lados, RST, ou ociosidade > `idle` + 30 s sem pacotes.
- Long-poll `GET /api/v1/probes/{id}?wait=10s`: responde quando todas as conexões do probe estiverem fechadas ou no
  fim do prazo (máx 60 s).
- Reinício: o índice vem do SQLite; o consumidor durável retoma do último ack.

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

Consome: `fs.v1.>`. Publica: nada além do push para clientes da API.

## Dados
Tabelas (definidas na migration 0001): `connections`, `packets` (BLOB por pacote ou lote), `pcaps` (BLOB),
`app_events`, `raw_streams` (BLOB), `dns_queries`, `probes`, `stray_packets`. Retenção conforme RF-06.

## Critérios de aceite
- [ ] Uma sondagem por probe aparece completa em `GET /api/v1/probes/{id}` em ≤ 500 ms após o fechamento.
- [ ] Após 10 min sem tráfego, `GET` do mesmo probe devolve 404.
- [ ] Com 2 GiB atingidos, o mais antigo é expurgado e o banco não passa de 2,2 GiB.
- [ ] O pcap baixado abre no tshark e mostra os dois sentidos.
- [ ] Respostas de todas as rotas validam contra o openapi.yaml (teste de contrato).
- [ ] Parar o capture faz `/api/v1/health` mostrar `capture: down` em ≤ 15 s.

## Fora de escopo
- Autenticação, paginação por cursor (só `limit`), histórico além da retenção.

## Decisões relacionadas
- specs/decisions/0005-sqlite-com-blobs.md
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0012-retencao-curta.md
- specs/decisions/0004-pacotes-pelo-nats.md
