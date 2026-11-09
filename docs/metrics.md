# Métricas (`/metrics`)

Derivado da [spec 004](../specs/004-store-e-api.md) (RF-10 e "Métricas"). O store expõe as métricas no formato
Prometheus **só na porta 9001** (HTTP), em `http://vps602.tmsoft.com.br:9001/metrics`. Na 9000 a rota não existe.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: finger-sniffer
    scrape_interval: 15s
    static_configs:
      - targets: ["vps602.tmsoft.com.br:9001"]
```

## Métricas dos serviços (heartbeat)

Os serviços (capture, web, raw, dns e o próprio store) mandam um heartbeat a cada 5 s com seus contadores; o store
os republica como `fs_<métrica>{service="<svc>"}`, com o valor do último heartbeat recebido. Nomes terminados em
`_total` são contadores; os demais, gauges.

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_service_up{service}` | gauge | 1 enquanto chegam heartbeats; 0 depois de 15 s sem heartbeat |
| `fs_service_info{service,version}` | gauge | sempre 1; a versão (commit) que cada serviço roda |
| `fs_<métrica>{service}` | contador ou gauge | contadores do heartbeat (lista abaixo) |

Publicados hoje no heartbeat (o conjunto depende de cada serviço e aparece também em `services.<svc>.metrics` do
`/api/v1/health`; um contador só aparece depois do primeiro uso desde o último reinício do serviço, por exemplo os
de WebSocket; o capture publica os seus zerados desde a partida):

| Serviço | Métricas |
| --- | --- |
| capture | `fs_capture_kernel_packets_total`, `fs_capture_kernel_drops_total`, `fs_capture_packets_in_total`, `fs_capture_packets_out_total`, `fs_capture_batches_total`, `fs_capture_queue_freezes_total`, `fs_capture_max_frame_bytes`, `fs_capture_filtered_userspace_total`, `fs_capture_offload_suspect_total`, `fs_capture_truncated_total`, `fs_dropped_events_total` (detalhes [abaixo](#capture)) |
| web | `fs_web_connections_active`, `fs_web_connections_total`, `fs_web_http1_requests_total`, `fs_web_http2_connections_total`, `fs_web_http2_streams_total`, `fs_web_http3_connections_total`, `fs_web_http3_requests_total`, `fs_web_websocket_connections_total`, `fs_web_websocket_frames_total`, `fs_web_h3_listening` (1 com o listener UDP 443 de pé) |
| raw | `fs_raw_sessions_total`, `fs_raw_active_sessions` |
| dns | `fs_dns_queries_udp_total`, `fs_dns_queries_tcp_total` |
| store | `fs_store_app_events_total`, `fs_store_packets_total`, `fs_store_late_packets_total` (pacote tardio, como o ACK ou o RST depois do FIN, anexado ao pcap e ao registro já gravado, TCP ou QUIC, até 2 s depois do fim), `fs_store_raw_stream_bytes_total`, `fs_store_conn_id_requests_total`, `fs_store_pending_events_total` (evento de aplicação que chegou antes dos pacotes da conexão e esperou), `fs_store_event_only_connections_total` (conexão criada só por eventos, sem pacotes: capture fora do ar ou atrasado), `fs_store_bad_events_total` (evento sem 5-tupla, descartado) |
| todos que publicam no NATS | `fs_published_events_total`, `fs_buffered_events`, `fs_buffered_bytes` (buffer do produtor) |
| host (pelo store) | `fs_host_syncookies_sent` |

### capture

O heartbeat é um mapa plano, sem rótulos: o sentido vai no nome (`_in_total`/`_out_total`), e não num rótulo
`{dir}` (spec 003, ADR 0023). Todos os contadores abaixo existem com 0 desde a partida do capture, então uma
série ausente quer dizer capture fora do ar, não "nada aconteceu".

| Métrica | Conteúdo |
| --- | --- |
| `fs_capture_packets_in_total`, `fs_capture_packets_out_total` | pacotes publicados, do cliente para o espelho (`in`) e do espelho para o cliente (`out`) |
| `fs_capture_kernel_packets_total`, `fs_capture_kernel_drops_total` | estatísticas do socket AF_PACKET: pacotes vistos e perdidos pelo kernel (spec 003 RF-07) |
| `fs_capture_batches_total` | lotes FSPB publicados no NATS (fecham em 5 ms, 256 pacotes ou 900 KiB) |
| `fs_capture_queue_freezes_total` | vezes que o anel TPACKET_V3 encheu e o kernel congelou a fila (estatística do socket; vem junto com perdas) |
| `fs_capture_max_frame_bytes` | maior frame visto desde a partida (gauge); acima de MTU + 14 indica offload de agregação ligado |
| `fs_capture_filtered_userspace_total` | pacotes de portas excluídas (API, ssh, NATS) que passaram pelo BPF e foram descartados na conferência em espaço de usuário; deve ficar em 0 |
| `fs_capture_offload_suspect_total` | pacotes marcados `offload_suspect` (frame maior que MTU + 14, ou qualquer pacote enquanto um offload de agregação estiver ligado, spec 003 RF-06) |
| `fs_capture_truncated_total` | pacotes cortados pelo `FS_CAPTURE_SNAPLEN` (padrão 65535) e marcados como truncados |
| `fs_dropped_events_total` | eventos descartados pelo buffer do produtor com o NATS fora do ar (acima de 30 s ou 16 MiB, spec 003 RF-05) |

```console
$ curl -s http://vps602.tmsoft.com.br:9001/metrics | grep -E '^fs_(capture|dropped)'
fs_capture_batches_total{service="capture"} 132
fs_capture_filtered_userspace_total{service="capture"} 0
fs_capture_kernel_drops_total{service="capture"} 0
fs_capture_kernel_packets_total{service="capture"} 274
fs_capture_max_frame_bytes{service="capture"} 1474
fs_capture_offload_suspect_total{service="capture"} 0
fs_capture_packets_in_total{service="capture"} 147
fs_capture_packets_out_total{service="capture"} 127
fs_capture_queue_freezes_total{service="capture"} 0
fs_capture_truncated_total{service="capture"} 0
fs_dropped_events_total{service="capture"} 0
```

## Métricas do store

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_store_events_ingested_total{subject}` | contador | eventos consumidos do JetStream, por subject |
| `fs_store_ingest_lag_seconds` | histograma | do `ts` do envelope até o commit no SQLite |
| `fs_store_connections_open` | gauge | conexões abertas agora |
| `fs_store_connections_total{l4,proto}` | contador | conexões registradas, por L4 e pilha |
| `fs_store_connections_degraded_total` | contador | conexões gravadas em modo degradado (sem pcap nem bytes crus) |
| `fs_store_stray_packets_total` | contador | pacotes avulsos |
| `fs_store_dns_queries_total` | contador | consultas DNS gravadas |
| `fs_store_purged_total{reason}` | contador | registros expurgados, `reason` = `age` (retenção) ou `size` (teto do banco) |
| `fs_store_db_bytes` | gauge | tamanho do banco SQLite |
| `fs_store_connections` | gauge | conexões guardadas no banco (abertas e fechadas, dentro da retenção) |
| `fs_store_record_ready_seconds{reason}` | histograma | do fim da conexão até o registro completo gravado; `reason` = `close` (TCP com FIN/RST, meta p95 ≤ 500 ms), `quic_close` (QUIC encerrado, visto pelo web, mesma meta) ou `idle` (fechada por ociosidade, fora da meta); ver [abaixo](#tempo-até-o-registro) |
| `fs_store_live_clients{transport}` | gauge | clientes de tempo real, `transport` = `sse` ou `ws` |
| `fs_store_live_events_total{kind}` | contador | eventos ao vivo emitidos, por tipo |
| `fs_store_live_dropped_total` | contador | eventos descartados para clientes lentos (ADR 0020) |
| `fs_store_live_delay_seconds` | histograma | do `ts` do evento de origem até o envio ao cliente (meta: < 1 s) |
| `fs_store_api_requests_total{route,code}` | contador | requisições da API por rota e código |
| `fs_store_api_request_duration_seconds{route}` | histograma | duração das requisições da API (meta p95 < 100 ms) |

`route` é o padrão da rota, nunca o caminho com IDs: por exemplo `GET /api/v1/connections/{conn_id}`.

Trecho real:

```console
$ curl -s http://vps602.tmsoft.com.br:9001/metrics | grep -E '^fs_(service_up|store_connections_total|store_live_clients)'
fs_service_up{service="capture"} 1
fs_service_up{service="dns"} 1
fs_service_up{service="raw"} 1
fs_service_up{service="store"} 1
fs_service_up{service="web"} 1
fs_store_connections_total{l4="tcp",proto="tls"} 11
fs_store_connections_total{l4="tcp",proto="tls/h2"} 2
fs_store_connections_total{l4="tcp",proto="tls/http1.1"} 1
fs_store_connections_total{l4="udp",proto="quic/h3"} 7
fs_store_connections_total{l4="udp",proto="udp"} 2
fs_store_live_clients{transport="sse"} 0
fs_store_live_clients{transport="ws"} 1
$ curl -s -o /dev/null -w '%{http_code}\n' https://vps602.tmsoft.com.br:9000/metrics
404
```

`proto` no rótulo é o do momento da gravação da conexão (spec 004), por isso aparecem `tls` (handshake TLS sem
requisição HTTP, comum em varreduras) e `udp` (fluxo UDP sem camada de aplicação).

## Tempo até o registro

`fs_store_record_ready_seconds` mede, para cada conexão finalizada, o tempo entre o fim dela (o último pacote, ou o
CONNECTION_CLOSE do QUIC se vier depois) e o commit do registro completo. O rótulo `reason` separa três casos:

| `reason` | Quando | Tempo esperado |
| --- | --- | --- |
| `close` | TCP com RST, ou FIN dos dois lados | RST e FIN com o ACK final: na hora (mais o lote do ingest); FIN sem o ACK final: `FS_TCP_CLOSE_GRACE` |
| `quic_close` | QUIC com CONNECTION_CLOSE, stateless reset ou fim por ociosidade informado pelo web | `FS_TCP_CLOSE_GRACE` contado do evento do web |
| `idle` | fluxo sem fim visto, fechado pelo store por falta de pacotes | o próprio prazo de ociosidade: `FS_IDLE_DEFAULT` + 30 s no TCP (150 s), 30 s no UDP |

`FS_TCP_CLOSE_GRACE` é a folga para os últimos pacotes do capture: padrão **100 ms**, aceita de 0 a 500 ms (fora
disso o store não sobe, spec 004 RNF-01). Pacotes que chegam depois do registro gravado (ACK final atrasado, RST
depois do FIN, último datagrama QUIC) não viram conexão nova: são anexados ao registro e ao pcap por até 2 s e
contados em `fs_store_late_packets_total`. Antes da task 077 o TCP esperava 1 s fixo; antes da task 090 o QUIC
esperava 2 s.

A meta de registro p95 ≤ 500 ms (spec 000 RNF-04, ADR
[0026](../specs/decisions/0026-fechamento-rapido-e-ajustes-da-release.md)) é lida em `close` e `quic_close`, a mesma
para TCP e QUIC; na carga oficial da `v0.1.0` o registro QUIC ficou em p95 252 ms. `idle` fica fora da meta: o
atraso é o prazo de ociosidade (+ 30 s), por definição.

Na vps602 (commit `6facb2c`, `FS_TCP_CLOSE_GRACE=100ms`), em 9/11/2026:

```console
$ curl -s http://vps602.tmsoft.com.br:9001/metrics | grep -E '^fs_store_record_ready_seconds_(sum|count)'
fs_store_record_ready_seconds_sum{reason="close"} 5.708734011000001
fs_store_record_ready_seconds_count{reason="close"} 87
fs_store_record_ready_seconds_sum{reason="idle"} 120.444764897
fs_store_record_ready_seconds_count{reason="idle"} 4
fs_store_record_ready_seconds_sum{reason="quic_close"} 2.809077488
fs_store_record_ready_seconds_count{reason="quic_close"} 21
```

Média de 66 ms no `close` (86 de 87 abaixo de 158 ms, todos abaixo de 316 ms), 134 ms no `quic_close` (19 de 21
abaixo de 158 ms, todos abaixo de 316 ms) e 30 s no `idle` (fluxos UDP). Os buckets são exponenciais de 10 ms a
10 s.

## Consultas úteis

```promql
# serviço fora do ar
fs_service_up == 0

# versões diferentes entre serviços (deploy pela metade)
count(count by (version) (fs_service_info)) > 1

# perdas no kernel (AF_PACKET) nos últimos 5 min
increase(fs_capture_kernel_drops_total[5m]) > 0

# offload de agregação ligado ou pacote truncado pelo snaplen
increase(fs_capture_offload_suspect_total[5m]) > 0 or increase(fs_capture_truncated_total[5m]) > 0

# eventos perdidos com o NATS fora do ar
increase(fs_dropped_events_total[5m]) > 0

# p95 do atraso do feed ao vivo
histogram_quantile(0.95, sum by (le) (rate(fs_store_live_delay_seconds_bucket[5m])))

# p95 da API por rota
histogram_quantile(0.95, sum by (le, route) (rate(fs_store_api_request_duration_seconds_bucket[5m])))

# registro pronto depois do fim da conexão (p95 por motivo; meta 500 ms no close)
histogram_quantile(0.95, sum by (le, reason) (rate(fs_store_record_ready_seconds_bucket{reason=~"close|quic_close"}[5m])))
```
