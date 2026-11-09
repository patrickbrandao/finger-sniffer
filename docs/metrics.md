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

Os serviços capture, web, raw e dns mandam um heartbeat a cada 5 s com seus contadores; o store os republica como
gauges `fs_<métrica>{service="<svc>"}`, com o valor do último heartbeat recebido.

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_service_up{service}` | gauge | 1 enquanto chegam heartbeats; 0 depois de 15 s sem heartbeat |
| `fs_service_info{service,version}` | gauge | sempre 1; a versão (commit) que cada serviço roda |
| `fs_<métrica>{service}` | gauge | contadores do heartbeat, por exemplo `fs_capture_kernel_drops_total`, `fs_capture_packets_in_total`, `fs_web_connections_active`, `fs_web_http2_streams_total`, `fs_raw_sessions_total`, `fs_dns_queries_udp_total`, `fs_buffered_events` |

O conjunto exato de `fs_<métrica>` depende do que cada serviço publica no heartbeat; o mesmo mapa aparece em
`services.<svc>.metrics` do `/api/v1/health`.

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
| `fs_store_record_ready_seconds` | histograma | do fim da conexão até o registro completo gravado (meta: ≤ 500 ms) |
| `fs_store_live_clients{transport}` | gauge | clientes de tempo real, `transport` = `sse` ou `ws` |
| `fs_store_live_events_total{kind}` | contador | eventos ao vivo emitidos, por tipo |
| `fs_store_live_dropped_total` | contador | eventos descartados para clientes lentos (ADR 0020) |
| `fs_store_live_delay_seconds` | histograma | do `ts` do evento de origem até o envio ao cliente (meta: < 1 s) |
| `fs_store_api_requests_total{route,code}` | contador | requisições da API por rota e código |
| `fs_store_api_request_duration_seconds{route}` | histograma | duração das requisições da API (meta p95 < 100 ms) |

`route` é o padrão da rota, nunca o caminho com IDs: por exemplo `GET /api/v1/connections/{conn_id}`.

<!-- METRICS_EXAMPLE -->

## Consultas úteis

```promql
# serviço fora do ar
fs_service_up == 0

# versões diferentes entre serviços (deploy pela metade)
count(count by (version) (fs_service_info)) > 1

# perdas no kernel (AF_PACKET) nos últimos 5 min
delta(fs_capture_kernel_drops_total[5m]) > 0

# p95 do atraso do feed ao vivo
histogram_quantile(0.95, sum by (le) (rate(fs_store_live_delay_seconds_bucket[5m])))

# p95 da API por rota
histogram_quantile(0.95, sum by (le, route) (rate(fs_store_api_request_duration_seconds_bucket[5m])))

# registro pronto depois do fim da conexão (p99)
histogram_quantile(0.99, sum by (le) (rate(fs_store_record_ready_seconds_bucket[5m])))
```
