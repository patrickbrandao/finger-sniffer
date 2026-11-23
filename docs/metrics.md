# Métricas (`/metrics`)

Derivado da [spec 004](../specs/004-store-e-api.md) (RF-10 e "Métricas"). O store expõe as métricas no formato
Prometheus **só na porta 9001** (HTTP), em `http://finger-01.badblock.net.br:9001/metrics`. Na 9000 a rota não existe.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: finger-sniffer
    scrape_interval: 15s
    static_configs:
      - targets: ["finger-01.badblock.net.br:9001"]
```

## Métricas dos serviços (heartbeat)

Os serviços (capture, web, raw, dns, bot e o próprio store) mandam um heartbeat a cada 5 s com seus contadores; o store
os republica como `fs_<métrica>{service="<svc>"}`, com o valor do último heartbeat recebido. Nomes terminados em
`_total` são contadores; os demais, gauges.

Uma chave pode trazer rótulos no formato Prometheus, `nome{rotulo="valor",...}` (nomes de rótulo `[a-z_]+`, valores
`[A-Za-z0-9_.:/-]{1,64}`, sem `service`), e vira `fs_<nome>{service="<svc>",<rótulos>}` (ADR 0056 item 4): contador
quando o nome termina em `_total`, `_count`, `_sum` ou `_bucket`, gauge no resto. As séries `nome_bucket{le="..."}`,
`nome_sum` e `nome_count` com os mesmos demais rótulos saem juntas como o histograma `fs_<nome>` (o bucket `+Inf`
vem de `nome_count`; `le="+Inf"` não passa no conjunto de valores e é contado como inválido). O primeiro conjunto
de rótulos de um nome vence; série do mesmo nome com outros rótulos, chave malformada e o que passar de 512 chaves
num heartbeat (em ordem alfabética) são ignorados e contados em `fs_store_heartbeat_metrics_invalid_total{service}`.

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_service_up{service}` | gauge | 1 enquanto chegam heartbeats; 0 depois de 15 s sem heartbeat |
| `fs_service_info{service,version}` | gauge | sempre 1; a versão (commit) que cada serviço roda |
| `fs_<métrica>{service}` | contador ou gauge | contadores do heartbeat (lista abaixo) |
| `fs_<nome>{service,<rótulos>}` | contador, gauge ou histograma | chaves do heartbeat com rótulos |
| `fs_store_heartbeat_metrics_invalid_total{service}` | contador | chaves do heartbeat ignoradas (malformadas, rótulos em conflito ou além de 512), somadas uma vez por heartbeat |

Publicados hoje no heartbeat (o conjunto depende de cada serviço e aparece também em `services.<svc>.metrics` do
`/api/v1/health`; um contador só aparece depois do primeiro uso desde o último reinício do serviço, por exemplo os
de WebSocket; o capture publica os seus zerados desde a partida). Por isso os alertas usam `increase(...) > 0`, que não dispara
com a série ausente, e não `== 0` nem comparação com o valor anterior:

| Serviço | Métricas |
| --- | --- |
| capture | `fs_capture_kernel_packets_total`, `fs_capture_kernel_drops_total`, `fs_capture_packets_in_total`, `fs_capture_packets_out_total`, `fs_capture_batches_total`, `fs_capture_queue_freezes_total`, `fs_capture_max_frame_bytes`, `fs_capture_filtered_userspace_total`, `fs_capture_offload_suspect_total`, `fs_capture_truncated_total`, `fs_dropped_events_total` (detalhes [abaixo](#capture)) |
| web | `fs_web_connections_active`, `fs_web_connections_total`, `fs_web_http1_requests_total`, `fs_web_http2_connections_total`, `fs_web_http2_streams_total`, `fs_web_http3_connections_total`, `fs_web_http3_requests_total`, `fs_web_websocket_connections_total`, `fs_web_websocket_frames_total`, `fs_web_h3_listening`, `fs_web_h3_init_table_full_total`, `fs_web_input_budget_used_bytes`, `fs_web_input_budget_denied_total`, `fs_web_events_oversize_total`, `fs_web_events_marshal_errors_total`, `fs_web_panics_total`, `fs_web_acme_issued_total`, `fs_web_acme_failures_total` (detalhes [abaixo](#web)) |
| raw | `fs_raw_sessions_total`, `fs_raw_active_sessions`, `fs_raw_events_oversize_total`, `fs_raw_input_budget_used_bytes`, `fs_raw_input_budget_denied_total`, `fs_raw_panics_total` (detalhes [abaixo](#raw)) |
| dns | `fs_dns_queries_udp_total`, `fs_dns_queries_tcp_total`, `fs_dns_formerr_total`, `fs_dns_dropped_total`, `fs_dns_rate_limited_total` (detalhes [abaixo](#dns)) |
| store | `fs_store_app_events_total`, `fs_store_packets_total`, `fs_store_late_packets_total`, `fs_store_late_dropped_total`, `fs_store_raw_stream_bytes_total`, `fs_store_conn_id_requests_total`, `fs_store_conn_id_invalid_total`, `fs_store_pending_events_total`, `fs_store_event_only_connections_total`, `fs_store_bad_events_total`, `fs_store_bad_batches_total`, `fs_store_batch_count_mismatch_total`, `fs_store_ingest_errors_total`, `fs_store_finalize_retries_total`, `fs_store_packet_spills_total` (detalhes [abaixo](#store-heartbeat)) |
| bot | `fs_bot_verdicts_total{class,source}`, `fs_bot_auth_seconds`, `fs_bot_auth_wait_seconds`, `fs_bot_view_wait_total{missing}`, `fs_bot_auth_ja4h_total{source}`, `fs_bot_auth_fingerprint_total{kind,source}`, `fs_bot_ingest_*`, `fs_bot_conns_evicted_total{reason}`, `fs_bot_index_bytes`, `fs_bot_list_*{list}`, `fs_bot_webhook_*`, `fs_bot_keys_active`, `fs_bot_rate_limited_total`, `fs_bot_purged_total{reason}`, `fs_bot_db_bytes`, `fs_bot_agg_dropped_total`, `fs_bot_store_feed_messages_total` (detalhes [abaixo](#bot)) |
| todos que publicam no NATS | `fs_published_events_total`, `fs_dropped_events_total`, `fs_buffered_events`, `fs_buffered_bytes` (detalhes [abaixo](#produtor-nats)) |
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
$ curl -s http://finger-01.badblock.net.br:9001/metrics | grep -E '^fs_(capture|dropped)'
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

### web

| Métrica | Conteúdo |
| --- | --- |
| `fs_web_connections_active`, `fs_web_connections_total` | conexões TCP abertas agora (gauge) e aceitas desde a partida, em todas as portas do web |
| `fs_web_http1_requests_total` | requisições HTTP/1.x lidas |
| `fs_web_http2_connections_total`, `fs_web_http2_streams_total` | conexões h2 (TLS ou h2c) e streams abertos nelas |
| `fs_web_http3_connections_total`, `fs_web_http3_requests_total` | conexões QUIC/h3 aceitas e requisições h3 |
| `fs_web_websocket_connections_total`, `fs_web_websocket_frames_total` | WebSockets estabelecidos (HTTP/1.1 ou RFC 8441) e frames recebidos |
| `fs_web_h3_listening` | 1 com o listener UDP do h3 (`FS_WEB_UDP_PORTS`, 8443 no finger-01) de pé, 0 sem ele (gauge) |
| `fs_web_h3_init_table_full_total` | 5-tuplas QUIC novas que acharam cheia a tabela de Initials em análise (4096 entradas), com ou sem despejo: com despejo sai a entrada não reclamada encerrada mais antiga; sem nada para despejar, a conexão segue no h3, mas sem a análise do Initial. Sobe sob inundação de UDP forjado |
| `fs_web_input_budget_used_bytes` | bytes reservados agora do orçamento de entrada `FS_WEB_INPUT_BUDGET` (gauge; memória alocada para guardar entrada do cliente, ADRs 0033 e 0036) |
| `fs_web_input_budget_denied_total` | reservas recusadas pelo orçamento global ou pelo teto do dono (requisição, conexão, sessão): 431, 503, `H3_EXCESSIVE_LOAD` ou `fields_truncated` |
| `fs_web_events_oversize_total` | eventos acima de 900 KiB (`event.MaxEventBytes`, ADR 0018) descartados antes de publicar |
| `fs_web_panics_total` | pânicos recuperados numa goroutine de conexão ou stream; só aquela conexão fecha (ADR 0070 item 6) |
| `fs_web_events_marshal_errors_total` | eventos que falharam ao serializar, descartados |
| `fs_web_acme_issued_total` | certificados emitidos e gravados pelo ACME (spec 015) |
| `fs_web_acme_failures_total` | tentativas de emissão ou renovação que falharam (o web repete com espera crescente) |

`fs_web_input_budget_used_bytes` e `fs_web_input_budget_denied_total` existem desde a partida do web; os demais
aparecem no primeiro uso.

### raw

| Métrica | Conteúdo |
| --- | --- |
| `fs_raw_sessions_total`, `fs_raw_active_sessions` | sessões aceitas desde a partida e abertas agora (gauge), somando todas as portas cruas |
| `fs_raw_events_oversize_total` | eventos acima de 900 KiB descartados antes de publicar (ADR 0035) |
| `fs_raw_input_budget_used_bytes` | bytes reservados agora no orçamento de entrada de 64 MiB do raw (gauge, ADR 0070) |
| `fs_raw_input_budget_denied_total` | sessões fechadas antes do handshake TLS por falta de orçamento (ADR 0070 item 2) |
| `fs_raw_panics_total` | pânicos recuperados numa sessão crua; só aquela conexão fecha (ADR 0070 item 6) |

### dns

| Métrica | Conteúdo |
| --- | --- |
| `fs_dns_queries_udp_total`, `fs_dns_queries_tcp_total` | mensagens DNS recebidas por UDP e por TCP |
| `fs_dns_formerr_total` | consultas ilegíveis (cabeçalho legível, corpo não) respondidas com FORMERR |
| `fs_dns_dropped_total` | mensagens sem resposta (menos de 12 bytes ou com QR=1, que já é resposta) e conexões TCP recusadas com as 256 em uso |
| `fs_dns_rate_limited_total` | consultas UDP acima do RRL, respondidas com TC=1 sem dados para o resolvedor repetir em TCP; o TCP fica fora do RRL (ADR 0035) |

### bot

O bot ([bot.md](bot.md), spec 018 RF-12) usa as chaves com rótulos da ADR 0056 item 4. Os histogramas vão como as
séries cumulativas `nome_bucket{le="..."}`, `nome_sum` e `nome_count`, só com os limites finitos (1, 2, 5, 10, 20,
50, 100 e 200 ms): o bot **não** manda `le="+Inf"`, que o store monta de `nome_count` (ADR 0057 item 3). Os
contadores de veredito, de espera da visão e os histogramas existem com 0 desde a partida; os demais aparecem no
primeiro uso ou no primeiro ciclo do heartbeat.

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_bot_verdicts_total{class,source}` | contador | vereditos servidos; `class` = `human`, `good_bot`, `bot`, `suspect`, `unknown`; `source` = `auth` (forwardAuth), `query` (consultas por origem ou por `fs_conn_id`) ou `probe` |
| `fs_bot_auth_seconds` | histograma | duração do forwardAuth inteiro, com a espera da visão (RNF-01: p95 ≤ 10 ms e p99 ≤ 50 ms sem a espera) |
| `fs_bot_auth_wait_seconds` | histograma | só a espera da visão no forwardAuth (até `FS_BOT_VIEW_WAIT`, 100 ms), para medir o RNF-01 descontando-a |
| `fs_bot_view_wait_total{missing}` | contador | forwardAuth que terminou a espera sem uma das visões: `missing` = `tcp` (conexão do store não casada) ou `fork` (registro do traefix ainda não chegou) |
| `fs_bot_auth_ja4h_total{source}` | contador | de onde veio o JA4H do forwardAuth: `header` (`X-Traefix-Ja4h`, ou o `X-Fs-Ja4h` antigo), `ingest` (última requisição da conexão) ou `none` (ADR 0058 item 1) |
| `fs_bot_auth_fingerprint_total{kind,source}` | contador | de onde veio cada visão do veredito do forwardAuth, `kind` = `tls`, `h2`, `tcp` ou `timing`, `source` = `ingest` (registro de conexão do traefix), `store` (conexão do store casada; não existe para `timing`), `header` (`X-Traefix-Ja4`/`-Ja3`/`-H2`/`-Alpn`/`-Ja4t`/`-Ttl`/`-Timing`) ou `none` (ADRs 0062 item 4, 0063 item 5 e 0065 itens 2 e 4) |
| `fs_bot_ingest_records_total` | contador | registros do traefix aceitos pelo ingest |
| `fs_bot_ingest_dropped_total` | contador | registros recusados no ingest (inválidos ou, com chave, de site fora dela), sem rejeitar o lote |
| `fs_bot_ingest_refused_total{reason}` | contador | lotes do ingest recusados pelos limites de entrada (ADR 0073 item 2): `reason` = `busy` (503 sem vaga entre os 8 lotes simultâneos, ou os 6 da 9002), `key_concurrency` (429, 2 lotes da chave da 9002 em andamento) ou `body_timeout` (400, o corpo não chegou em 10 s) |
| `fs_bot_ingest_parse_errors_total{part}` | contador | bytes ilegíveis num registro aceito, `part` = `client_hello` ou `h2_prefix` (a visão sai com `parse_error`) |
| `fs_bot_ingest_ignored_total{type}` | contador | registros de tipo desconhecido num lote `traefix.fingerprint/v1`, ignorados sem contar como recusados (ADR 0063 item 2) |
| `fs_bot_ingest_clipped_total{field}` | contador | registros aceitos no ingest com um texto acima do teto, cortado em bytes na fronteira de UTF-8 sem recusar o registro (um por campo cortado em cada registro; ADR 0073 item 6), `field` = `method`, `http_version`, `authority`, `sni`, `entry_point`, `router`, `service`, `tls_version`, `cipher`, `alpn`, `field_names`, `cookie_names`, `field_name` (nome permitido longo: o campo sai), `field_value` ou `ja4h` (longo: tratado como ausente) |
| `fs_bot_ingest_fingerprint_mismatch_total{kind}` | contador | fingerprint pronta do traefix diferente da calculada pelo bot dos bytes crus (ou JA4T do traefix diferente do store), `kind` = `ja3`, `ja3n`, `ja4`, `ja4r`, `ja4o`, `akamai` ou `ja4t` (ADRs 0062 e 0063) |
| `fs_bot_store_feed_messages_total` | contador | mensagens `fs.v1.store.connection` recebidas do store |
| `fs_bot_conns_evicted_total{reason}` | contador | conexões despejadas do índice antes do TTL: `reason` = `count` (`FS_BOT_MAX_CONNS`, 100 000) ou `bytes` (`FS_BOT_INDEX_MAX_BYTES`, 384 MiB); o vencimento normal pelo TTL não conta |
| `fs_bot_public_conns_closed_total{reason}` | contador | conexões da 9002 fechadas pelos limites da ADR 0073 item 1: `reason` = `source` (17ª conexão simultânea da mesma origem, IPv4 ou /64 IPv6, fechada no `accept`) ou `idle` (ociosa mais antiga fechada com 180 conexões ou mais); com as 200 ocupadas nos últimos 60 s o health fica `degraded` com `public conns` |
| `fs_bot_index_bytes` | gauge | bytes contabilizados do índice (aproximação de ±25% do heap, ADR 0057 item 2); despejo por bytes nos últimos 60 s deixa o health `degraded` com `index bytes` |
| `fs_bot_list_entries{list}` | gauge | entradas de cada lista (`known_clients`, `googlebot`, `bingbot`, `aws`, ...; `ja4db` só com `FS_BOT_JA4DB_ENABLE=true`) |
| `fs_bot_list_age_seconds{list}` | gauge | idade da última atualização boa de cada lista baixada (sem nenhuma, desde a partida); acima de 72 h o health fica `degraded` com `list <nome> stale` |
| `fs_bot_webhook_sent_total{code}` | contador | tentativas de entrega do webhook, `code` = classe do status (`2xx`, `3xx`, `4xx`, `5xx`) ou `error` (erro de rede, prazo de 5 s, destino recusado ou status fora de 200–599); cada nova tentativa conta de novo |
| `fs_bot_webhook_dropped_total` | contador | eventos de webhook descartados: fila de 1000 da chave cheia, ou eventos ainda na fila de uma chave revogada ou do serviço parando |
| `fs_bot_webhook_url_rejected_total` | contador | chaves com `webhook_url` que não é `https` com host, recusadas na carga das chaves (uma vez por URL) |
| `fs_bot_keys_active` | gauge | chaves não revogadas |
| `fs_bot_rate_limited_total` | contador | respostas 429 por limite de chave |
| `fs_bot_purged_total{reason}` | contador | linhas de agregado expurgadas: `reason` = `age` (7 dias) ou `size` (banco acima de `FS_BOT_MAX_BYTES`, 2 GiB) |
| `fs_bot_db_bytes` | gauge | tamanho do banco do bot |
| `fs_bot_agg_dropped_total` | contador | observações descartadas pelo teto de entradas dos agregados em memória |

```promql
# p95 do forwardAuth inteiro e p95 só da espera da visão
histogram_quantile(0.95, sum by (le) (rate(fs_bot_auth_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le) (rate(fs_bot_auth_wait_seconds_bucket[5m])))

# fração de vereditos bot por origem
sum by (source) (rate(fs_bot_verdicts_total{class="bot"}[5m])) / sum by (source) (rate(fs_bot_verdicts_total[5m]))

# índice despejando por bytes, webhook perdendo eventos
increase(fs_bot_conns_evicted_total{reason="bytes"}[5m]) > 0 or increase(fs_bot_webhook_dropped_total[5m]) > 0
```

### store (heartbeat)

Além das [métricas nativas](#métricas-do-store), o store publica no próprio heartbeat:

| Métrica | Conteúdo |
| --- | --- |
| `fs_store_packets_total` | pacotes gravados (lotes confirmados) |
| `fs_store_app_events_total` | eventos de aplicação (web, raw, dns) lidos do JetStream e válidos |
| `fs_store_pending_events_total` | eventos de aplicação que chegaram antes dos pacotes da conexão e esperaram |
| `fs_store_event_only_connections_total` | conexões criadas só por eventos, sem pacotes: capture fora do ar ou atrasado |
| `fs_store_bad_events_total` | eventos de aplicação ilegíveis ou sem 5-tupla (exceto DNS por UDP, que não tem conexão), descartados |
| `fs_store_late_packets_total` | pacotes tardios (ACK ou RST depois do FIN, último datagrama QUIC) anexados ao pcap e ao registro já gravado, até 2 s depois do fim |
| `fs_store_late_dropped_total` | pacotes tardios descartados porque a conexão já saiu do banco (retenção ou `DELETE`) |
| `fs_store_raw_stream_bytes_total` | bytes crus de aplicação gravados (`fs.v1.web.stream.bytes`, `fs.v1.raw.read`) |
| `fs_store_conn_id_requests_total`, `fs_store_conn_id_invalid_total` | pedidos de `conn_id` respondidos e pedidos inválidos, deixados sem resposta (o serviço segue com `conn_id: unknown`) |
| `fs_store_bad_batches_total` | lotes FSPB do capture com formato ou versão diferentes de `fspb1`/`1`, ou truncados, descartados inteiros (ADR 0034). Erro de banco não conta aqui: vai para `fs_store_ingest_errors_total` |
| `fs_store_batch_count_mismatch_total` | lotes cujo `Fs-Count` diverge do número de pacotes decodificados (o lote é aplicado mesmo assim) |
| `fs_store_ingest_errors_total` | transações do ingest desfeitas (o lote volta ao JetStream por Nak e é reentregue) e falhas de finalização de conexões depois do commit |
| `fs_store_finalize_retries_total` | novas tentativas de finalizar uma conexão, uma a uma, até 5; esgotadas, a conexão é fechada sem pcap |
| `fs_store_packet_spills_total` | conexões abertas cujos pacotes passaram da memória do ingest para a tabela `packets` (mais de 1 MiB na conexão ou de 64 MiB somando todas); daí em diante os pacotes delas vão direto para o banco (task 248) |

### produtor NATS

Web, raw, dns e capture publicam por um produtor com buffer (spec 003 RF-05):

| Métrica | Conteúdo |
| --- | --- |
| `fs_published_events_total` | mensagens aceitas pelo NATS |
| `fs_dropped_events_total` | mensagens descartadas: buffer acima de 30 s ou 16 MiB com o NATS fora do ar, ou mensagem acima do `max_payload` do NATS, que nunca seria aceita (ADR 0035) |
| `fs_buffered_events`, `fs_buffered_bytes` | mensagens e bytes no buffer agora (gauges) |

## Métricas do store

| Métrica | Tipo | Conteúdo |
| --- | --- | --- |
| `fs_store_events_ingested_total{subject}` | contador | eventos consumidos do JetStream, por subject |
| `fs_store_ingest_lag_seconds` | histograma | do `ts` do envelope até o commit no SQLite |
| `fs_store_connections_open` | gauge | conexões abertas agora |
| `fs_store_connections_total{l4,proto}` | contador | conexões registradas, por L4 e pilha |
| `fs_store_connections_degraded_total` | contador | conexões gravadas em modo degradado (sem pcap nem bytes crus) |
| `fs_store_stray_packets_total` | contador | pacotes avulsos |
| `fs_store_stray_midflow_total` | contador | pacotes TCP (exceto RST) que viraram avulsos num fluxo cujo início o store não viu (nenhum SYN nem SYN-ACK no fluxo); com o ingest em dia e sem lacuna do stream, só tráfego alheio (varreduras, sessões de antes da partida do store) o faz crescer; `fs_store_stray_packets_total` continua contando todos (ADR 0041) |
| `fs_store_stream_lost_total` | contador | mensagens do `FS_EVENTS` que nunca chegaram ao store (expiradas por `max_age` ou `max_bytes`), somando os saltos de `Sequence.Stream` no metadado das mensagens recebidas; reentrega não conta e a primeira mensagem depois da partida não conta salto (ADR 0041) |
| `fs_store_ingest_backlog_seconds` | gauge | parede menos o instante em que a última mensagem processada entrou no stream; volta a 0 quando um Fetch não traz mensagens (consumidor em dia) (ADR 0041) |
| `fs_store_ingest_pending_messages` | gauge | `NumPending` do metadado da última mensagem processada (ADR 0041) |
| `fs_store_stream_recreated_total` | contador | vezes que o store recriou o `FS_EVENTS` e o consumidor depois de eles sumirem (reinício do NATS com o stream em memória, ADR 0016); a perda entre a queda e a recriação não entra em `fs_store_stream_lost_total`, que recomeça a contar saltos do zero (task 320) |
| `fs_store_app_events_dropped_total` | contador | eventos de aplicação de uma conexão aberta não gravados por passar do teto de bytes por conexão (`FS_PCAP_MAX_BYTES_PER_CONN`); a análise segue no registro (ADR 0067, task 318) |
| `fs_store_dns_queries_total` | contador | consultas DNS gravadas |
| `fs_store_purged_total{reason}` | contador | registros expurgados, `reason` = `age` (retenção), `size` (teto do banco) ou `space` (livre do tmpfs do banco abaixo de 10%, ou expurgo de emergência depois de um `SQLITE_FULL`; ADR 0045) |
| `fs_store_db_bytes` | gauge | tamanho do banco SQLite |
| `fs_store_connections` | gauge | conexões guardadas no banco (abertas e fechadas, dentro da retenção) |
| `fs_store_record_ready_seconds{reason}` | histograma | do fim da conexão até o registro completo gravado; `reason` = `close` (TCP com FIN/RST, meta p95 ≤ 500 ms), `quic_close` (QUIC encerrado, visto pelo web, mesma meta) ou `idle` (fechada por ociosidade, fora da meta); ver [abaixo](#tempo-até-o-registro) |
| `fs_store_live_clients{transport}` | gauge | clientes de tempo real, `transport` = `sse` ou `ws` |
| `fs_store_live_events_total{kind}` | contador | eventos ao vivo emitidos, por tipo |
| `fs_store_live_dropped_total` | contador | eventos descartados para clientes lentos: fila cheia em eventos (`FS_LIVE_BUFFER`) ou em bytes (4 MiB por cliente, 64 MiB no hub); o cliente recebe `stream.dropped` (ADR 0020, ADR 0034) |
| `fs_store_live_delay_seconds` | histograma | do `ts` do evento de origem até o envio ao cliente (meta: < 1 s) |
| `fs_store_flows_dropped_total{reason}` | contador | tabela de fluxos cheia (8192 entradas): `reason` = `evicted` (entrada não estabelecida mais antiga despejada, sem registro nem avulso) ou `table_full` (pacote de 5-tupla nova recusado sem nada para despejar) |
| `fs_store_api_requests_total{route,code}` | contador | requisições da API por rota e código |
| `fs_store_api_request_duration_seconds{route}` | histograma | duração das requisições da API (meta p95 < 100 ms) |
| `fs_store_api_json_bytes_in_flight` | gauge | bytes das respostas JSON finitas montadas e ainda não escritas (orçamento de 256 MiB, ADR 0066) |
| `fs_store_api_rejected_total{route,reason}` | contador | `503` da API por orçamento esgotado (`busy`) ou desligamento (`shutting_down`) (ADR 0066) |
| `fs_store_writer_seconds{op}` | histograma | duração das operações do escritor único do SQLite (task 248): `ingest_tx` (lote do ingest, do BEGIN ao fim do COMMIT), `ingest_commit` (só o COMMIT), `finalize_tx` (finalização com o pcap), `purge_delete` (um DELETE em lote do expurgo), `purge_vacuum` (`incremental_vacuum`), `wal_checkpoint` (checkpoint PASSIVE pela conexão própria, sem segurar o escritor) e `wal_restart` (última passada do checkpoint, com o escritor parado para o WAL recomeçar do início) |
| `fs_store_wal_frames` | gauge | quadros (páginas de 4 KiB) no WAL do SQLite no último checkpoint; volta perto de 0 quando o WAL recomeça |
| `fs_store_db_fs_bytes{kind}` | gauge | tamanho (`size`) e livre (`free`) do sistema de arquivos do banco (`statfs` do tmpfs de 4G, ADR 0045) |
| `fs_store_db_full_total` | contador | erros `SQLITE_FULL` (tmpfs do banco cheio) nas escritas do store; meta da carga: Δ 0 |
| `fs_store_db_full_dropped_total` | contador | mensagens do `FS_EVENTS` confirmadas e descartadas no modo banco cheio, quando nem o lote sem BLOBs coube |
| `fs_store_conn_publish_seconds` | histograma | tempo de montar e publicar uma mensagem `fs.v1.store.connection` (estado da conexão para o serviço bot, ADR 0047) |
| `fs_store_conn_publish_dropped_total` | contador | mensagens `fs.v1.store.connection` descartadas: fila de 4096 cheia ou NATS que recusou; o ingest nunca espera por elas |

`route` é o padrão da rota, nunca o caminho com IDs: por exemplo `GET /api/v1/connections/{conn_id}`.

Trecho real:

```console
$ curl -s http://finger-01.badblock.net.br:9001/metrics | grep -E '^fs_(service_up|store_connections_total|store_live_clients)'
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
$ curl -s -o /dev/null -w '%{http_code}\n' https://finger-01.badblock.net.br:9000/metrics
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
| `idle` | fluxo sem fim visto, fechado pelo store por falta de pacotes | o próprio prazo de ociosidade: TCP estabelecido `max(FS_IDLE_DEFAULT, FS_IDLE_MAX)` + 30 s (630 s com os padrões, para não fechar antes do web uma conexão com `idle=`), TCP sem handshake completo 10 s (vira avulso), QUIC sem close `FS_IDLE_DEFAULT` + 30 s (150 s), UDP 30 s |

`FS_TCP_CLOSE_GRACE` é a folga para os últimos pacotes do capture: padrão **100 ms**, aceita de 0 a 500 ms (fora
disso o store não sobe, spec 004 RNF-01). Pacotes que chegam depois do registro gravado (ACK final atrasado, RST
depois do FIN, último datagrama QUIC) não viram conexão nova: são anexados ao registro e ao pcap por até 2 s e
contados em `fs_store_late_packets_total`. Antes da task 077 o TCP esperava 1 s fixo; antes da task 090 o QUIC
esperava 2 s.

A meta de registro p95 ≤ 500 ms (spec 000 RNF-04, ADR
[0026](../specs/decisions/0026-fechamento-rapido-e-ajustes-da-release.md)) é lida em `close` e `quic_close`, a mesma
para TCP e QUIC; na carga oficial da `v0.1.0` o registro QUIC ficou em p95 252 ms. `idle` fica fora da meta: o
atraso é o prazo de ociosidade (+ 30 s), por definição.

No servidor anterior (commit `6facb2c`, `FS_TCP_CLOSE_GRACE=100ms`), em 9/11/2026:

```console
$ curl -s http://finger-01.badblock.net.br:9001/metrics | grep -E '^fs_store_record_ready_seconds_(sum|count)'
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

# eventos perdidos pelo produtor (NATS fora do ar ou mensagem acima do max_payload)
increase(fs_dropped_events_total[5m]) > 0

# eventos do web ou do raw descartados (acima do teto ou erro de serialização)
increase(fs_web_events_oversize_total[5m]) > 0 or increase(fs_web_events_marshal_errors_total[5m]) > 0 or increase(fs_raw_events_oversize_total[5m]) > 0

# lotes de pacotes inválidos ou transações desfeitas no ingest
increase(fs_store_bad_batches_total[5m]) > 0 or increase(fs_store_ingest_errors_total[5m]) > 0

# falha de emissão ou renovação de certificado
increase(fs_web_acme_failures_total[1h]) > 0

# DNS sob abuso: RRL ou descartes
increase(fs_dns_rate_limited_total[5m]) > 0 or increase(fs_dns_dropped_total[5m]) > 0

# tabelas cheias: Initials QUIC no web, fluxos no store
increase(fs_web_h3_init_table_full_total[5m]) > 0 or increase(fs_store_flows_dropped_total[5m]) > 0

# orçamento de entrada do web recusando reservas
increase(fs_web_input_budget_denied_total[5m]) > 0

# p95 do atraso do feed ao vivo
histogram_quantile(0.95, sum by (le) (rate(fs_store_live_delay_seconds_bucket[5m])))

# p95 da API por rota
histogram_quantile(0.95, sum by (le, route) (rate(fs_store_api_request_duration_seconds_bucket[5m])))

# registro pronto depois do fim da conexão (p95 por motivo; meta 500 ms no close)
histogram_quantile(0.95, sum by (le, reason) (rate(fs_store_record_ready_seconds_bucket{reason=~"close|quic_close"}[5m])))
```
