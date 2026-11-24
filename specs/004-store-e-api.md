# 004 — Serviço store e API

Status: aprovada
Depende de: 001, 003, 013

## Contexto
Dono de todos os registros. Consome o NATS, correlaciona pacotes e eventos de aplicação no mesmo `conn_id`,
calcula a análise IP/TCP (spec 013), monta o pcap de cada conexão, guarda em SQLite com retenção curta e serve a
API JSON, o tempo real e as métricas agregadas em portas não capturadas.

## Requisitos
- RF-01: consumidor durável `store` do stream JetStream `FS_EVENTS`; cria/ajusta o stream no start
  (`MemoryStorage`, `max_age` 60 s, `max_bytes` 128 MiB, `DiscardOld` — ADRs 0016 e 0039), com a lista explícita de subjects
  de eventos da ADR 0017 (request/reply fica fora).
- RF-02: correlação por 5-tupla + janela de tempo → `conn_id` (ULID); QUIC pela 5-tupla UDP, e um Initial com
  DCID novo depois do fim da conexão QUIC anterior abre conexão nova (ADR 0019); associação ao probe assim que o
  ID aparecer (SNI, Host, caminho, DNS, `PROBE`).
- RF-02a: responde o request/reply `fs.v1.store.conn_id` (ADR 0017): devolve o ID da conexão aberta com a 5-tupla
  ou reserva um ULID por 30 s para a próxima conexão criada pelos pacotes com essa 5-tupla.
- RF-03: pacotes que não formam conexão (SYN sem resposta, RST avulso, ICMP, UDP solto, quadro não IP; o ARP nem
  chega, é descartado no BPF do capture, ADR 0040) ficam como "pacotes avulsos",
  consultáveis por janela de tempo. Regra: fluxo TCP que nunca completou o handshake (sem SYN-ACK — inclui
  SYN recusado com RST e varreduras) e fluxo UDP sem nenhuma resposta viram avulsos quando terminam.
- RF-04: pcap por conexão (dois sentidos), teto `FS_PCAP_MAX_BYTES_PER_CONN` (16 MiB); acima disso guarda só os
  cabeçalhos dos pacotes e marca `pcap_truncated`. Os registros "só cabeçalhos" têm orçamento próprio de mais
  `FS_PCAP_MAX_BYTES_PER_CONN` bytes; esgotado, o pacote não entra no pcap (a análise IP/TCP já o contou). A
  recuperação de órfãs do reinício aplica o mesmo teto e grava `pcap_truncated` correto (ADR 0034).
- RF-04a: os pacotes de uma conexão aberta ficam **em memória** no ingest até a finalização, que grava o pcap
  direto em `pcaps` (task 248, ADR 0043). A tabela `packets` só recebe: (a) transbordo — a conexão que passa de
  1 MiB em memória, ou qualquer conexão quando o total passa de 64 MiB, é copiada para `packets` no lote em curso
  e daí em diante grava direto lá; (b) pacotes tardios de conexões já finalizadas; (c) o desligamento normal, que
  copia todos os buffers para `packets` antes de sair (a recuperação de órfãs monta o pcap no reinício). O
  `/pcap` de uma conexão aberta é o pcap parcial montado da memória (ou de `packets`, se transbordou).
  Consequência aceita: numa queda brusca do store (kill -9, OOM, panic) as conexões abertas perdem o pcap parcial
  (o registro sobrevive; a órfã fica com um pcap sem pacotes, só o cabeçalho do arquivo) — o mesmo risco já aceito para os eventos pendentes;
  desligamento normal e deploy não perdem pacotes.
- RF-05: persistência em SQLite (modernc, WAL) — registros, índices e **BLOBs** (pcap, bytes crus de cada sentido).
  O banco (`FS_STORE_DB`, com `-wal` e `-shm`) fica num **tmpfs dedicado** de 4G em `/finger-sniffer/var/store`
  (ADR 0045): sobrevive ao reinício do store e some no reinício do host, quando o store sobe com o banco vazio.
  Schema em [database/sqlite/migrations/](../database/sqlite/migrations/) aplicado por goose embutido no start.
- RF-06: retenção `FS_RETENTION` (10 min) e teto `FS_STORE_MAX_BYTES` (3 GiB, ADR 0045): o primeiro atingido expurga o mais
  antigo, em lotes, com `incremental_vacuum`. O expurgo por tamanho cobre `connections` (com as filhas),
  `dns_queries` e `stray_packets`, do mais antigo para o mais novo, e só desiste quando nada mais pode ser apagado
  (ADR 0034). O mesmo expurgo dispara quando o livre do tmpfs do banco (`statfs`) cai abaixo de 10% e vai até
  15% (`reason=space`). `SQLITE_FULL` no ingest: rollback, expurgo de emergência (fora do orçamento, até 15% livre
  ou 2 s), checkpoint `TRUNCATE` e uma nova tentativa; se falhar, **modo banco cheio** (conexões novas sem pcap e
  sem bytes crus, `degraded=true`) até o livre voltar a 15%; lote que falha até sem BLOBs é confirmado e
  descartado com métrica, nunca `Nak` em laço (ADR 0045).
  - **Reserva de espaço** (ADR 0045, adendo): o store mantém ao lado do banco um arquivo de 32 MiB,
    `<FS_STORE_DB>-reserve` (escrito de verdade, não esparso, modo `0600`), criado na partida e recriado depois de
    cada rodada de manutenção só com o livre do tmpfs, descontada a reserva, em ≥ 15% e fora do modo banco cheio.
    Com o tmpfs cheio de verdade o `DELETE` e o checkpoint também dão `SQLITE_FULL`; por isso o expurgo de
    emergência apaga a reserva **antes** de tudo, faz checkpoint `TRUNCATE` antes de começar, **depois de cada
    passo** de `DELETE` e no fim (corta o WAL e o arquivo do banco). Checkpoint que não roda (leitor longo) não
    interrompe o expurgo. A reserva conta no `statfs` do tmpfs, não em `FS_STORE_MAX_BYTES`.
- RF-07: API em 9000 (HTTPS, certificado de `FS_CERT_DIR` com recarga a quente por `pkg/certs`, spec 015 RF-04)
  e 9001 (HTTP), CORS `*`, sem autenticação, JSON, nomes em inglês. Escuta em `FS_LISTEN_IPV4`/`FS_LISTEN_IPV6`
  e em `127.0.0.1` (diagnóstico local), nunca em `*` (ADR 0001, ADR 0023).
  Na 9001, `/debug/pprof/` (inclusive `/debug/pprof/rates?block=N&mutex=N`, que liga ou desliga os perfis de bloqueio e mutex)
  responde só a clientes de loopback; de outra origem, 404 (diagnóstico da task 246, fora do openapi).
- RF-08: tempo real: SSE `GET /api/v1/stream` e WebSocket `GET /api/v1/ws`, filtros `probe`, `src_ip`,
  `dst_port`, `kind`; sem filtro = feed global. Hub em memória após o commit, sem replay, fila por cliente
  `FS_LIVE_BUFFER` (1024) com descarte e `stream.dropped`, até `FS_LIVE_MAX_CLIENTS` (64) clientes (ADR 0020);
  fila também limitada em bytes, 4 MiB por cliente e 64 MiB somando todas (ADR 0034). Detalhes em "Tempo real".
- RF-09: health agregado: heartbeat de cada serviço (5 s; `down` após 15 s sem heartbeat), versões
  (acusa desencontro), sysctls e offloads efetivos, estado do certificado, uso de disco/SQLite, NTP.
  O store fica `degraded`, com motivo, enquanto o ingest está mais de 5 s atrás do stream (`ingest backlog <n>s`)
  e por 5 min depois de perder mensagens do stream (`stream lost <n> messages in 5m`) (ADR 0041); enquanto o Fetch
  do consumidor falha há mais de 5 s (`ingest fetch failing <n>s`: o backlog congela no último valor e não o
  mostraria) e por 5 min depois de recriar o stream (`stream recreated in 5m`): o `FS_EVENTS` em memória (ADR 0016)
  e o consumidor somem num reinício do NATS, e o store os recria sozinho, sem esperar o próprio reinício
  (`fs_store_stream_recreated_total`; a perda entre a queda e a recriação não é mensurável pelo salto de
  sequência) (task 320); também com
  `db full` (modo banco cheio e 5 min depois do último `SQLITE_FULL`) e `db space <n>% free` (livre do tmpfs
  abaixo de 10%) (ADR 0045).
- RF-10: `/metrics` (Prometheus, `prometheus/client_golang`) em 9001 com as métricas próprias do store (lista em
  "Métricas") e as recebidas no heartbeat dos demais.
- RF-11: modo degradado (RNF-01): acima de `FS_MAX_CONNS` (padrão 1000) conexões simultâneas ou
  `FS_MAX_NEW_CONNS_PER_S` (padrão 250) novas/s, mantém o resumo, para de guardar pcap/bytes crus das novas
  conexões e marca `degraded=true`. A garantia continua a da spec 000 (400 e 100/s com análise completa, ADR
  0046); o padrão
  fica acima dela, com margem para o tráfego alheio de um servidor público e dos sites do host, que também é
  capturado (ADRs 0030 e 0039). Contagem (ADR 0026):
  - simultâneas = conexões TCP e QUIC vivas, de qualquer cliente; as já fechadas (FIN dos dois lados ou RST) que
    só esperam a folga não contam; fluxos UDP que não são QUIC (DNS e outros) não entram nos limites, mas saem
    `degraded` se chegarem com o limite passado; `fs_store_connections_open` continua contando a tabela inteira;
  - novas/s = balde de `FS_MAX_NEW_CONNS_PER_S` fichas (capacidade de 1 s) recarregado pelo instante de captura;
    pacotes fora de ordem não recarregam; tentativa que vira avulso (SYN recusado ou sem resposta) devolve a ficha;
  - o limite de simultâneas só degrada quando o excesso (vivas ≥ `FS_MAX_CONNS`) dura mais de 200 ms no tempo de
    captura (ADR 0027): a rajada de SYNs à frente dos FINs depois de uma pausa da rede não degrada; o excesso
    dentro da janela fica limitado pelo balde de novas/s; `FS_MAX_CONNS=0` degrada tudo, sem janela. O zero só
    tem esse significado no store: o web e o raw, que leem o mesmo env, tratam `FS_MAX_CONNS` ≤ 0 como o padrão
    deles (1000), com aviso no log (ADR 0034).
- RF-11a: tabela de fluxos com teto (ADR 0034): no máximo 8192 conexões e fluxos em memória. Com a tabela cheia,
  uma 5-tupla nova despeja a entrada não estabelecida mais antiga (TCP sem o ACK do handshake; UDP sem resposta do
  espelho, inclusive o que tem cara de Initial QUIC: o QUIC só é estabelecido com um datagrama do espelho com
  cabeçalho longo ou um evento h3, e só então conta nas simultâneas e gasta a ficha das novas/s, ADR 0069); depois,
  o UDP não-QUIC respondido mais antigo (que tem teto próprio de 2048 entradas: acima dele, o novo do mesmo tipo
  despeja o mais antigo); sem gravar registro nem avulso do despejado. Sem entrada a despejar, a 5-tupla nova é
  recusada (nenhuma linha em `connections`, `packets` ou `stray_packets`). Os dois casos contam em
  `fs_store_flows_dropped_total{reason=evicted|table_full}`. Sem limite por IP.
- RF-12: publicação para o serviço bot (ADR 0047, spec 018): depois do commit de cada estágio da conexão
  (`opened` com o SYN ou primeiro datagrama/evento analisado, `updated` quando um evento de aplicação é incorporado,
  no máximo um a cada 100 ms por conexão — o primeiro sai na hora e os da janela viram um só no fim dela, com o estado
  daquele instante, ADR 0055 item 1 —, `closed` com o registro final), o store publica em `fs.v1.store.connection` (NATS core, fora do `FS_EVENTS`)
  o `Connection` da API sem BLOBs, nos mesmos pontos em que o tempo real emite `connection.*`. Acima de 900 KiB,
  corta as listas como na ADR 0032 e marca `connection_truncated`. A publicação não bloqueia o escritor:
  serialização e envio fora da transação, fila de 4096 mensagens com descarte contado
  (`fs_store_conn_publish_dropped_total`) e tempo em `fs_store_conn_publish_seconds` (histograma). Conexão em modo
  degradado publica só `opened` e `closed`. Sem assinante, o NATS descarta.
- RF-13: o health conhece o sexto serviço `bot` como os outros (heartbeat, `down` após 15 s, `versions_match`).
- RNF-01: `GET` de conexão/probe p95 < 100 ms; registro completo ≤ 500 ms após o fim (p95, TCP e QUIC; no QUIC
  o fim é o `http3.connection` com `close`, ADR 0026); evento ao vivo < 1 s (p99), medidos como na
  ADR 0022 (`ts` do evento ao vivo pela ADR 0025). Referência da F4 (task 060): evento isolado 430–570 ms do `ts` ao feed; a
  150 req/s, p95 ~0,6 s e máximo ~1,1 s.

## Comportamento
- Fim de conexão (ADR 0026): RST fecha na hora; FIN dos dois lados fecha no ACK final (os dois FIN confirmados)
  ou, sem ele, depois de `FS_TCP_CLOSE_GRACE` (padrão 100 ms; aceita 0–500 ms, fora disso o store não sobe);
  ociosidade sem pacotes: TCP estabelecido, `max(FS_IDLE_DEFAULT, FS_IDLE_MAX)` + 30 s (630 s com os padrões, para
  não fechar antes do web uma conexão com `idle=`); TCP que não completou o handshake, 10 s (ADR 0034); UDP e
  QUIC como abaixo.
- Relógio dos prazos (ADR 0041): ociosidades, `FS_TCP_CLOSE_GRACE`, a espera de tardios, a ociosidade das conexões
  só de eventos e as reservas de `conn_id` contam no relógio de captura do ingest,
  `C = min(parede, T + (parede − P))` (`T` = maior instante de captura processado, `P` = parede quando ele foi
  processado): com o ingest atrasado os prazos andam com o stream, sem tráfego andam com a parede. A espera de 2 s
  da fila pendente, `updated_ns`, os `ts` de decisão do feed e os histogramas de atraso usam a parede.
- Lacuna do stream (ADR 0041): mensagens do `FS_EVENTS` que expiram antes da entrega aparecem como salto de
  `Sequence.Stream` e contam em `fs_store_stream_lost_total`. Ao detectar um salto, os fluxos abertos cujo último
  pacote é anterior à publicação da mensagem que o revelou passam a vencer por ociosidade em 10 s (pelo relógio
  `C`); um pacote novo devolve o prazo normal.
- Pacotes tardios: até 2 s depois do fim (instante de captura), pacotes da mesma 5-tupla (TCP: ACK, RST depois do
  FIN; QUIC: datagramas da mesma 5-tupla/DCID) entram no pcap e nos totais do registro já gravado e contam em
  `fs_store_late_packets_total`; não viram conexão nova nem avulso. SYN novo (TCP) ou Initial com DCID novo (QUIC)
  abre conexão nova. Fluxo que virou avulso não recebe tardios.
- Eventos de aplicação (`fs.v1.web.*`, `fs.v1.raw.*`, `fs.v1.dns.query`) são associados pela `flow` do envelope à
  conexão com a mesma 5-tupla cujo intervalo contém o `ts` do evento (com folga de 2 s antes do início, porque o
  evento pode chegar antes do lote de pacotes do SYN):
  - evento sem conexão ainda: espera até 2 s numa fila pendente; depois disso, cria a conexão só com os dados do
    evento (sem pacotes: `times.syn` nulo, sem `ip`/`tcp`, sem pcap) — é o caso do capture fora do ar;
  - evento de conexão já finalizada (até `FS_RETENTION`): atualiza o registro gravado;
  - evento cuja conexão não existe mais no banco (expurgada): segue a regra do evento sem conexão; evento de
    conexão aberta de um probe apagado pelo `DELETE` é descartado (ADR 0034);
  - todo evento é guardado em `app_events`; os fluxos (`stream.bytes`, `raw.read`) vão para `raw_streams`.
- Montagem do registro a partir dos eventos:

| Evento | Campo do registro | Regra |
| --- | --- | --- |
| `web.tls.client_hello` | `tls` (ClientHello) | substitui; `client_hello_segments` calculado pelo store a partir dos segmentos do cliente que cobrem o ClientHello |
| `web.tls.handshake` | `tls.negotiated`, `tls.handshake_ms`, `tls.alerts`, `times.tls_done` | funde no `tls` |
| `web.http1.request` | `http[]` | acrescenta, ordenado por `index`, até as 1000 primeiras (`http_truncated` acima, ADR 0067); `requests` = total h1+h2+h3 |
| `web.http2.connection` | `http2` (nível de conexão) | a última versão vale; preserva `streams` |
| `web.http2.stream` | `http2.streams[]` | acrescenta ou substitui por `stream_id`; `stream_id` 0 (stream não identificado pelo web) sempre acrescenta (ADR 0032); até 1000 itens, `http2.streams_truncated` acima (ADR 0067) |
| `web.http3.connection` | `http3` (nível de conexão), `tls` (= `http3.client_hello`), `times.tls_done` | a última versão vale; preserva `requests`; com `close` preenchido, fecha a conexão `FS_TCP_CLOSE_GRACE` depois (ADR 0026) |
| `web.http3.request` | `http3.requests[]` | acrescenta ou substitui por `stream_id`, até 1000 itens (`http3.requests_truncated` acima, ADR 0067); conta em `requests` |
| `web.websocket.frame` | `websocket` | o primeiro frame com `upgrade` preenche `over/path/extensions/subprotocol`; frames acrescentados (teto da ADR 0018, `frames_truncated`); `close` preenche `websocket.close`; `upgrade_only` (sessão sem frames) preenche `over/path/extensions/subprotocol` e não acrescenta frame (`frames: []`, ADR 0032) |
| `raw.session`, `web.raw.session` | `raw` | substitui |
| `web.stream.bytes`, `raw.read` | `raw_streams`, `raw_truncated` | grava o pedaço pelo `offset`; `truncated` marca o sentido |
| `dns.query` | tabela `dns_queries` | `conn_id` preenchido quando `proto=tcp` e houver conexão |

- Conexão aberta (ADR 0067): os payloads gravados em `app_events` somam no máximo `FS_PCAP_MAX_BYTES_PER_CONN` por
  conexão; acima, o evento não é gravado e conta em `fs_store_app_events_dropped_total`. Acima dos tetos das listas,
  um evento a mais não remonta o registro inteiro (listas serializadas em cache no ingest e no publicador).

- `proto` da conexão, derivado dos eventos: `tls/` como prefixo quando houve `client_hello`; depois `http1.0` ou
  `http1.1` (versão da primeira requisição), `h2` (ALPN) ou `h2c` (prior knowledge/Upgrade), `ws` acrescentado como
  sufixo quando houve Upgrade (ex. `tls/http1.1/ws`), `raw` (raw), `raw/unknown` (web sem protocolo reconhecido),
  `dns` (fluxo **TCP** da porta 53 com `dns.query`; fluxos UDP da 53 ficam `udp` e sem probe, e a consulta
  fica em `/api/v1/dns` — ADR 0023), `quic/h3` (`http3.connection` com ALPN `h3` negociado) ou `quic`
  (Initial analisado sem h3: versão desconhecida, handshake falho, outro ALPN). Sem evento de aplicação: `tcp` ou
  `udp`.
- Fim de conexão QUIC (ADR 0019, 0026): `http3.connection` com `close` → `end` `FS_TCP_CLOSE_GRACE` depois (a
  mesma folga do TCP; o nome fica por compatibilidade), `close.by` do web,
  `close.how = quic_close` (ou `timeout` quando o web informa `idle_timeout`). O `tls` do registro QUIC é o ClientHello do Initial, mas
  o `proto` não ganha o prefixo `tls/`. Fluxo UDP com evento h3 e sem
  `close` usa ociosidade `FS_IDLE_DEFAULT` + 30 s, não a de UDP.
- `probe_id` da conexão: o primeiro `probe_id` não nulo dos envelopes da conexão; a tabela `probes` é atualizada
  (`first_seen`/`last_seen`) a cada conexão ou consulta DNS com probe.
- Long-poll `GET /api/v1/probes/{id}?wait=10s` (máx 60 s): responde quando o probe tem **ao menos uma conexão** e
  todas estão fechadas, ou no fim do prazo. Só consultas DNS (ou nada) não bastam: a espera continua até a
  primeira conexão aparecer e fechar (ex.: o resolvedor do cliente ou de um proxy já consultou o nome, mas a
  conexão ainda não chegou). No fim do prazo: 200 com o estado atual (`all_closed` = nenhuma conexão aberta) ou 404 se o probe não tem nada. Sem
  `wait`, responde na hora como antes.
  - Teto da resposta (ADR 0032, decisão do humano): no máximo as 1000 primeiras conexões (por início) e as 1000
    primeiras consultas DNS (por instante), com `truncated: true` quando alguma lista foi cortada; o restante fica
    em `GET /api/v1/connections?probe=` e `GET /api/v1/dns?probe=`. O critério do `wait` e `all_closed` olham o
    conjunto inteiro.
  - No máximo 64 `wait` simultâneos no store; acima, `503` na hora com `Retry-After: 1`. A volta do laço lê só o
    estado das conexões; o registro completo é lido uma vez, ao sair.
  - Parâmetros do critério (ADR 0029): `min_conns` (1–1000, padrão 1) exige ao menos essa quantidade de
    conexões; `settle` (duração Go `0s`–`10s`, padrão `0s`) exige também que nenhuma conexão do probe tenha sido
    criada, correlacionada ao probe ou fechada nos últimos `settle` (relógio do store, do instante em que ele
    registrou a mudança). `settle`/`min_conns` sem `wait`, fora do formato ou da faixa → 400.
  - Com `wait`, a resposta traz `wait_met`: `true` quando saiu pelo critério, `false` pelo fim do prazo. Vale a
    presença do parâmetro: `wait=0s` é um `wait` válido, avalia o critério uma vez, responde na hora e traz
    `wait_met`. Para
    o conjunto completo de uma sondagem, o uso recomendado é `wait=30s&settle=1s` (acima dos 500 ms do RNF-04).
- `DELETE /api/v1/probes/{id}` (ADRs 0034 e 0068): uma transação curta grava em `deleted_probes` o corte do probe
  (maior `conn_id` e maior `rowid` de `dns_queries` dele naquele instante) e apaga a linha de `probes`; responde
  `204`. Toda leitura (por probe, lista, detalhe, `/pcap`, `/raw`, `/dns` e tempo real) exclui na hora as linhas do
  probe abaixo do corte; o laço de retenção apaga as conexões (com as filhas) e as consultas abaixo do corte em
  lotes de 100, com o passo de 25 ms e a vez do ingest entre lotes, e tira a linha de `deleted_probes` no fim. Os `conn_id` das conexões que ainda estavam abertas (ou à espera da finalização) ficam
  em memória no ingest, que descarta os pacotes, os eventos e a finalização delas, sem recriar a linha, até a
  conexão fechar. Tráfego novo com o mesmo probe ID cria um probe novo.
- Downloads de BLOB (`/pcap`, `/raw`; ADR 0032): no máximo 4 em andamento somando as duas rotas; acima, `503`
  com `Retry-After: 1`. Cada resposta tem prazo de escrita de 60 s (por resposta, nunca global).
- Respostas JSON finitas (`/probes/{id}`, `/connections`, `/connections/{id}`, `/dns`, `/packets`; ADR 0066): prazo de
  escrita de 60 s por resposta; orçamento do processo de **256 MiB** dos bytes montados e ainda não escritos,
  reservado durante a montagem e devolvido no fim da escrita; não cabe → `503` com `Retry-After: 1` e
  `{"error":"busy"}`. Teto de **64 MiB** por resposta: o probe para de acrescentar e marca `truncated: true`; as
  listas devolvem menos que `limit`; um registro único nunca é cortado.
- Desligamento (ADR 0066): o sinal é ligado antes de cancelar o contexto base; rota finita interrompida por ele
  responde `503` com `Retry-After: 1` e `{"error":"shutting down"}`; cliente que foi embora não recebe nada. SSE e
  WS só fecham.
- Falha no ingest (ADR 0034):
  - erro de SQL em qualquer item aborta a transação do lote (rollback) e o lote volta por `Nak`; só o lote FSPB
    malformado (curto, ou `Fs-Format`/`Fs-Schema-Version` diferentes de `fspb1`/`1`, conferidos antes de
    decodificar) é descartado com `Ack` e conta em `store_bad_batches_total`; `Fs-Count` diferente dos registros
    lidos só gera aviso e `store_batch_count_mismatch_total`;
  - o rollback desfaz também a tabela de fluxos: conexões criadas pelo lote são reinseridas na reentrega;
  - conexões que fecharam no lote só saem da fila de finalização depois do commit; falha na finalização → nova
    tentativa uma a uma, até 5, depois a linha é fechada com `ended_ns` e o que houver;
  - erro depois do commit nunca vira `Nak` (só log; o lote já está gravado);
  - a retenção expurga também linhas com `ended_ns` nulo que já não estão na tabela de fluxos e são mais velhas
    que `FS_RETENTION` + a ociosidade máxima do TCP;
  - sem `MaxDeliver`/`BackOff` no consumidor (ADR 0016 mantida).
- Reinício: o índice vem do SQLite (tmpfs, ADR 0045); o consumidor durável retoma do último ack. Depois do
  reinício do host o banco começa vazio e o que ainda estiver no stream entra nele.
- Erros da API (corpo `{"error": "..."}`): 400 para parâmetro de consulta ou de caminho fora do formato do
  openapi (`conn_id` que não é ULID, probe ID fora de `^[a-z0-9]{8,32}$`, `dir` ausente ou inválido); 404 para
  ID no formato certo mas desconhecido/expirado e para rota inexistente; 500 para erro interno; 503 com
  `Retry-After` acima do teto de `wait` (`/probes/{id}`), de downloads (`/pcap`, `/raw`) ou do orçamento de
  respostas JSON, e em qualquer rota finita durante o desligamento (ADR 0066). Toda rota do
  openapi declara os códigos que devolve (contrato 0.3.3; 0.3.4 descreve o `LiveEvent.ts`; 0.3.5, o `ts` do `packet.stray`, ADR 0026;
  0.4.0, aditivo: instantes por requisição, `ip.packets`, `settle`/`min_conns`/`wait_met`, ADR 0029; 0.4.1,
  documental: nulos dos instantes e `wait=0s`; 0.5.0, aditivo: `ip.src_kind`, `tcp.syn_mss`, `tcp.mtu_implied`,
  `tcp.mss_reduction`, ADR 0031; 0.6.0, aditivo: `truncated` no probe, os 503, `target_truncated`,
  `lists_truncated`, `transport_params_truncated`, `h3_settings_truncated`, `websocket` sem frames e descrições,
  ADR 0032; asyncapi 0.5.0 com `upgrade_only`; 0.7.0, aditivo: `503` nas rotas finitas, corte por bytes, marcas
  `http_truncated`, `streams_truncated`, `requests_truncated`, `method_truncated`, `version_truncated` e
  `controls.truncated`, ADRs 0066, 0067 e 0070; asyncapi 0.7.0; entram com as tasks 318, 319, 327 e 340).

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

- `ts` do `LiveEvent` (ADR 0025) = instante em que o espelho teve o fato e pôde emiti-lo: `connection.opened` →
  primeiro pacote ou evento; `connection.updated` → entrada do evento de aplicação de origem no `FS_EVENTS`
  (metadado `Timestamp` do JetStream; sem ele, o recebimento pelo consumidor), não o `ts` do envelope (o
  `raw.session` leva o accept e só sai no fim); atualização de registro já gravado → instante do store;
  `connection.closed` → fim (FIN/RST/`quic_close`) ou, por ociosidade e órfã do reinício, o instante em que o
  store decidiu fechar; `http.request`/`dns.query` → `ts` do envelope; `packet.stray` → `ts` do pacote quando
  emitido na chegada (RST avulso, ICMP) ou, para o avulso decidido pelo fim do fluxo por ociosidade (UDP ou SYN
  sem resposta), o instante da decisão (ADR 0026);
  `stream.dropped` → envio. Os tempos do fato ficam em `data.started`/`data.ended`.
- `conn_id` e `probe_id` do envelope do `LiveEvent` preenchidos quando houver. Filtros: `probe` (= `probe_id`),
  `src_ip` (cliente; para `dns.query`, o resolvedor), `dst_port` (porta do espelho; `dns.query` = 53), `kind`
  (lista por vírgula dos 6 tipos filtráveis; `stream.dropped` não é filtrável, é sempre entregue a quem perdeu
  eventos e pedi-lo dá 400). Filtro inválido → 400 antes do upgrade/stream.
- SSE: `event: <kind>`, `data: <JSON>`, comentário `: ping` a cada 15 s, `Cache-Control: no-store`, flush por
  evento. WS: uma mensagem de texto por evento, ping a cada 30 s, mensagens do cliente ignoradas, fecha com 1001
  no desligamento.
- Fila por cliente (ADR 0034): além de `FS_LIVE_BUFFER` eventos, no máximo 4 MiB por cliente e 64 MiB somando as
  filas de todos (cada evento conta em cada fila em que está); acima, o evento é descartado para aquele cliente e
  entra no `stream.dropped`. O SSE não tem prazo de escrita (cliente lento perde eventos, não a conexão, ADR 0020);
  o WebSocket encerra o cliente que não aceita uma escrita em 30 s.
- Mais de `FS_LIVE_MAX_CLIENTS` clientes → 503. A latência ingest → cliente entra na métrica
  `fs_store_live_delay_seconds` (`ts` do `LiveEvent` até o envio).

### Métricas (RF-10)
Próprias do store, além das gauges `fs_<métrica>{service=...}` recebidas no heartbeat e `fs_service_up`. Chave do
heartbeat com rótulos (`nome{r="v"}`, histograma em `_bucket`/`_sum`/`_count`, ADR 0056 item 4) vira
`fs_<nome>{service,<rótulos>}`; malformada ou além de 512 chaves por heartbeat é ignorada e contada em
`fs_store_heartbeat_metrics_invalid_total`:
`fs_service_info{service,version}`, `fs_store_events_ingested_total{subject}`, `fs_store_ingest_lag_seconds`
(histograma: `ts` do envelope → commit), `fs_store_connections_open`, `fs_store_connections_total{l4,proto}`,
`fs_store_connections_degraded_total`, `fs_store_stray_packets_total`, `fs_store_dns_queries_total`,
`fs_store_purged_total{reason=age|size|space}`, `fs_store_db_bytes`, `fs_store_db_fs_bytes{kind=size|free}`,
`fs_store_db_full_total`, `fs_store_db_full_dropped_total`, `fs_store_late_packets_total`,
`fs_store_record_ready_seconds{reason=close|quic_close|idle}` (histograma: fim → registro gravado; `close` = FIN/RST,
`quic_close` = close do web, `idle` = ociosidade; os três pré-criados; a meta RNF-01 é lida em `close` e
`quic_close`, ADR 0026), `fs_store_live_clients{transport=sse|ws}`, `fs_store_live_events_total{kind}`,
`fs_store_live_dropped_total`, `fs_store_live_delay_seconds` (histograma),
`fs_store_flows_dropped_total{reason=evicted|table_full}`, `fs_store_ingest_errors_total`,
`fs_store_finalize_retries_total`, `fs_store_batch_count_mismatch_total` (ADR 0034),
`fs_store_stream_lost_total`, `fs_store_ingest_backlog_seconds` (gauge: parede − publicação da última mensagem
processada), `fs_store_ingest_pending_messages` (gauge: `NumPending` do consumidor), `fs_store_stray_midflow_total`
(avulsos TCP de fluxo sem início visto, exceto RST) (ADR 0041), `fs_store_stream_recreated_total` (vezes que o
`FS_EVENTS` e o consumidor foram recriados depois de sumirem; task 320),
`fs_store_writer_seconds{op}` (histograma: duração de cada comando do escritor SQLite), `fs_store_wal_frames` (gauge:
quadros do WAL no último checkpoint) e `fs_store_packet_spills_total` (pacotes de conexão aberta que transbordaram para `packets`,
RF-04a) (task 248),
`fs_store_api_requests_total{route,code}` e `fs_store_api_request_duration_seconds{route}` (histograma; `route` =
padrão do mux, nunca o caminho com IDs), `fs_store_api_json_bytes_in_flight` (gauge) e
`fs_store_api_rejected_total{route,reason=busy|shutting_down}` (ADR 0066), `fs_store_app_events_dropped_total`
(ADR 0067).

## Interfaces e contratos
Contrato: [cmd/finger-sniffer-store/openapi.yaml](../cmd/finger-sniffer-store/openapi.yaml) (servido em
`/api/v1/openapi.yaml`). Rotas:

| Método e caminho | Retorno |
| --- | --- |
| `GET /api/v1/health` | `{"ok":true,"version":"...","services":{...},"host":{...}}` |
| `GET /api/v1/probes/{id}?wait=10s` | conexões e consultas DNS do probe, completas, até 1000 de cada (`truncated` acima; ADR 0032) |
| `GET /api/v1/connections?src_ip=&dst_port=&since=&until=&probe=&limit=` | lista resumida |
| `GET /api/v1/connections/{conn_id}` | registro completo (specs 008–013) |
| `GET /api/v1/connections/{conn_id}/pcap` | pcap da conexão (`application/vnd.tcpdump.pcap`); 503 acima de 4 downloads |
| `GET /api/v1/connections/{conn_id}/raw?dir=in\|out` | bytes de aplicação de cada sentido (`out` = o que o espelho mandou); 503 acima de 4 downloads |
| `GET /api/v1/dns?probe=&since=` | consultas DNS |
| `GET /api/v1/packets?since=&until=&src_ip=` | pacotes avulsos; `src_ip` = IP do cliente (origem com `dir=in`, destino com `dir=out`) |
| `DELETE /api/v1/probes/{id}` | apaga o probe, suas conexões (abertas também) e consultas DNS, na hora |
| `GET /api/v1/stream` | SSE |
| `GET /api/v1/ws` | WebSocket |
| `GET /api/v1/openapi.yaml` | contrato |
| `GET /metrics` (só 9001) | Prometheus |

Formato do registro (resumo; o completo está no openapi.yaml):
```json
{
  "conn_id": "01JC0X3K8V2T7Q9N4M6P1R5S8W", "probe_id": "t1a2b3c4", "proto": "tls/http1.1",
  "src": {"ip": "45.170.76.49", "port": 41234}, "dst": {"ip": "170.247.40.86", "port": 8443},
  "family": 4, "l4": "tcp", "degraded": false,
  "times": {"syn": "2026-11-07T12:00:00.000000123Z", "established": "...", "first_data": "...", "end": "..."},
  "close": {"by": "client", "how": "fin", "idle_before_close_ms": 15000, "half_close": false},
  "ip": {}, "tcp": {}, "tls": {}, "http": [], "http2": {}, "http3": {}, "websocket": {}, "raw": {}
}
```

Consome: os subjects de eventos do stream (ADR 0017). Responde: `fs.v1.store.conn_id`. Publica: `fs.v1.store.connection`
(RF-12, para o bot; ADR 0047 item 3) e o push para clientes da API.

## Dados
Tabelas (migration [00001_initial.sql](../database/sqlite/migrations/00001_initial.sql)): `probes`, `connections`
(registro completo em `record_json`), `packets` (BLOB por pacote; só transbordo, tardios e desligamento, RF-04a), `pcaps` (BLOB),
`app_events`, `raw_streams` (BLOB), `dns_queries`, `stray_packets`, `deleted_probes` (cortes dos `DELETE` em
andamento, ADR 0068). Tabelas filhas com `ON DELETE CASCADE`
sobre `connections`, para o expurgo apagar tudo de uma vez. O `record_json` de uma conexão aberta é o da criação
(ou da última mudança de `proto`/`probe`); a API sobrepõe o estado ao vivo da tabela de fluxos em toda leitura
de conexão aberta, na lista e no detalhe (ADR 0034). Retenção conforme RF-06. O store abre o banco com
`foreign_keys=ON`, `journal_mode=WAL` e `auto_vacuum=INCREMENTAL`; o escritor com `synchronous=OFF`,
`wal_autocheckpoint=16384` e `journal_size_limit` de 64 MiB (banco em tmpfs, ADR 0045).

## Critérios de aceite
- [ ] Uma sondagem por probe aparece completa em `GET /api/v1/probes/{id}` em ≤ 500 ms após o fechamento.
- [ ] Após 10 min sem tráfego, `GET` do mesmo probe devolve 404.
- [ ] Com o teto atingido, o mais antigo é expurgado e o banco não passa de 110% do teto.
- [ ] O pcap baixado abre no tshark e mostra os dois sentidos.
- [ ] Respostas de todas as rotas validam contra o openapi.yaml (teste de contrato).
- [ ] Parar o capture faz `/api/v1/health` mostrar `capture: down` em ≤ 15 s.
- [ ] `?wait=10s` num probe com só consultas DNS espera a primeira conexão e responde quando ela fecha.
- [ ] `?wait=10s&settle=1s` com duas conexões do probe separadas por 500 ms devolve as duas, `wait_met: true`;
      `?wait=2s&min_conns=3` com duas conexões devolve as duas no fim do prazo com `wait_met: false`;
      `settle=11s`, `min_conns=0` ou `settle` sem `wait` → 400.
- [ ] Feed global pelo `/ws` e pelo `/stream`: evento de uma requisição h1/h2/h3 chega em < 1 s; cliente que não lê
      recebe `stream.dropped` e não atrasa o ingest; 65º cliente recebe 503.
- [ ] Conexão `quic/h3` encerrada pelo cliente fecha no store em ≤ 500 ms (p95) do `http3.connection` com
      `close`, com `close.how = quic_close`; datagramas tardios entram no mesmo registro (ADR 0026).
- [ ] FIN dos dois lados com ACK final fecha o registro no ACK; sem ACK, depois de `FS_TCP_CLOSE_GRACE`; RST fecha
      na hora; ACK/RST tardio até 2 s entra no registro gravado, sem conexão nova nem avulso.
- [ ] Com os padrões (1000/250), o perfil do RNF-01 (400 vivas, 100 novas/s com jitter, consultas DNS, varreduras
      e algumas dezenas de conexões alheias por cima) não marca `degraded`; excesso sustentado acima de
      `FS_MAX_CONNS` vivas ou de `FS_MAX_NEW_CONNS_PER_S` novas/s marca (ADR 0030).
- [ ] Conexão aberta não grava linhas em `packets` abaixo de 1 MiB; o `/pcap` dela durante a conexão e depois de
      um desligamento normal no meio dela traz os pacotes já vistos (RF-04a).
- [ ] `/metrics` traz as métricas da seção "Métricas" e passa no lint do `prometheus/testutil` (`GatherAndLint`).

## Fora de escopo
- Autenticação, paginação por cursor (só `limit`), histórico além da retenção (vereditos e agregados de 7 dias são
  do serviço bot, spec 018).

## Decisões relacionadas
- specs/decisions/0005-sqlite-com-blobs.md
- specs/decisions/0047-fase-de-bots-servico-bot.md
- specs/decisions/0007-api-aberta-e-feed-global.md
- specs/decisions/0012-retencao-curta.md
- specs/decisions/0004-pacotes-pelo-nats.md
- specs/decisions/0017-request-reply-e-conn-id.md
- specs/decisions/0018-tamanho-dos-eventos.md
- specs/decisions/0019-http3-eventos-e-fim-quic.md
- specs/decisions/0020-tempo-real-sem-replay.md
- specs/decisions/0029-campos-da-auditoria-de-requisitos.md
- specs/decisions/0022-prova-do-mvp-no-espelho.md
- specs/decisions/0025-ts-dos-eventos-ao-vivo.md
- specs/decisions/0026-fechamento-rapido-e-ajustes-da-release.md
- specs/decisions/0030-margem-do-modo-degradado.md
- specs/decisions/0032-campos-da-auditoria-de-2026-11.md
- specs/decisions/0034-tetos-e-falhas-do-store.md
- specs/decisions/0039-limites-e-metas-no-finger-01.md
- specs/decisions/0041-ingest-atrasado-relogio-e-lacunas.md
- specs/decisions/0043-limite-conhecido-da-v0-3-0-no-finger-01.md
- specs/decisions/0045-banco-do-store-em-ram.md
- specs/decisions/0046-rnf-01-400-100-com-o-banco-em-ram.md
- specs/decisions/0055-ajustes-da-primeira-onda-da-f8.md
- specs/decisions/0066-respostas-finitas-da-api-do-store-orcamento-e-desligamento.md
- specs/decisions/0067-teto-do-registro-de-conexao-aberta.md
- specs/decisions/0068-delete-de-probe-em-lotes.md
- specs/decisions/0069-despejo-do-udp-na-tabela-de-fluxos.md
- specs/decisions/0056-segunda-onda-da-f8.md
