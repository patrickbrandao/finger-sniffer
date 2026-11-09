# 0029 — Campos para a auditoria de requisitos (instantes por requisição, IP por pacote, TFO, alertas, `settle`)

Status: aceita
Data: 2026-11-09

## Contexto
A auditoria do documento de requisitos original contra a `v0.1.0` em produção (09/11/2026) encontrou cinco itens
parciais que um cliente de teste de não-interferência precisa para comparar o que o espelho viu por caminhos
diferentes:
- **A1**: o registro não traz o instante de cada requisição e de cada resposta em `http[]`, `http2.streams[]` e
  `http3.requests[]` (só `t_first_byte_ms`, `t_since_prev_response_ms` e offsets). A spec 013 RF-01 já pedia
  "cada requisição e resposta": divergência spec × implementação. Os três eventos (`http1.request`,
  `http2.stream`, `http3.request`) são publicados no fim da resposta, com o `ts` do envelope = instante da
  publicação, e o store copia o payload como veio.
- **A2**: `ip` é um objeto único que mistura o SYN (TTL, DF, IP ID, flow label) e o primeiro segmento com dados
  (TOS/ECN). A spec 013 pede "cada pacote do handshake e o primeiro com dados".
- **A3**: `tcp_fastopen=3` está no sysctl, mas nenhum listener liga `TCP_FASTOPEN`: o SYN-ACK nunca traz cookie,
  então nenhum cliente real chega a mandar dados no SYN e `tcp.syn.payload_b64` nunca aparece.
- **A4**: os alertas TLS vêm do texto de erro do `crypto/tls`. Um cliente que aborta com alerta em texto claro
  (`unknown_ca`, 48) aparece só como `out bad_record_mac` (20), o alerta que o servidor mandou depois.
- **A5**: o long-poll `wait` responde quando as conexões **já conhecidas** fecharam; uma conexão aberta logo
  depois, ou ainda não correlacionada (até ~500 ms, RNF-04), fica de fora, e o cliente não tem como saber que o
  conjunto está completo.

## Decisão
Mudanças **aditivas** nos contratos: openapi e asyncapi passam a **0.4.0**; nada é removido nem renomeado.

1. **A1 — instantes por requisição e resposta, publicados pelo web.** `HTTP1Request`, `HTTP2Stream` e
   `HTTP3Request` ganham quatro campos `NullableTimestamp` (RFC 3339 UTC com nanossegundos, relógio do web):
   - `request_started_at`: o web leu o primeiro byte da requisição (h1: primeiro byte da linha de requisição; numa
     requisição em pipeline já no buffer, o instante da leitura que a trouxe; h2/h3: o frame HEADERS do stream);
   - `request_ended_at`: o web leu o último byte da requisição (h1: fim do corpo ou dos trailers, ou do cabeçalho
     sem corpo; h2/h3: END_STREAM ou FIN do stream); nulo se a requisição não terminou;
   - `response_started_at`: o web escreveu o primeiro byte da resposta (1xx incluídos; h2/h3: primeiro HEADERS
     do servidor no stream); nulo se nada foi enviado;
   - `response_ended_at`: o web escreveu o último byte da resposta (h2/h3: END_STREAM ou RST_STREAM/reset do
     servidor); nulo se nada foi enviado.

   São instantes da aplicação: em TLS e QUIC, depois de decifrar e antes de cifrar; o instante no fio fica no
   pcap. Os controles `delay_*` aparecem neles. No stream 1 de h2c por `Upgrade` a requisição é a do `http[]`
   (instantes nulos no stream; os da resposta preenchidos). O store **não calcula nada**: copia o payload como já
   faz; o `ts` do envelope continua sendo o instante da publicação (≈ `response_ended_at`) e não é copiado.
   Registros feitos com eventos anteriores ao 0.4.0 não têm os campos.
2. **A2 — IP por pacote, calculado pelo store.** `ip` mantém todos os campos atuais (mesma origem: compatível) e
   ganha `ip.packets: {syn, ack, first_data}`, cada um um `IPPacket` ou nulo:
   `ttl` (hop limit no IPv6), `df` (nulo no IPv6), `ip_id` (nulo no IPv6), `tos` (traffic class no IPv6), `dscp`,
   `ecn`, `flow_label` (nulo no IPv4), `total_length` (IPv4: Total Length; IPv6: 40 + Payload Length),
   `options_hex` (opções IPv4; vazio no IPv6) e `fragmented`.
   - `syn`: o primeiro SYN do cliente (retransmissão não substitui);
   - `ack`: o primeiro segmento do cliente com ACK e sem SYN depois do SYN-ACK (com ou sem dados);
   - `first_data`: o primeiro segmento do cliente com dados (pode ser o próprio SYN, com TFO, ou o próprio `ack`).
   - UDP: `syn` e `ack` nulos; `first_data` é o primeiro datagrama do cliente.
   Os instantes desses pacotes já estão em `times.syn`, `times.established` e `times.first_data`.
3. **A3 — o espelho concede TFO.** Os listeners TCP do web (`FS_WEB_TCP_PORTS`) e do raw (`FS_RAW_PORTS`) ligam
   `TCP_FASTOPEN` com fila de **256** pedidos pendentes (`setsockopt` no `ListenConfig.Control`). Com o
   `tcp_fastopen=3` já aplicado, o SYN-ACK passa a trazer o cookie quando o cliente o pede, e um cliente que repete
   a conexão manda dados no SYN, que aparecem em `tcp.syn.payload_b64`. Falha no `setsockopt` só registra aviso e
   segue sem TFO (o heartbeat não muda). Sem mudança de contrato nem de sysctl. DNS TCP, 9000 e 9001 ficam sem
   TFO. Consequência aceita: com dados no SYN o accept e a leitura acontecem antes do ACK do handshake, e no modo
   `banner` do raw o banner pode sair antes do fim do handshake.
4. **A4 — alertas pelos bytes.** `tls.alerts` é montado pelo produtor (web e raw) nesta ordem de autoridade:
   - todo registro de alerta (tipo `0x15`) **em texto claro** visto nos bytes de cada sentido durante o handshake,
     com `level` e `description` exatos dos bytes (`dir: in` do cliente, `dir: out` do espelho), na ordem em que
     apareceram;
   - depois, o alerta que o `crypto/tls` informa (`remote error` → `in`, alerta cifrado decifrado por ele;
     `local error` → `out`, alerta que ele mandou, cifrado no TLS 1.3), só se não houver já um alerta igual
     (mesma direção e descrição) vindo dos bytes.
   O parser dos registros fica em `pkg/tlsparse` (reaproveitado pelo raw). Sem mudança de schema; a descrição de
   `alerts` no openapi registra a origem.
5. **A5 — `settle` e `min_conns` no long-poll.** `GET /api/v1/probes/{id}?wait=` aceita:
   - `settle` (duração Go, mesmo formato do `wait`, `0s`–`10s`, padrão **0**: comportamento de hoje): além do
     critério atual, nenhuma conexão do probe foi criada, correlacionada ao probe ou fechada nos últimos `settle`
     (relógio do store, a partir do instante em que o store registrou a mudança);
   - `min_conns` (inteiro 1–1000, padrão **1**): a resposta exige ao menos essa quantidade de conexões.
   - `settle` ou `min_conns` sem `wait` → 400. O prazo continua o do `wait` (máx. 60 s).
   - A resposta ganha `wait_met` (só com `wait`): `true` quando saiu pelo critério, `false` quando saiu pelo fim
     do prazo. Uso recomendado para o conjunto completo: `wait=30s&settle=1s` (acima dos 500 ms do RNF-04).

## Alternativas consideradas
- A1 pelo `ts` do envelope copiado pelo store: dá só um instante (a publicação, depois da resposta), não o
  início da requisição nem o da resposta; o web é o único que vê os quatro.
- A1 pelos pacotes (mapear `in_offset`/`out_offset` para segmentos): impossível em TLS/QUIC sem as chaves e caro
  nos fluxos longos.
- A2 trocando `ip` por uma lista `ip.packets[]`: quebraria o contrato; objeto com chaves nomeadas é mais claro
  que lista posicional.
- A3 pelo bit `0x400` no `tcp_fastopen` (TFO em todo listener sem `setsockopt`): ligaria TFO também na 9000/9001
  e em qualquer socket futuro; o `setsockopt` por listener é explícito e testável no código do serviço.
- A4 só pelos bytes: perderia o alerta cifrado do TLS 1.3, que o `crypto/tls` vê decifrado.
- A5 mudando a semântica do `wait`: quebraria clientes; um parâmetro novo com padrão compatível não quebra.
  `min_conns` sozinho não basta para quem não sabe quantas conexões o caminho abre; `settle` sozinho não basta
  para um cliente que abre a 2ª conexão depois de uma pausa conhecida; os dois juntos cobrem os casos.

## Consequências
- Specs 004, 005, 006, 008, 009, 010, 011, 013 e 016 atualizadas; openapi e asyncapi 0.4.0.
- Tarefas: store (A2, A5 e a passagem dos campos de A1 até o registro), web (A1, A3 no web, A4 com o parser em
  `pkg/tlsparse`) e raw (A3 e A4 no raw, depois do parser do web).
- Os exemplos do openapi e do asyncapi são gerados pelos testes dos produtores e mudam nas tarefas de
  implementação. Exceção, por delegação neste PR (task 113, ADR 0023): o teste de contrato de `pkg/event` exige
  que `event.HTTP3Request` tenha toda propriedade do schema, então ele ganha os quatro campos (`*string`, nulos
  até o web preenchê-los) e o exemplo `connection-quic-example.json` é regravado com eles nulos.
- Muda o comportamento em runtime do web e do raw (SYN-ACK com cookie TFO): implantado com as entregas.
