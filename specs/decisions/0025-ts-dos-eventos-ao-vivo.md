# 0025 — `ts` dos eventos ao vivo: instante em que o espelho pôde emitir o fato

Status: aceita (`ts` do `packet.stray` decidido depois do pacote: ver 0026)
Data: 2026-11-09

## Contexto
A carga oficial da task 068 (`test/load/RESULTS.md`, janela `official-50b`, commit `6facb2c`) mediu o RNF-02 como
manda a ADR 0022 (chegada no cliente da 9000 − `ts` do `LiveEvent`): p99 3 952 ms, reprovado. A causa não é
latência do pipeline:
- o raw (e o web, no `fs.v1.web.raw.session`) publica o resumo da sessão **só no fim**, com o `ts` do envelope =
  instante do accept, porque o store associa o evento à conexão pelo `ts` dentro do intervalo dela (spec 004);
- o store repassa esse `ts` ao `connection.updated` que o resumo produz; 4% dos eventos do feed (8 166 de
  ~203 mil) "atrasam" ~3,9 s, que é a vida da conexão no perfil de carga;
- o mesmo vale, em menor número, para o `connection.closed` por ociosidade, cujo `ts` é o último pacote e que só
  pode sair depois de `idle` + 30 s (máximo de 30,2 s no relatório), e para o fechamento de órfãs no reinício.

Sem esses eventos o p99 fica em 818 ms em regime (384 ms com o banco vazio). O `LiveEvent.ts` não tinha semântica
escrita no openapi; a ADR 0022 só dizia "`ts` do evento".

## Decisão
- **`LiveEvent.ts` é o instante em que o espelho teve o fato e pôde emiti-lo**, nunca um instante anterior que
  só fica conhecido depois. Os tempos do fato continuam no `data` (`started`, `ended`) e no registro.
  - `connection.opened`: `ts` do primeiro pacote ou do evento que criou a conexão (sem mudança).
  - `connection.updated`: instante em que o evento de aplicação que o produziu **entrou no stream `FS_EVENTS`**
    (metadado `Timestamp` do JetStream, isto é, a publicação pelo serviço de origem); a atualização tardia de um
    registro já gravado continua com o instante do store (sem mudança).
  - `connection.closed`: FIN/RST/`quic_close`: o fim (`ts` do pacote ou do `http3.connection` com `close`, sem
    mudança); **ociosidade e órfãs do reinício: o instante em que o store decidiu o fechamento**.
  - `http.request`, `dns.query`: `ts` do envelope (sem mudança: são publicados na hora do fato).
  - `packet.stray`: avulso decidido na chegada do pacote (RST sem conexão, ICMP) usa o `ts` do pacote; avulso
    decidido na saída da tabela (fluxo UDP ou SYN sem resposta, por ociosidade) usa **o instante em que o store
    decidiu** (ADR 0026, item 5; task 108). Os instantes dos pacotes ficam no `data` e em `/api/v1/packets`.
  - `stream.dropped`: instante do envio.
- O envelope NATS **não muda**: `ts` continua "quando o fato ocorreu" e o `raw.session` continua com `ts` = accept,
  usado na associação à conexão. Nenhum produtor muda.
- `fs_store_live_delay_seconds` passa a medir do `LiveEvent.ts` até o envio; `fs_store_ingest_lag_seconds` continua
  do `ts` do envelope ao commit.
- A medição do RNF-02 da ADR 0022 não muda (chegada − `ts` do `LiveEvent`, p99 < 1 s, todos os eventos): com esta
  semântica ela deixa de depender da vida das conexões e do `idle`.
- A mudança é do store (task 106). Ela **bloqueia a release**: a carga da task 068 é repetida depois dela, com a
  103 e a 105.

## Alternativas consideradas
- (a) Excluir da medição os resumos retroativos: o feed continuaria com `ts` enganoso para quem o consome (o
  cliente ordena e mede pelo `ts`), e a meta passaria a ter exceções por tipo de evento.
- (b2) O raw publicar o envelope com `ts` = fim e o store associar pelo início do `data`: muda dois produtores
  (raw e web), a regra de associação da spec 004 e o contrato de eventos às vésperas da `v0.1.0`, com risco de
  desencontro de versões no deploy por serviço; o ganho para o feed é o mesmo desta decisão.
- `ts` do `connection.updated` = instante da chegada ao store em vez do metadado do JetStream: esconderia do
  RNF-02 o trecho produtor → NATS → store. Fica como recurso só se o metadado faltar (mensagem sem metadado de
  JetStream, como nos testes de unidade), com o instante do recebimento pelo consumidor.

## Consequências
- Spec 000 (RNF-02), spec 004 (tempo real, métricas, RNF-01) e ADR 0022 apontam para esta ADR.
- Contratos 0.3.4 (documentais): o openapi descreve `LiveEvent.ts`; o asyncapi registra que os resumos de sessão
  levam `ts` = accept e que a publicação é o metadado do JetStream.
- O consumidor do feed que quiser a vida da conexão usa `data.started`/`data.ended`, não o `ts` do evento.
