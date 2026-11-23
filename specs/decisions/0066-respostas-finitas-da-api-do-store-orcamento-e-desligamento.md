# 0066 — Respostas finitas da API do store: orçamento de bytes, teto por resposta e 503 no desligamento

Status: aceita
Data: 2026-11-22

## Contexto
A revisão de 2026-11-21 achou dois problemas nas rotas JSON finitas da API do store (todas menos SSE, WS, `/pcap` e
`/raw`):
- **task 319**: as rotas montam a resposta inteira na memória (`/probes/{id}` com até 1000 registros completos,
  `/packets` com até 1000 frames em base64, `/connections`, `/connections/{id}`, `/dns`) e não têm teto de bytes nem
  de respostas em andamento. A prova mostrou 40 clientes que não leem segurando 525 MiB de heap; o item 1 (prazo de
  escrita de 60 s por resposta, PR #293) limita o tempo, não a memória simultânea. E o tamanho de um registro não tem
  teto no store (ADR 0018 limita o evento, não o registro), então um `/probes/{id}` de registros grandes monta
  centenas de MiB mesmo para um cliente que lê. O teto de 1000 itens da ADR 0032 contava itens, não bytes.
- **task 340**: o contexto base do servidor é cancelado no desligamento; o `writeErr` trata `context.Canceled`
  como "cliente desistiu" e não escreve nada, e o `net/http` completa um `200` sem corpo. Todo deploy com um `wait`
  em curso entrega ao cliente um 200 que não é `Probe`.

A ADR 0032 decidiu o teto de 64 esperas e de 4 downloads de BLOB, e descartou o `WriteTimeout` global (quebraria
SSE, WS e long-poll). Fato novo: a medida da 319 e o 200 vazio da 340.

## Decisão
1. **Orçamento de bytes das respostas JSON em andamento.** Um contador do processo (constante **256 MiB**, sem
   variável) soma os bytes das respostas finitas montadas e ainda não escritas: `getProbe`, `listConnections`,
   `getConnection`, `listDNSQueries`, `listStrayPackets`. A reserva acompanha a montagem (cada `record_json`, frame
   ou linha lida soma o seu tamanho; a serialização soma o corpo) e é devolvida quando a escrita termina, falha ou
   vence o prazo de 60 s do item 1 da task 319 (o `defer` do handler). Nunca bloqueia: não cabe → a montagem é
   abandonada e a rota responde **`503`** com **`Retry-After: 1`** e corpo `Error` `{"error":"busy"}`. Health e
   `openapi.yaml` ficam fora (pequenos e estáticos).
2. **Teto de bytes por resposta: 64 MiB.** `getProbe` para de acrescentar conexões (e consultas DNS) quando o corpo
   chega a 64 MiB e marca `truncated: true`, com a mesma semântica do corte de 1000 (o restante segue em
   `/connections?probe=` e `/dns?probe=`; `all_closed` e o critério do `wait` olham o conjunto inteiro). As listas
   (`/connections`, `/dns`, `/packets`) devolvem menos itens que `limit` quando o corpo chegaria a 64 MiB; o
   cliente continua pela janela de tempo (`until`/`since`). Um registro único (`getConnection`) nunca é cortado:
   conta inteiro no orçamento do item 1 (o tamanho dele fica limitado pela ADR 0067).
3. **Desligamento.** A `API` recebe o sinal de desligamento (ligado antes de cancelar o contexto base e antes do
   `Shutdown`). Rota finita cuja consulta ou espera termina com `context.Canceled` **com o sinal ligado** responde
   **`503`** com **`Retry-After: 1`** e `{"error":"shutting down"}`; sem o sinal (o cliente foi embora) segue sem
   escrever nada, como hoje. Vale para todas as rotas finitas, inclusive `deleteProbe`, `/pcap` e `/raw`. SSE e WS
   só fecham, como hoje.
4. **Métricas.** `fs_store_api_json_bytes_in_flight` (gauge, bytes reservados no item 1) e
   `fs_store_api_rejected_total{route,reason=busy|shutting_down}` (os 503 dos itens 1 e 3; os 503 das 64 esperas e
   dos 4 downloads continuam só em `fs_store_api_requests_total{code="503"}`).
5. **Contrato.** openapi **0.7.0** (aditivo): a resposta `Busy` descreve os três motivos (teto de esperas,
   orçamento de respostas, desligamento) e passa a ser declarada em `listConnections`, `getConnection`,
   `listDNSQueries`, `listStrayPackets` e `deleteProbe`; `BlobBusy` ganha o desligamento; a descrição de
   `Probe.truncated` e das listas ganha o corte por bytes. Aplicado por delegação (specs/002, ADR 0023) pelas tarefas de implementação, junto com o código, porque os testes de contrato exigem struct e casos; o bloco exato fica nas tarefas.

## Alternativas consideradas
- **Teto de respostas em andamento como o dos BLOBs** (ex.: 16 por rota): simples, mas não limita o tamanho de uma
  resposta de registros grandes, que é o agravante da 319; o orçamento em bytes cobre os dois.
- **Serializar em streaming** (escrever cada registro ao ler): tira a memória da montagem, mas o `Probe` precisa de
  `all_closed`/`truncated`/`wait_met` antes ou depois das listas e o erro no meio deixa um JSON quebrado com 200;
  fica para uma ADR futura se o orçamento morder no uso legítimo.
- **`500` documentado no desligamento**: o cliente não saberia que tentar de novo resolve; o `503` com
  `Retry-After` já é o código de "tente de novo" da API.

## Consequências
- Spec 004 (Comportamento, erros da API, Métricas), openapi 0.7.0 e `docs/api.md` (docs) atualizados.
- Tarefas: 319 itens 2 e 3 (orçamento, teto por resposta, teste com clientes que não leem), 340 (sinal de
  desligamento e teste). As duas tocam `internal/store/api.go`: em série (319 antes).
- Com o orçamento, o pior caso de memória da API fica em ~256 MiB + o que as 64 esperas e os 4 downloads seguram,
  dentro do `GOMEMLIMIT` do store.
