# 0067 — Teto das listas do registro e dos eventos de uma conexão aberta

Status: aceita
Data: 2026-11-22

## Contexto
O store guarda em memória, para cada conexão aberta, todas as requisições HTTP/1 (`http[]`), os streams h2
(`http2.streams[]`) e as requisições h3 (`http3.requests[]`), e grava cada evento em `app_events`, sem teto por
conexão; só os frames WebSocket têm (ADR 0018). O web atende requisições sem limite numa conexão keep-alive (spec
005 RF-08), e a ociosidade conta do último pacote. A task 318 mediu: com 25 600 requisições numa conexão aberta o
registro chega a 15,9 MiB, o lote do ingest fica 10× mais lento e cada `updated` de `fs.v1.store.connection` leva
377 ms no publicador; o expurgo não apaga eventos de conexão aberta. A ADR 0032 item 8 deixou `streams_truncated`
fora ("o teto de 1000 streams continua sem marca"), contando com o teto do parser h2; o HTTP/1 nunca teve teto.

## Decisão
1. **Listas com teto de 1000 itens por conexão**: `http[]`, `http2.streams[]` e `http3.requests[]` guardam os 1000
   primeiros (por `index` no h1, por chegada no h2/h3; substituir um item já listado pelo mesmo `stream_id`
   continua valendo; `stream_id` 0 conta como item). Acima disso o store só conta. `requests` continua o total
   h1+h2+h3. Marcas aditivas no `Connection`: `http_truncated` (raiz), `http2.streams_truncated` e
   `http3.requests_truncated` (booleanos; ausente = `false`). Altera a ADR 0032 item 8 quanto a
   `streams_truncated`.
2. **Eventos de aplicação com teto de bytes por conexão aberta**: os payloads gravados em `app_events` de uma
   conexão somam no máximo `FS_PCAP_MAX_BYTES_PER_CONN` (16 MiB, o mesmo teto do pcap). Acima, o evento não é
   gravado (a análise que cabe nas listas já está no registro) e conta em `fs_store_app_events_dropped_total`.
   `loadAppState` (reinício) aplica os mesmos tetos.
3. **Custo constante por atualização**: acima do teto, um evento a mais não remonta o registro inteiro; o
   publicador e o `liveStage` usam o JSON das listas em cache (como já é feito com `tls` e `h3Level`) e só
   reserializam o que mudou. Meta do teste: tempo do lote e do `updated` com 5 000 requisições igual (± 50%) ao com
   1000.
4. **O web não ganha teto de requisições por conexão**: a spec 005 RF-08 fica como está.
5. **Contrato**: openapi 0.7.0 (junto com a ADR 0066) e asyncapi 0.7.0 (o `Connection` de
   `fs.v1.store.connection` vem do openapi). Aplicado por delegação (specs/002, ADR 0023) pelas tarefas de implementação, junto com o código, porque os testes de contrato exigem struct e casos; o bloco exato fica nas tarefas.

## Alternativas consideradas
- **Fechar a conexão no web depois de N requisições**: contraria a spec 005 RF-08 (todo fechamento observado vem do
  cliente) e muda o que o espelho mede; o problema é de armazenamento, não do protocolo.
- **Teto só de bytes do registro**: deixa o custo por item crescer com o tamanho de cada evento e não dá ao cliente
  uma regra simples ("as 1000 primeiras"), igual à do probe.
- **Expurgar eventos de conexão aberta pelo tamanho**: apagaria dados ainda em uso pela montagem do registro.

## Consequências
- Spec 004 (tabela "Montagem do registro", Métricas) e openapi atualizados; `docs/api.md` (docs).
- Task 318 (implementer-store). Os 1000 × 16 MiB de eventos possíveis no pior caso ficam no mesmo patamar do pcap em
  memória (RF-04a), já coberto pelo expurgo por tamanho das conexões encerradas e pelo modo banco cheio (ADR 0045).
- O bot vê no máximo 1000 requisições resumidas por conexão do store (o índice dele já guarda só 16, ADR 0056).
