# 0017 — Request/reply fora do stream e `conn_id` reservado pelo store

Status: aceita
Data: 2026-11-08

## Contexto
Dois fatos novos, achados ao preparar a F3:
- O stream `FS_EVENTS` assina `fs.v1.>` (ADRs 0003 e 0016). Uma requisição NATS core publicada num subject que
  algum stream assina recebe do JetStream um `PubAck` no inbox de resposta. Os request/reply
  `fs.v1.dns.acme.set|clear` cairiam no stream, e o web poderia receber o `PubAck` do JetStream no lugar da
  resposta do dns.
- A spec 005 RF-06 pede o `conn_id` no corpo de `GET /p/<id>/`, mas o `conn_id` (ULID) é criado pelo store a partir
  dos pacotes (spec 004 RF-02). O web não tem como saber o ID.

## Decisão
- O stream `FS_EVENTS` assina uma **lista explícita** de subjects de eventos: `fs.v1.capture.>`, `fs.v1.web.>`,
  `fs.v1.raw.>`, `fs.v1.dns.query`, `fs.v1.svc.>`. Request/reply (`fs.v1.dns.acme.set|clear`,
  `fs.v1.store.conn_id`) ficam fora e são NATS core. Um subject de evento novo entra na lista no mesmo PR que o
  cria no asyncapi.yaml. Substitui o `fs.v1.>` das ADRs 0003 e 0016; o resto delas continua valendo.
- Novo request/reply **`fs.v1.store.conn_id`**: o web (e quem mais precisar) manda a 5-tupla logo depois do accept
  (ou do primeiro datagrama QUIC, F4) e o store responde o `conn_id`:
  - se já existe conexão aberta com essa 5-tupla, responde o ID dela;
  - senão, **reserva** um ULID para a 5-tupla por 30 s; a próxima conexão criada pelos pacotes com essa 5-tupla
    usa o ID reservado. Reserva não usada expira sem efeito.
  - O web pede de forma assíncrona e espera no máximo 250 ms, só quando precisa (corpo de `/p/<id>/`). Sem
    resposta, o corpo traz `conn_id: unknown` e o store segue com o próprio ID.

## Alternativas consideradas
- `NoAck` no stream: resolve o `PubAck`, mas deixa as requisições guardadas no stream de eventos.
- Prefixo próprio para request/reply (`fs.v1.rpc.>`): obriga renomear subjects já citados em várias specs.
- O web gerar o ULID e o store adotar: o registro já existe com outro ID quando o primeiro evento chega; renomear a
  chave com tabelas filhas exige migration e é frágil.
- Tirar o `conn_id` do corpo e devolver só a 5-tupla: muda comportamento acordado (spec 005 RF-06).

## Consequências
- Mais uma dependência síncrona web → store, limitada a 250 ms e com degradação explícita.
- O store atende request/reply fora do laço de ingest; a tabela de fluxos precisa de trava.
- Ao criar um subject de evento novo, o PR atualiza a lista do stream (store) e o asyncapi.yaml juntos.
