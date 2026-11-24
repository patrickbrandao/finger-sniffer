# 0076 — Estágios da conexão que sai sem registro e `opened` do bot só depois do handshake

Status: aceita
Data: 2026-11-24

## Contexto
Fato da revisão de 2026-11-21 (task 341), reproduzido num teste fora do repositório: toda 5-tupla nova vira `conn`
na tabela de fluxos e publica, já no SYN, `opened` em `fs.v1.store.connection` (canal do bot) e `connection.opened`
no tempo real. Quando a tentativa sai da tabela sem registro, nenhum estágio final é publicado:
- **avulso** (spec 004 RF-03): TCP sem SYN-ACK (SYN sem resposta, varredura) ou UDP sem resposta; a linha é apagada
  e os pacotes viram `stray_packets`;
- **despejada** pela tabela cheia (spec 004 RF-11a, a partir da ADR 0034 item 1, com a ordem da ADR 0069);
- **probe apagado** pelo `DELETE` (a partir da ADR 0034 item 8, em lotes pela ADR 0068): a conexão aberta fica
  escondida até fechar, sem estágio;
- **só de eventos** (`createEventOnly`): o registro existe, mas a conexão publica `opened`/`updated` e nunca `closed`.

Efeitos: o bot guarda a entrada `opened` por `FS_BOT_CONN_TTL` (10 min) com um `conn_id` que não existe mais no
store, e o cliente do feed que acompanha as conexões abertas pelo `connection.opened` (como sugere
`docs/realtime.md`) acumula entradas que nunca fecham. Mais grave para o bot: o SYN não precisa de handshake e pode
ter origem falsificada; um SYN flood barato publica um `opened` por SYN e, com o índice no teto (ADRs 0061 e 0064),
cada um despeja uma conexão legítima. Publicar só um `closed` não resolve o flood: o índice do bot guarda a entrada
fechada até o TTL (para o casamento pela RF-04 da spec 018), e um SYN flood contra uma porta que escuta recebe
SYN-ACK do kernel, não vira avulso e já fecha hoje por ociosidade do meio-aberto (10 s), ocupando o índice do mesmo
jeito.

O bot só usa a visão do store depois do handshake: o forwardAuth e o resumo do traefix chegam depois de TLS e da
requisição, a consulta e o probe olham conexões completas, e o casamento é pela origem e pelo `started` (SYN), que
não muda. O índice do bot só tem UDP para o h3.

## Decisão
Este registro altera a ADR 0047 item 3 quanto aos estágios de `fs.v1.store.connection`.
1. **Canal do bot (`fs.v1.store.connection`): `opened` só com a conexão estabelecida.** O store publica o primeiro
   estágio de uma conexão no instante em que ela fica estabelecida:
   - TCP: o ACK do cliente depois do SYN-ACK (`times.established`, o mesmo marco que tira a entrada da fila `half`
     da RF-11a), ou o primeiro evento de aplicação da 5-tupla (web ou raw só têm evento de conexão aceita pelo
     kernel; cobre a conexão vista no meio do fluxo, ADR 0041 item 5);
   - UDP: o primeiro datagrama do cliente depois da primeira resposta do espelho, ou o primeiro evento de aplicação
     (h3). Responder não basta: o espelho responde a um Initial QUIC ou a uma consulta DNS com origem falsificada,
     e a origem falsificada não continua a conversa;
   - conexão só de eventos: na criação, como hoje (o evento prova a conexão).

   O primeiro estágio publicado é sempre `opened`, com o estado daquele instante (registro com `started` do SYN ou
   do primeiro datagrama, como antes); evento de aplicação incorporado antes dele não sai como `updated`, entra no
   `opened`. Conexão que sai da tabela sem ter sido estabelecida (avulso, SYN-ACK seguido de RST ou de silêncio,
   UDP respondido uma vez, despejada da fila `half`) não publica **nenhum** estágio no canal do bot, nem `closed`.
   A órfã do reinício (`recoverOrphans`) segue a mesma regra pelo registro gravado: publica `closed` só se o
   registro tiver `times.established` ou evento de aplicação. O modo degradado continua publicando só `opened` e
   `closed`, com o `opened` no mesmo marco.
2. **Toda conexão com `opened` publicado recebe exatamente um estágio final, nos dois canais.** Vale para
   `fs.v1.store.connection` (a partir do `opened` do item 1) e para o tempo real (`connection.opened` continua na
   criação, no primeiro pacote ou evento: o espelho mostra ao cliente que o SYN chegou, mesmo sem handshake). O fim
   é o `closed` / `connection.closed` de sempre, inclusive para a conexão só de eventos (quando ela sai do conjunto
   das só de eventos por ociosidade, `eventOnlyIdle`, sem ter sido adotada por pacotes; adotada, o fim é o da
   conexão dos pacotes, com o mesmo `conn_id`).
3. **Marca `discarded` para a conexão que sai sem registro.** Campo opcional novo no `ConnectionSummary` do openapi
   do store (aditivo, ADR 0001; ausente = a conexão tem registro gravado): `discarded` ∈ `stray` (virou pacotes
   avulsos), `evicted` (despejada pela tabela cheia), `deleted` (probe apagado pelo `DELETE`). Só aparece no
   `closed` / `connection.closed` publicado quando a linha sai do banco sem registro; a API nunca a devolve, porque
   o `conn_id` deixa de existir nela (404). O `connection` desse `closed` é o estado em memória da conexão naquele
   instante (como o `closed` normal: `ended` = último pacote, `close` pelo que foi visto, `timeout` se nada), sem
   BLOBs. Momento e `ts` do `LiveEvent` (ADR 0025): o instante em que o store decidiu — saída da tabela para o
   avulso e para a escondida do probe apagado (`finalizeOne`), o despejo para a `evicted`. No feed, o
   `connection.closed` de um avulso sai junto dos `packet.stray` dos mesmos pacotes.
4. **Bot**: trata o `closed` com `discarded` como qualquer `closed` (substitui o registro e marca fechada; o
   `MatchStore` sem `first` não casa entrada fechada); sem mudança de código obrigatória: o parser já ignora campos
   desconhecidos. Pelo item 1, `stray` nunca chega ao canal do bot; `evicted` só pode chegar de UDP não-QUIC
   respondido e conversado (teto de 2048 da ADR 0069 item 2), e `deleted` de conexão de probe estabelecida. Uma
   tarefa do bot (task 417) fixa essa compatibilidade em teste.
5. **Contratos**: openapi do store 0.8.0 (aditivo: `ConnectionSummary.discarded`); asyncapi 0.8.0 (aditivo: o
   `closed` do `StoreConnectionPayload` pode levar `connection.discarded`; o `opened` passa a ser o da conexão
   estabelecida, mudança de momento sem mudança de forma). Spec 004 (RF-12 e tabela do tempo real) e spec 018
   (Comportamento) atualizadas.

## Alternativas consideradas
- **Só um estágio final novo (`discarded`) e o bot apagando a entrada** (opção B da task 341): fecha o `opened` sem
  fim, mas não resolve o flood: o SYN contra porta que escuta recebe SYN-ACK, não é avulso nem despejado e ocupa o
  índice do bot por 10 min do mesmo jeito; e um estágio novo no enum quebra o bot de hoje, que recusa estágio
  desconhecido (`ParseStoreConnection`). Rejeitada.
- **`closed` com marca sem adiar o `opened`**: aditiva e simples, mas mantém o vetor do flood pelo mesmo motivo.
  Fica só como o item 3, para fechar o ciclo nos dois canais.
- **Adiar também o `connection.opened` do tempo real**: o feed não tem índice a esgotar (fila por cliente com
  descarte, ADR 0034) e perderia o valor de diagnóstico de ver o SYN chegar sem handshake (caminho que bloqueia o
  SYN-ACK). Rejeitada.
- **Marca no payload do asyncapi em vez do `ConnectionSummary`**: o feed também precisa dela e o `data` do
  `connection.closed` é o `ConnectionSummary`; um campo só serve os dois canais.
- **UDP estabelecido pela resposta do espelho (como na RF-11a)**: o espelho responde a origem falsificada; não
  protege o índice. Rejeitada para o canal do bot; a definição da RF-11a para o despejo fica como está.

## Consequências
- Um SYN flood, com ou sem origem falsificada, e uma varredura não chegam ao índice do bot; o teto de conexões e de
  bytes do índice só é disputado por conexões que completaram o handshake (ou UDP com ida e volta do cliente).
- O `opened` do bot sai ~1 RTT depois do SYN (no lote do ACK); o forwardAuth chega depois de TLS e da requisição, então
  a espera pela visão do store (`bot_view_wait_total{missing="tcp"}`) não deve mudar; a carga da F8 seguinte confirma.
- Consultas DNS de ida e volta única deixam de ir ao bot (que não as usa).
- Quem acompanha o feed pode fechar toda conexão aberta pelo `connection.closed`, com ou sem `discarded`;
  `docs/realtime.md` e `docs/bot.md` passam a dizer isso (task 418).
- Implementação: store (task 341: `ingest.go`, `connpub.go`, `correlate.go`), bot (task 417: teste de
  compatibilidade), docs (task 418).
- Spec 018 RF-02 sem mudança de fonte; ADRs 0061 e 0064 (índice no teto) seguem valendo para conexões completas.
