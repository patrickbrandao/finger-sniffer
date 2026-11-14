- store: evento de conexão só de eventos cuja linha saiu do banco (`DELETE` de probe, teto de tamanho) não prende mais
  o ingest em laço de Nak: a entrada em memória é esquecida e o evento segue a regra do evento sem conexão, com
  `conn_id` novo (task 140).
