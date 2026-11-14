- store: falha de transação no ingest desfaz também a memória (conexões criadas pelo lote recriadas com o mesmo ID na
  reentrega, conexões só de eventos, pendentes e estado de aplicação); erro de SQL de pacote vira Nak em vez de "lote
  ruim"; fila de finalização com até 5 tentativas uma a uma e expurgo de órfãs abertas na retenção (task 139).
