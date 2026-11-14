- store: erro da finalização depois do commit do lote não vira mais Nak (sem reentrega duplicada); as conexões ficam
  na fila e são finalizadas no ciclo seguinte; métricas `fs_store_ingest_errors_total` e
  `fs_store_finalize_retries_total` (task 157).
