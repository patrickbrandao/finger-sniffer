- fix(store): `ingest backlog` e `fs_store_ingest_backlog_seconds` calculados na leitura (parede − publicação da
  última mensagem processada): crescem com o ingest parado em vez de congelar no último lote (task 338).
