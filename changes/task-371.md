- bot: na 9002 o ingest cobra por registro (balde por chave, padrão 500/s e rajada 2 048, `key create --ingest-rate
  --ingest-burst`, migration 0003 com `key_usage_daily.records`); cada chave fica com até 10% (todas juntas 50%) dos
  tetos do índice e dos agregados (`reason="key"`) e até 4 clientes do feed (48 da 9002) (task 371, ADR 0073 item 3).
