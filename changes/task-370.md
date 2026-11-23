- bot: ingest com até 8 lotes simultâneos (6 da 9002, 2 por chave da 9002) pegos antes de ler o corpo — 503 `busy`
  ou 429 com `Retry-After: 1` — e prazo de 10 s para o corpo (400); `fs_bot_ingest_refused_total{reason}`
  (task 370, ADR 0073 item 2).
