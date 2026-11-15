- test(e2e): `TestStoreIdleKeepsOneConnection` (h1 com `idle=300` parada 200 s e reusada: o store registra uma
  conexão só, ADR 0034 item 2) e caso 11 aceitando `ts_clock_hz` nulo por execução (task 201), com 5 execuções
  seguidas registradas em `test/load/RESULTS.md` (task 217).
