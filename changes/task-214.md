- `TestRetentionDoesNotStallIngest` deixa de depender de um teto fixo sob `-race`: confere que nenhum DELETE passa
  de um lote e que a espera do ingest fica em 2× o maior passo do expurgo medido no mesmo processo (200 ms só sem
  `-race`); `TestInvalidKeysRequest` roda com ociosidade de 30 s (task 214).
- Carga do orçamento de entrada do web (`test/load/budget.sh`, `budgetload`): orçamento cheio, 2540 recusas, sem
  reinício, mas o web encostou no `MemoryMax=96M` (47 403 eventos `max`); resultado em `test/load/RESULTS.md`.
