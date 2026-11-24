- verify: `p0f.fp` real de `deploy/versions.env` em `tmp/p0f/` com `FS_P0F_DB` para os testes (full, lotes do store,
  norace); modo `verify.sh norace` com os testes de tempo sem `-race` e job `norace` no CI com tmpfs de 16 MiB para o
  `TestDBFullRealTmpfs`; `race-check` espera o `norace` (spec 017 RF-08b e RF-08c, task 360).
