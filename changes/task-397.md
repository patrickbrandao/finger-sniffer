- CI: lint, testes com tag e govulncheck no job `static` e o fuzz curto no job `fuzz` (modos `verify.sh static` e
  `verify.sh fuzz`), em paralelo ao `verify-full`, que os pula com `FS_SKIP_STATIC`/`FS_SKIP_FUZZ`; `race-check` espera
  todos os jobs e o `verify-test.sh` confere que todo passo do full está em algum job (spec 017 RF-11, task 397).
