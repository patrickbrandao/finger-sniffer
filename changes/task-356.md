- verify-full `--e2e`: passos `versão implantada` (antes; health da 9001 com `versions_match=true` e o store na versão
  do `git describe` local ou de `FS_E2E_EXPECT_VERSION`, senão reprova sem rodar o e2e) e `versão implantada (depois)`
  (roda mesmo com o e2e reprovado; reprova se a versão mudou na suíte) (spec 017 RF-09, task 356).
