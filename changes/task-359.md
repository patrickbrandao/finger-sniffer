- verify-full: passo `testes com tag` (testes `load`, vet de `e2e`/`golden` e de `linux_priv` com `GOOS=linux`; falha
  se um pacote com tag ficar fora dos padrões); no quick, só os pacotes com tag afetados. Lint com
  `build-tags: [e2e, load, golden]`; `TestF8SimOffline` sem a tag `e2e` (spec 017 RF-08a, task 359).
