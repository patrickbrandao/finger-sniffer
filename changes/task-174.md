- infra: os testes `linux_priv` do `verify-full` usam um diretório remoto próprio na vps602 (`mktemp -d`) e apagam
  só ele, também em falha de compilação, de `scp` ou por sinal; teste em `scripts/verify-test.sh` (task 174).
