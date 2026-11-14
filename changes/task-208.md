- Testes de contrato (store e e2e) usam o Redocly travado em `scripts/contracts-tools/` em vez de `npx -y`; sem o
  binário pulam com a instrução de instalação (no CI o teste do store falha) e um teste novo prova que o lint
  reprova um valor fora do schema (task 208).
