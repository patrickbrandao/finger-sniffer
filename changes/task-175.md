- infra: actions do CI e do release fixadas por SHA de 40 caracteres (versão em comentário); Redocly CLI e
  AsyncAPI CLI saem do `npx -y` e passam a vir de `scripts/contracts-tools/` com `package-lock.json` versionado
  e `npm ci --ignore-scripts`; `verify-test.sh` confere as duas regras (task 175).
