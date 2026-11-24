//go:build race

package web

// raceSlow escala os tetos de tempo dos testes: com -race o código roda até ~10x mais devagar.
const raceSlow = 10

// retainFactor é o teto de memória retida sobre a reservada nos testes de orçamento: com -race as alocações
// do mesmo caminho ficam maiores (instrumentação), e 2× deixa margem de ~0%.
const retainFactor = 3
