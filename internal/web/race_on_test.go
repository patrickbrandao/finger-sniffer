//go:build race

package web

// raceSlow escala os tetos de tempo dos testes: com -race o código roda até ~10x mais devagar.
const raceSlow = 10
