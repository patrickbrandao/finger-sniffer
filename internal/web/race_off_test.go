//go:build !race

package web

// raceSlow escala os tetos de tempo dos testes: sem -race, 1.
const raceSlow = 1

// retainFactor é o teto de memória retida sobre a reservada nos testes de orçamento (ADR 0070).
const retainFactor = 2
