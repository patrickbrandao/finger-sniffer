//go:build !race

package web

// raceSlow escala os tetos de tempo dos testes: sem -race, 1.
const raceSlow = 1
