//go:build !race

package raw

// raceOn liga os ajustes dos testes de memória: sem -race, desligado.
const raceOn = false
