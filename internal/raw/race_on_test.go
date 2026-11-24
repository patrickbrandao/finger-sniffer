//go:build race

package raw

// raceOn liga os ajustes dos testes de memória: com -race as alocações são instrumentadas e o tempo cresce.
const raceOn = true
