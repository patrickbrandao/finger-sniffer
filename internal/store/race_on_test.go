//go:build race

package store

// raceEnabled: o binário de teste foi compilado com -race (o SQLite em Go puro fica várias vezes mais lento).
const raceEnabled = true
