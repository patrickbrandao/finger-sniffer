// Package version guarda a versão e o commit do build, preenchidos por -ldflags no Makefile.
package version

import "fmt"

// Valores padrão usados quando o binário é compilado sem -ldflags (ex.: go test, go run).
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)

// String devolve a identificação do binário no formato "<nome> <versão> (<commit>)".
func String(name string) string {
	return fmt.Sprintf("%s %s (%s)", name, Version, Commit)
}
