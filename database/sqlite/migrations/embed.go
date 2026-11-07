// Package migrations embute as migrations goose do SQLite do store (ADR 0005).
package migrations

import "embed"

// FS contém os arquivos *.sql desta pasta, na ordem de versão do goose.
//
//go:embed *.sql
var FS embed.FS
