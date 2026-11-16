// Package botmigrations embute as migrations goose do banco do bot (spec 018 "Dados", ADR 0047 item 2).
package botmigrations

import "embed"

// FS contém os arquivos *.sql desta pasta, na ordem de versão do goose.
//
//go:embed *.sql
var FS embed.FS
