//go:build !linux

package web

import "syscall"

// enableTFO não faz nada fora do Linux (o espelho só roda em Linux; aqui é o ambiente de desenvolvimento).
func enableTFO(syscall.RawConn, int) error { return nil }
