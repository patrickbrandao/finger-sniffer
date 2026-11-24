//go:build !linux && !darwin

package web

import "net"

// rxPending fora do Linux e do macOS não consulta o kernel: o pipelined fica só com o bufio.
func rxPending(net.Conn) bool { return false }
