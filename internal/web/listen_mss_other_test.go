//go:build !linux

package web

import "net"

// testListenConfig devolve a configuração dos listeners do harness (fora do Linux, a padrão: o macOS não
// reduz o SO_RCVBUF autoajustado, ver listen_mss_linux_test.go).
func testListenConfig() net.ListenConfig { return net.ListenConfig{} }
