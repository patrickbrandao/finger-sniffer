package store

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// loopbackAPI é o endereço local de diagnóstico em que a API sempre escuta (spec 004 RF-07, ADR 0023).
var loopbackAPI = netip.MustParseAddr("127.0.0.1")

// listenIPs devolve os IPs da API: 127.0.0.1 e os IPs públicos FS_LISTEN_IPV4/FS_LISTEN_IPV6 (vazio = ausente),
// nunca "*" (ADR 0001, ADR 0023).
func listenIPs() ([]netip.Addr, error) {
	ips := []netip.Addr{loopbackAPI}
	for _, k := range []struct {
		key string
		v4  bool
	}{{"FS_LISTEN_IPV4", true}, {"FS_LISTEN_IPV6", false}} {
		s := strings.TrimSpace(service.Env(k.key, ""))
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Is4() != k.v4 || a.Zone() != "" {
			return nil, fmt.Errorf("store: %s invalid: %q", k.key, s)
		}
		if a != loopbackAPI {
			ips = append(ips, a)
		}
	}
	return ips, nil
}

// apiAddrs combina a porta de addr com cada IP de ListenIPs; sem ListenIPs (testes), usa addr como veio.
func (c Config) apiAddrs(addr string) ([]string, error) {
	if len(c.ListenIPs) == 0 {
		return []string{addr}, nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("store: api address %q: %w", addr, err)
	}
	out := make([]string, 0, len(c.ListenIPs))
	for _, ip := range c.ListenIPs {
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out, nil
}

// listenAll abre todos os endereços; se um falha, fecha os já abertos.
func listenAll(addrs []string) ([]net.Listener, error) {
	ls := make([]net.Listener, 0, len(addrs))
	for _, a := range addrs {
		l, err := net.Listen("tcp", a)
		if err != nil {
			for _, o := range ls {
				_ = o.Close()
			}
			return nil, fmt.Errorf("store: listen %s: %w", a, err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// serveAll atende cada listener com serve; o canal recebe o primeiro erro que não seja o fechamento normal
// (ou nil quando todos fecham pelo Shutdown).
func serveAll(ls []net.Listener, serve func(net.Listener) error) <-chan error {
	errc := make(chan error, len(ls))
	done := make(chan error, len(ls))
	for _, l := range ls {
		go func() {
			err := serve(l)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			done <- err
		}()
	}
	go func() {
		var first error
		for range ls {
			if err := <-done; err != nil && first == nil {
				first = err
				break
			}
		}
		errc <- first
	}()
	return errc
}

func addrsString(ls []net.Listener) string {
	s := make([]string, len(ls))
	for i, l := range ls {
		s[i] = l.Addr().String()
	}
	return strings.Join(s, ",")
}
