//go:build linux

package capture

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Releitura dos endereços locais com erro ou vazia mantém a lista anterior e avisa (task 191); os pacotes de
// saída continuam "out".
func TestRefreshLocal(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	local := netip.MustParseAddr("172.233.24.85")
	ok := func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("172.233.24.85"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	fail := func() ([]net.Addr, error) { return nil, errors.New("netlinkrib: too many open files") }
	empty := func() ([]net.Addr, error) { return nil, nil }

	// Start com erro ou vazio: Warn, mapa nil, o serviço segue.
	for _, f := range []func() ([]net.Addr, error){fail, empty} {
		buf.Reset()
		if m := refreshLocal(log, "ens192", nil, f); m != nil {
			t.Fatalf("start: %v", m)
		}
		if !strings.Contains(buf.String(), "level=WARN") {
			t.Fatalf("no warn: %q", buf.String())
		}
	}

	cls := &classifier{local: refreshLocal(log, "ens192", nil, ok)}
	if !cls.local[local] {
		t.Fatalf("local: %v", cls.local)
	}
	out := parseFrame(buildFrame(frameOpt{proto: 6, src: local.AsSlice(), dst: []byte{192, 0, 2, 1}, sport: 443, dport: 41234}))
	for name, f := range map[string]func() ([]net.Addr, error){"error": fail, "empty": empty} {
		buf.Reset()
		cls.local = refreshLocal(log, "ens192", cls.local, f)
		if len(cls.local) != 1 || !cls.local[local] {
			t.Fatalf("%s: list replaced: %v", name, cls.local)
		}
		if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "kept=1") {
			t.Fatalf("%s: no warn: %q", name, buf.String())
		}
		if cls.direction(out) != event.DirOut {
			t.Fatalf("%s: outgoing packet labeled in", name)
		}
	}
	// Releitura boa troca a lista.
	other := func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}}, nil
	}
	if m := refreshLocal(log, "ens192", cls.local, other); m[local] || !m[netip.MustParseAddr("2001:db8::1")] {
		t.Fatalf("not replaced: %v", m)
	}
}
