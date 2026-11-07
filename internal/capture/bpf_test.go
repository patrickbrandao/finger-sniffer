package capture

import (
	"testing"

	"golang.org/x/net/bpf"
)

var excluded = []uint16{48022, 48161, 9000, 9001}

func TestExcludeFilter(t *testing.T) {
	prog, err := ExcludeFilter(excluded)
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		frame  frameOpt
		accept bool
	}{
		{"tcp4 dst 443", frameOpt{proto: 6, sport: 41234, dport: 443}, true},
		{"tcp4 dst ssh", frameOpt{proto: 6, sport: 41234, dport: 48022}, false},
		{"tcp4 src ssh", frameOpt{proto: 6, sport: 48022, dport: 41234}, false},
		{"tcp4 api 9001", frameOpt{proto: 6, sport: 50000, dport: 9001}, false},
		{"udp4 snmp src", frameOpt{proto: 17, sport: 48161, dport: 1000}, false},
		{"udp4 dns", frameOpt{proto: 17, sport: 5353, dport: 53}, true},
		{"tcp4 with ip options", frameOpt{proto: 6, ihlWords: 7, sport: 1, dport: 48022}, false},
		{"tcp4 with ip options ok", frameOpt{proto: 6, ihlWords: 7, sport: 1, dport: 80}, true},
		{"tcp4 non-first fragment", frameOpt{proto: 6, fragOff: 10, sport: 0, dport: 48022}, true},
		{"icmp4", frameOpt{proto: 1}, true},
		{"tcp6 dst 443", frameOpt{v6: true, proto: 6, sport: 1, dport: 443}, true},
		{"tcp6 dst ssh", frameOpt{v6: true, proto: 6, sport: 1, dport: 48022}, false},
		{"udp6 src 9000", frameOpt{v6: true, proto: 17, sport: 9000, dport: 1}, false},
		{"icmp6", frameOpt{v6: true, proto: 58}, true},
		{"vlan tcp4 ssh", frameOpt{vlan: true, proto: 6, sport: 1, dport: 48022}, false},
		{"vlan tcp4 80", frameOpt{vlan: true, proto: 6, sport: 1, dport: 80}, true},
		{"vlan tcp6 ssh", frameOpt{vlan: true, v6: true, proto: 6, sport: 48022, dport: 1}, false},
		{"vlan udp6 53", frameOpt{vlan: true, v6: true, proto: 17, sport: 1, dport: 53}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := vm.Run(buildFrame(tt.frame))
			if err != nil {
				t.Fatal(err)
			}
			if got := n > 0; got != tt.accept {
				t.Fatalf("accept=%v, want %v (ret %d)", got, tt.accept, n)
			}
		})
	}
	// ARP e frames curtos são aceitos (o filtro não deve descartar o que não entende).
	arp := buildFrame(frameOpt{})
	arp[12], arp[13] = 0x08, 0x06
	if n, _ := vm.Run(arp); n == 0 {
		t.Fatal("arp must be accepted")
	}
	if _, err := bpf.Assemble(prog); err != nil {
		t.Fatalf("assemble: %v", err)
	}
}

func TestExcludeFilterNoPorts(t *testing.T) {
	prog, err := ExcludeFilter(nil)
	if err != nil || len(prog) != 1 {
		t.Fatalf("%v %v", prog, err)
	}
}

func TestExcludeFilterTooMany(t *testing.T) {
	if _, err := ExcludeFilter(make([]uint16, 51)); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzExcludeFilter(f *testing.F) {
	prog, _ := ExcludeFilter(excluded)
	vm, _ := bpf.NewVM(prog)
	f.Add(buildFrame(frameOpt{proto: 6, sport: 1, dport: 48022}))
	f.Fuzz(func(t *testing.T, b []byte) {
		// A VM não pode falhar com nenhum frame (no kernel, leituras fora do pacote viram "drop").
		_, _ = vm.Run(b)
	})
}
