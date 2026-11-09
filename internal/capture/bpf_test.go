package capture

import (
	"testing"

	"golang.org/x/net/bpf"
)

var excluded = []uint16{48022, 48161, 9000, 9001}

func TestExcludeFilter(t *testing.T) {
	prog, err := ExcludeFilter(excluded, 0)
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
		{"tcp6 hbh 9001", frameOpt{v6: true, v6ext: []byte{ipv6HopByHop}, proto: 6, sport: 1, dport: 9001}, false},
		{"tcp6 hbh 443", frameOpt{v6: true, v6ext: []byte{ipv6HopByHop}, proto: 6, sport: 1, dport: 443}, true},
		{"vlan udp6 hbh src 9000", frameOpt{vlan: true, v6: true, v6ext: []byte{ipv6HopByHop}, proto: 17, sport: 9000, dport: 1}, false},
		{"tcp6 first fragment ssh", frameOpt{v6: true, v6ext: []byte{ipv6Fragment}, proto: 6, sport: 48022, dport: 1}, false},
		{"tcp6 non-first fragment", frameOpt{v6: true, v6ext: []byte{ipv6Fragment}, v6fragOff: 3, proto: 6, sport: 48022, dport: 1}, true},
		{"tcp6 hbh+rt+dst+ah 9001", frameOpt{v6: true, v6ext: []byte{ipv6HopByHop, ipv6Routing, ipv6DstOpts, ipv6AH}, proto: 6, sport: 1, dport: 9001}, false},
		{"tcp6 six ext 48022", frameOpt{v6: true, v6ext: []byte{0, 60, 43, 44, 51, 60}, proto: 6, sport: 1, dport: 48022}, false},
		{"tcp6 seven ext (bpf gives up)", frameOpt{v6: true, v6ext: []byte{0, 60, 43, 44, 51, 60, 60}, proto: 6, sport: 1, dport: 48022}, true},
		{"icmp6 after hbh", frameOpt{v6: true, v6ext: []byte{ipv6HopByHop}, proto: 58}, true},
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
	prog, err := ExcludeFilter(nil, 0)
	if err != nil || len(prog) != 1 || prog[0] != (bpf.RetConstant{Val: maxSnap}) {
		t.Fatalf("%v %v", prog, err)
	}
}

func TestExcludeFilterTooMany(t *testing.T) {
	if _, err := ExcludeFilter(make([]uint16, 51), 0); err == nil {
		t.Fatal("expected error")
	}
}

// Com 50 portas (o máximo) todos os saltos cabem e o programa monta.
func TestExcludeFilterMaxPorts(t *testing.T) {
	ports := make([]uint16, 50)
	for i := range ports {
		ports[i] = uint16(1000 + i) //nolint:gosec // teste
	}
	prog, err := ExcludeFilter(ports, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bpf.Assemble(prog)
	if err != nil || len(raw) > 4096 {
		t.Fatalf("assemble: %d %v", len(raw), err)
	}
	vm, _ := bpf.NewVM(prog)
	for _, o := range []frameOpt{
		{vlan: true, v6: true, v6ext: []byte{0, 60, 43, 44, 51, 60}, proto: 6, sport: 1, dport: 1049},
		{vlan: true, proto: 17, sport: 1049, dport: 1},
		{v6: true, proto: 6, sport: 1, dport: 1000},
	} {
		if n, _ := vm.Run(buildFrame(o)); n != 0 {
			t.Fatalf("%+v accepted", o)
		}
	}
	if n, _ := vm.Run(buildFrame(frameOpt{vlan: true, v6: true, v6ext: []byte{0}, proto: 6, sport: 1, dport: 999})); n == 0 {
		t.Fatal("port 999 must be accepted")
	}
}

// O filtro corta o que aceita no snaplen (spec 003 RF-01).
func TestExcludeFilterSnaplen(t *testing.T) {
	for _, ports := range [][]uint16{nil, excluded} {
		prog, err := ExcludeFilter(ports, 128)
		if err != nil {
			t.Fatal(err)
		}
		vm, _ := bpf.NewVM(prog)
		for _, o := range []frameOpt{
			{proto: 6, sport: 1, dport: 443, payload: 1400},
			{v6: true, v6ext: []byte{0}, proto: 6, sport: 1, dport: 443, payload: 1400},
			{proto: 1, payload: 1000},
		} {
			if n, _ := vm.Run(buildFrame(o)); n != 128 {
				t.Fatalf("ports=%v %+v: ret %d, want 128", ports, o, n)
			}
		}
	}
	// Acima do teto: o frame inteiro (o kernel limita o retorno ao tamanho do pacote; a VM não).
	prog, _ := ExcludeFilter(excluded, 1<<30)
	vm, _ := bpf.NewVM(prog)
	if n, _ := vm.Run(buildFrame(frameOpt{proto: 6, sport: 1, dport: 443, payload: 9000})); n != maxSnap {
		t.Fatalf("ret %d", n)
	}
}

func FuzzExcludeFilter(f *testing.F) {
	prog, _ := ExcludeFilter(excluded, 0)
	vm, _ := bpf.NewVM(prog)
	f.Add(buildFrame(frameOpt{proto: 6, sport: 1, dport: 48022}))
	f.Add(buildFrame(frameOpt{v6: true, v6ext: []byte{0, 44, 51}, proto: 6, sport: 1, dport: 48022}))
	c := &classifier{excluded: toSet(excluded)}
	f.Fuzz(func(t *testing.T, b []byte) {
		// A VM não pode falhar com nenhum frame (no kernel, leituras fora do pacote viram "drop").
		n, err := vm.Run(b)
		if err != nil {
			t.Fatal(err)
		}
		// O que o kernel aceita e tem porta excluída visível ao parser só pode ser IPv6 com extensões demais
		// para o BPF (a conferência em espaço de usuário descarta).
		if fr := parseFrame(b); n > 0 && c.excludedPort(fr) && !fr.src.Is6() {
			t.Fatalf("bpf accepted excluded frame %+v", fr)
		}
	})
}
