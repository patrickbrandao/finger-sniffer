// Package capture é o serviço que captura na íntegra os pacotes da eth0 e os publica no NATS em lotes FSPB v1
// (spec 003, ADRs 0004, 0011, 0015).
package capture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// Snaplen padrão aceito pelo filtro (o frame inteiro).
const acceptAll = 0x40000

// ExcludeFilter monta o programa BPF clássico que descarta, no kernel, os pacotes TCP e UDP cuja porta de origem
// ou de destino está em ports (spec 003 RF-02). Todo o resto é aceito por inteiro: ICMP, fragmentos não iniciais,
// IPv6 com cabeçalhos de extensão, ARP etc. Suporta Ethernet com e sem uma etiqueta VLAN 802.1Q.
func ExcludeFilter(ports []uint16) ([]bpf.Instruction, error) {
	if len(ports) > 50 {
		return nil, fmt.Errorf("capture: too many excluded ports (%d)", len(ports))
	}
	a := &asm{}
	if len(ports) == 0 {
		a.emit(bpf.RetConstant{Val: acceptAll})
		return a.resolve()
	}

	// Tipo Ethernet; VLAN desloca tudo em 4 bytes.
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jeq(0x8100, "vlan", "")
	a.l2(14, ports)
	a.label("vlan")
	a.emit(bpf.LoadAbsolute{Off: 16, Size: 2})
	a.l2(18, ports)
	a.label("accept")
	a.emit(bpf.RetConstant{Val: acceptAll})
	a.label("drop")
	a.emit(bpf.RetConstant{Val: 0})
	return a.resolve()
}

// l2 gera o trecho para um cabeçalho L2 de tamanho l2len, com o tipo Ethernet já no acumulador.
func (a *asm) l2(l2len uint32, ports []uint16) {
	v4, v6 := a.uniq("v4"), a.uniq("v6")
	a.jeq(0x0800, v4, "")
	a.jeq(0x86dd, v6, "accept")

	// IPv4: protocolo, fragmento, IHL.
	a.label(v4)
	a.emit(bpf.LoadAbsolute{Off: l2len + 9, Size: 1})
	tcp4 := a.uniq("l4")
	a.jeq(6, tcp4, "")
	a.jeq(17, tcp4, "accept")
	a.label(tcp4)
	a.emit(bpf.LoadAbsolute{Off: l2len + 6, Size: 2})
	a.jset(0x1fff, "accept", "") // fragmento não inicial: sem portas
	a.emit(bpf.LoadMemShift{Off: l2len})
	a.ports(bpf.LoadIndirect{Off: l2len, Size: 2}, bpf.LoadIndirect{Off: l2len + 2, Size: 2}, ports)

	// IPv6: só TCP/UDP logo após o cabeçalho fixo.
	a.label(v6)
	a.emit(bpf.LoadAbsolute{Off: l2len + 6, Size: 1})
	tcp6 := a.uniq("l4")
	a.jeq(6, tcp6, "")
	a.jeq(17, tcp6, "accept")
	a.label(tcp6)
	a.ports(bpf.LoadAbsolute{Off: l2len + 40, Size: 2}, bpf.LoadAbsolute{Off: l2len + 42, Size: 2}, ports)
}

// ports compara a porta de origem e a de destino com a lista; casou → drop; senão → accept.
func (a *asm) ports(src, dst bpf.Instruction, ports []uint16) {
	for _, load := range []bpf.Instruction{src, dst} {
		a.emit(load)
		for _, p := range ports {
			a.jeq(uint32(p), "drop", "")
		}
	}
	a.jmp("accept")
}

// asm é um montador mínimo com rótulos simbólicos para os saltos relativos do BPF clássico.
type asm struct {
	ins    []bpf.Instruction
	fixups []fixup
	labels map[string]int
	n      int
}

type fixup struct {
	at          int
	true, false string // "" = próxima instrução
	always      bool
}

func (a *asm) emit(i bpf.Instruction) { a.ins = append(a.ins, i) }

func (a *asm) uniq(prefix string) string {
	a.n++
	return fmt.Sprintf("%s_%d", prefix, a.n)
}

func (a *asm) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.ins)
}

func (a *asm) jeq(v uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{at: len(a.ins), true: t, false: f})
	a.emit(bpf.JumpIf{Cond: bpf.JumpEqual, Val: v})
}

func (a *asm) jset(mask uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{at: len(a.ins), true: t, false: f})
	a.emit(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mask})
}

func (a *asm) jmp(to string) {
	a.fixups = append(a.fixups, fixup{at: len(a.ins), true: to, always: true})
	a.emit(bpf.Jump{})
}

// resolve troca os rótulos por deslocamentos relativos.
func (a *asm) resolve() ([]bpf.Instruction, error) {
	skip := func(at int, name string) (uint32, error) {
		if name == "" {
			return 0, nil
		}
		to, ok := a.labels[name]
		if !ok || to <= at {
			return 0, fmt.Errorf("capture: bad bpf label %q", name)
		}
		return uint32(to - at - 1), nil //nolint:gosec // programa pequeno
	}
	for _, f := range a.fixups {
		t, err := skip(f.at, f.true)
		if err != nil {
			return nil, err
		}
		if f.always {
			a.ins[f.at] = bpf.Jump{Skip: t}
			continue
		}
		fl, err := skip(f.at, f.false)
		if err != nil {
			return nil, err
		}
		if t > 255 || fl > 255 {
			return nil, fmt.Errorf("capture: bpf jump too long")
		}
		j := a.ins[f.at].(bpf.JumpIf)
		j.SkipTrue, j.SkipFalse = uint8(t), uint8(fl) //nolint:gosec // conferido acima
		a.ins[f.at] = j
	}
	return a.ins, nil
}
