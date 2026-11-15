// Package capture é o serviço que captura na íntegra os pacotes da interface FS_CAPTURE_IFACE (padrão ens192) e os publica no NATS em lotes FSPB v1
// (spec 003, ADRs 0004, 0011, 0015).
package capture

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// maxSnap é o maior valor aceito pelo filtro (o frame inteiro, inclusive os agregados por GRO/LRO).
const maxSnap = 0x40000

// v6ExtMax é quantos cabeçalhos de extensão IPv6 o filtro percorre antes de desistir (o BPF clássico não tem
// laços; cada um é desenrolado). Com mais que isso o pacote é aceito e a conferência em espaço de usuário decide.
const v6ExtMax = 6

// Próximos cabeçalhos IPv6 que o filtro e o parser sabem atravessar.
const (
	ipv6HopByHop = 0
	ipv6Routing  = 43
	ipv6Fragment = 44
	ipv6AH       = 51
	ipv6DstOpts  = 60
)

// ExcludeFilter monta o programa BPF clássico que descarta, no kernel, os pacotes TCP e UDP cuja porta de origem
// ou de destino está em ports (spec 003 RF-02) e corta o que aceita em snaplen bytes (RF-01; <= 0 ou acima de
// maxSnap: o frame inteiro). Todo o resto é aceito: ICMP, fragmentos não iniciais, ARP etc. Atravessa até
// v6ExtMax cabeçalhos de extensão IPv6 (Hop-by-Hop, Routing, Fragment, AH, Destination Options) e suporta
// Ethernet com e sem uma etiqueta VLAN 802.1Q. Frame curto demais para o filtro ler as portas (cabeçalho IP
// incompleto, extensão IPv6 com tamanho declarado além do fim, L4 cortado) também é aceito: no BPF clássico uma
// carga fora do pacote encerra o filtro com 0 (drop), por isso cada carga dependente do conteúdo é precedida por
// need, e o parser em espaço de usuário decide sobre o frame truncado.
func ExcludeFilter(ports []uint16, snaplen int) ([]bpf.Instruction, error) {
	if len(ports) > 50 {
		return nil, fmt.Errorf("capture: too many excluded ports (%d)", len(ports))
	}
	snap := uint32(maxSnap)
	if snaplen > 0 && snaplen < maxSnap {
		snap = uint32(snaplen) //nolint:gosec // conferido acima
	}
	a := &asm{snap: snap}
	if len(ports) == 0 {
		a.emit(bpf.RetConstant{Val: snap})
		return a.resolve()
	}

	// Tipo Ethernet; VLAN desloca tudo em 4 bytes.
	a.need(14, false)
	a.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	vlan := a.uniq("vlan")
	a.farIf(0x8100, vlan)
	a.l2(14, ports)
	a.label(vlan)
	a.need(18, false)
	a.emit(bpf.LoadAbsolute{Off: 16, Size: 2})
	a.l2(18, ports)
	return a.resolve()
}

// l2 gera o trecho para um cabeçalho L2 de tamanho l2len, com o tipo Ethernet já no acumulador. Cada trecho
// termina com os próprios "accept"/"drop", para os saltos condicionais (no máximo 255 instruções) ficarem curtos.
func (a *asm) l2(l2len uint32, ports []uint16) {
	v6, acc := a.uniq("v6"), a.uniq("acc")
	a.farIf(0x86dd, v6)
	a.jeq(0x0800, "", acc)

	// IPv4: protocolo, fragmento, IHL. Cabeçalho incompleto: aceita, o espaço de usuário decide.
	a.need(l2len+10, false)
	a.emit(bpf.LoadAbsolute{Off: l2len + 9, Size: 1})
	tcp4 := a.uniq("l4")
	a.jeq(6, tcp4, "")
	a.jeq(17, tcp4, acc)
	a.label(tcp4)
	a.emit(bpf.LoadAbsolute{Off: l2len + 6, Size: 2})
	a.jset(0x1fff, acc, "") // fragmento não inicial: sem portas
	a.emit(bpf.LoadMemShift{Off: l2len})
	// IHL < 5 é inválido e o parser não lê portas dele: aceita, como o parser.
	ihl := a.uniq("ihl")
	a.emit(bpf.TXA{})
	a.jge(20, ihl, "")
	a.emit(bpf.RetConstant{Val: a.snap})
	a.label(ihl)
	a.need(l2len+4, true) // portas além do fim do frame: aceita
	a.ports(bpf.LoadIndirect{Off: l2len, Size: 2}, bpf.LoadIndirect{Off: l2len + 2, Size: 2}, ports)
	a.label(acc)
	a.emit(bpf.RetConstant{Val: a.snap})

	// IPv6: X guarda o deslocamento absoluto do cabeçalho atual e A o tipo dele (campo "próximo cabeçalho").
	a.label(v6)
	l4 := a.uniq("l4")
	a.emit(bpf.LoadConstant{Dst: bpf.RegX, Val: l2len + 40})
	a.need(l2len+7, false) // cabeçalho IPv6 incompleto: aceita
	a.emit(bpf.LoadAbsolute{Off: l2len + 6, Size: 1})
	for range v6ExtMax {
		a.v6ext(l4)
	}
	a.farIf(6, l4)
	a.farIf(17, l4)
	a.emit(bpf.RetConstant{Val: a.snap}) // cabeçalhos demais: aceita
	a.label(l4)
	a.need(4, true) // portas além do fim do frame (cabeçalho IPv6 ou L4 cortado): aceita
	a.ports(bpf.LoadIndirect{Off: 0, Size: 2}, bpf.LoadIndirect{Off: 2, Size: 2}, ports)
}

// v6ext gera uma volta desenrolada do percurso dos cabeçalhos IPv6: TCP/UDP salta para l4; extensão conhecida
// avança X e deixa em A o próximo tipo; qualquer outra coisa (ICMPv6, ESP, sem próximo) é aceita.
func (a *asm) v6ext(l4 string) {
	ext, frag, ah, acc, next := a.uniq("ext"), a.uniq("frag"), a.uniq("ah"), a.uniq("acc"), a.uniq("next")
	a.farIf(6, l4)
	a.farIf(17, l4)
	a.jeq(ipv6HopByHop, ext, "")
	a.jeq(ipv6Routing, ext, "")
	a.jeq(ipv6DstOpts, ext, "")
	a.jeq(ipv6Fragment, frag, "")
	a.jeq(ipv6AH, ah, acc)

	// Extensão genérica: tamanho = (Hdr Ext Len + 1) * 8.
	// O tipo do cabeçalho em A já foi usado; need pode sobrescrevê-lo (advance recarrega A).
	a.label(ext)
	a.need(2, true)
	a.advance(1, 3)
	a.jmp(next)

	// AH: tamanho = (Payload Len + 2) * 4.
	a.label(ah)
	a.need(2, true)
	a.advance(2, 2)
	a.jmp(next)

	// Fragment: 8 bytes; fragmento não inicial não tem portas.
	a.label(frag)
	a.need(4, true)
	a.emit(bpf.LoadIndirect{Off: 2, Size: 2})
	a.jset(0xfff8, acc, "")
	a.emit(bpf.LoadIndirect{Off: 0, Size: 1})
	a.emit(bpf.StoreScratch{Src: bpf.RegA, N: 0})
	a.emit(bpf.TXA{})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 8})
	a.emit(bpf.TAX{})
	a.emit(bpf.LoadScratch{Dst: bpf.RegA, N: 0})
	a.jmp(next)

	a.label(acc)
	a.emit(bpf.RetConstant{Val: a.snap})
	a.label(next)
}

// advance avança X por um cabeçalho de extensão cujo tamanho é ([X+1] + add) << shift e deixa em A o tipo do
// próximo ([X+0]).
func (a *asm) advance(add, shift uint32) {
	a.emit(bpf.LoadIndirect{Off: 0, Size: 1})
	a.emit(bpf.StoreScratch{Src: bpf.RegA, N: 0})
	a.emit(bpf.LoadIndirect{Off: 1, Size: 1})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: add})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: shift})
	a.emit(bpf.ALUOpX{Op: bpf.ALUOpAdd})
	a.emit(bpf.TAX{})
	a.emit(bpf.LoadScratch{Dst: bpf.RegA, N: 0})
}

// need aceita o pacote (ret local) quando ele tem menos que n bytes (ind=false) ou menos que X+n bytes
// (ind=true). Sobrescreve A e preserva X: calcula len-n[-X] e olha o bit de sinal (o frame tem no máximo
// maxSnap bytes e X fica muito abaixo de 2^31, então o resultado negativo nunca se confunde com um positivo).
func (a *asm) need(n uint32, ind bool) {
	ok := a.uniq("ok")
	a.emit(bpf.LoadExtension{Num: bpf.ExtLen})
	a.emit(bpf.ALUOpConstant{Op: bpf.ALUOpSub, Val: n})
	if ind {
		a.emit(bpf.ALUOpX{Op: bpf.ALUOpSub})
	}
	a.jset(0x80000000, "", ok)
	a.emit(bpf.RetConstant{Val: a.snap})
	a.label(ok)
}

// ports compara a porta de origem e a de destino com a lista; casou → drop; senão → accept (rets locais).
func (a *asm) ports(src, dst bpf.Instruction, ports []uint16) {
	drop := a.uniq("drop")
	for _, load := range []bpf.Instruction{src, dst} {
		a.emit(load)
		for _, p := range ports {
			a.jeq(uint32(p), drop, "")
		}
	}
	a.emit(bpf.RetConstant{Val: a.snap})
	a.label(drop)
	a.emit(bpf.RetConstant{Val: 0})
}

// asm é um montador mínimo com rótulos simbólicos para os saltos relativos do BPF clássico.
type asm struct {
	snap   uint32 // valor de retorno do "accept"
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

func (a *asm) jge(v uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{at: len(a.ins), true: t, false: f})
	a.emit(bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: v})
}

// farIf salta para to quando A == v, por meio de um salto incondicional (sem o limite de 255 instruções).
func (a *asm) farIf(v uint32, to string) {
	skip := a.uniq("skip")
	a.jeq(v, "", skip)
	a.jmp(to)
	a.label(skip)
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
