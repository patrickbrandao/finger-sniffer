package lists

import (
	"math/bits"
	"net/netip"
)

// maxTreeLists é o teto de listas numa árvore (uma máscara de 64 bits por nó).
const maxTreeLists = 64

// maxTreeNodes limita os nós por família (cabe em int32 e segura a memória: 16 bytes por nó).
const maxTreeNodes = 1 << 24

// trieNode é um nó da árvore binária de prefixos; filhos por índice (0 = ausente) para não ter ponteiros no heap.
type trieNode struct {
	child [2]int32
	lists uint64 // listas cujo prefixo termina neste nó
}

// Tree é a árvore de prefixos (IPv4 e IPv6 separados; IPv4 mapeado em IPv6 normalizado para IPv4). Imutável
// depois de montada: a troca é atômica no Manager.
type Tree struct {
	names []string
	v4    []trieNode
	v6    []trieNode
}

// TreeBuilder monta uma Tree.
type TreeBuilder struct {
	t Tree
}

// NewTreeBuilder começa uma árvore vazia.
func NewTreeBuilder() *TreeBuilder {
	return &TreeBuilder{t: Tree{v4: []trieNode{{}}, v6: []trieNode{{}}}}
}

// Add acrescenta os prefixos de uma lista; devolve false se já há maxTreeLists listas.
func (b *TreeBuilder) Add(name string, prefixes []netip.Prefix) bool {
	if len(b.t.names) >= maxTreeLists {
		return false
	}
	id := uint64(1) << len(b.t.names)
	b.t.names = append(b.t.names, name)
prefixes:
	for _, p := range prefixes {
		p = normalizePrefix(p)
		if !p.IsValid() {
			continue
		}
		nodes := &b.t.v6
		if p.Addr().Is4() {
			nodes = &b.t.v4
		}
		raw := p.Addr().AsSlice()
		cur := int32(0)
		for i := range p.Bits() {
			bit := (raw[i/8] >> (7 - i%8)) & 1
			next := (*nodes)[cur].child[bit]
			if next == 0 {
				if len(*nodes) >= maxTreeNodes {
					continue prefixes // sem espaço: o prefixo fica de fora (nunca marcar um mais curto)
				}
				*nodes = append(*nodes, trieNode{})
				next = int32(len(*nodes) - 1) //nolint:gosec // limitado por maxTreeNodes
				(*nodes)[cur].child[bit] = next
			}
			cur = next
		}
		(*nodes)[cur].lists |= id
	}
	return true
}

// Build devolve a árvore pronta.
func (b *TreeBuilder) Build() *Tree {
	t := b.t
	return &t
}

// normalizePrefix desfaz o IPv4 mapeado em IPv6 (::ffff:a.b.c.d/len com len ≥ 96) e mascara.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return p
	}
	a := p.Addr().WithZone("")
	if a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}
		}
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96).Masked()
	}
	return netip.PrefixFrom(a, p.Bits()).Masked()
}

// Lookup devolve os nomes das listas com algum prefixo que contém o IP.
func (t *Tree) Lookup(ip netip.Addr) []string {
	if t == nil || !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap().WithZone("")
	nodes := t.v6
	if ip.Is4() {
		nodes = t.v4
	}
	raw := ip.AsSlice()
	var mask uint64
	cur := int32(0)
	for i := 0; ; i++ {
		mask |= nodes[cur].lists
		if i == len(raw)*8 {
			break
		}
		next := nodes[cur].child[(raw[i/8]>>(7-i%8))&1]
		if next == 0 {
			break
		}
		cur = next
	}
	var out []string
	for mask != 0 {
		i := bits.TrailingZeros64(mask)
		out = append(out, t.names[i])
		mask &^= 1 << i
	}
	return out
}

// Nodes é o número de nós (para os testes e a estimativa de memória).
func (t *Tree) Nodes() int { return len(t.v4) + len(t.v6) }
