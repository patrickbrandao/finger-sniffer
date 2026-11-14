package store

import "net/netip"

// srcKindRule é uma linha da tabela de ip.src_kind (spec 013 RF-05a, ADR 0031).
type srcKindRule struct {
	kind     string
	prefixes []netip.Prefix
}

// srcKindRules segue a ordem da tabela da ADR 0031: vale a primeira regra que casa; o que não casa é global.
// netip.Prefix.Contains não mistura famílias, então um IPv4 mapeado em IPv6 só casa com ::ffff:0:0/96.
var srcKindRules = []srcKindRule{
	{"loopback", prefixes("127.0.0.0/8", "::1/128")},
	{"link_local", prefixes("169.254.0.0/16", "fe80::/10")},
	{"private", prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")},
	{"shared", prefixes("100.64.0.0/10")},
	{"teredo", prefixes("2001::/32")},
	{"6to4", prefixes("2002::/16")},
	{"nat64", prefixes("64:ff9b::/96", "64:ff9b:1::/48")},
	{"other", prefixes(
		// IPv4: não unicast e uso especial.
		"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "192.0.0.0/24",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15",
		// IPv6: não unicast, IPv4 mapeado, descarte, documentação e benchmarking.
		"::/128", "ff00::/8", "::ffff:0:0/96", "100::/64", "2001:db8::/32", "3fff::/20", "2001:2::/48",
	)},
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// srcKind classifica o endereço de origem da conexão. Quem chama passa o endereço de fio: num pacote IPv4, o
// IPv4 sem mapeamento (Unmap); num pacote IPv6, o endereço como veio.
func srcKind(a netip.Addr) string {
	a = a.WithZone("")
	for _, r := range srcKindRules {
		for _, p := range r.prefixes {
			if p.Contains(a) {
				return r.kind
			}
		}
	}
	return "global"
}
