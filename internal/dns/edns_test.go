package dns

import (
	"encoding/binary"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	mdns "github.com/miekg/dns"
)

// optionTLVsReference é a leitura anterior à task 192 (buffer de mdns.MaxMsgSize), mantida só como
// referência: o resultado de optionTLVs tem de ser idêntico ao dela.
func optionTLVsReference(opt *mdns.OPT) []optionTLV {
	buf := make([]byte, mdns.MaxMsgSize)
	n, err := mdns.PackRR(opt, buf, 0, nil, false)
	const hdr = 11
	if err != nil || n < hdr {
		return nil
	}
	rd := buf[hdr:n]
	var out []optionTLV
	for len(rd) >= 4 {
		code := binary.BigEndian.Uint16(rd)
		l := int(binary.BigEndian.Uint16(rd[2:]))
		if 4+l > len(rd) {
			break
		}
		out = append(out, optionTLV{code: code, data: slices.Clone(rd[4 : 4+l])})
		rd = rd[4+l:]
	}
	return out
}

// ednsQuery monta uma consulta A com OPT e as opções dadas, empacota e desempacota como o servidor faz.
func ednsQuery(t testing.TB, opts ...mdns.EDNS0) *mdns.Msg {
	t.Helper()
	m := query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeA)
	m.SetEdns0(1232, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, opts...)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var in mdns.Msg
	if err := in.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	return &in
}

func ednsCases() map[string][]mdns.EDNS0 {
	return map[string][]mdns.EDNS0{
		"sem-opcoes": nil,
		"so-cookie":  {&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708"}},
		"ecs-v4": {&mdns.EDNS0_SUBNET{
			Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("200.1.2.0").To4(),
		}},
		"ecs-v6": {&mdns.EDNS0_SUBNET{
			Code: mdns.EDNS0SUBNET, Family: 2, SourceNetmask: 56, Address: net.ParseIP("2001:db8:1:2::"),
		}},
		"padding-zero":   {&mdns.EDNS0_PADDING{Padding: []byte{}}},
		"padding-grande": {&mdns.EDNS0_PADDING{Padding: make([]byte, 468)}},
		"desconhecida":   {&mdns.EDNS0_LOCAL{Code: 65001, Data: []byte{0xde, 0xad, 0xbe, 0xef}}},
		"varias-em-ordem": {
			&mdns.EDNS0_NSID{Code: mdns.EDNS0NSID},
			&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708a1a2a3a4a5a6a7a8"},
			&mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 32, Address: net.ParseIP("198.51.100.7").To4()},
			&mdns.EDNS0_LOCAL{Code: 65002, Data: []byte{1}},
			&mdns.EDNS0_PADDING{Padding: make([]byte, 31)},
		},
	}
}

// TestOptionTLVsMatchesReference confere que o buffer dimensionado pelo OPT lê as mesmas opções de antes
// e que o EDNSInfo do evento sai igual, inclusive com OPT sem opções (options: []).
func TestOptionTLVsMatchesReference(t *testing.T) {
	for name, opts := range ednsCases() {
		t.Run(name, func(t *testing.T) {
			opt := ednsQuery(t, opts...).IsEdns0()
			got, want := optionTLVs(opt), optionTLVsReference(opt)
			if len(got) != len(want) || (len(got) > 0 && !reflect.DeepEqual(got, want)) {
				t.Fatalf("optionTLVs = %+v, referência %+v", got, want)
			}
			e := ednsInfo(opt)
			if e.Options == nil {
				t.Fatal("Options nil: o JSON sairia null em vez de []")
			}
			if len(opts) == 0 && (len(e.Options) != 0 || e.CookieHex != nil || e.ECS != nil || e.PaddingLen != nil) {
				t.Fatalf("OPT sem opções gerou %+v", e)
			}
		})
	}
}

// TestEDNSInfoAllocBound garante que ler o OPT não aloca na ordem de 64 KiB por consulta.
func TestEDNSInfoAllocBound(t *testing.T) {
	opt := ednsQuery(t, ednsCases()["varias-em-ordem"]...).IsEdns0()
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = ednsInfo(opt)
		}
	})
	if bpo := res.AllocedBytesPerOp(); bpo > 4096 {
		t.Fatalf("ednsInfo aloca %d B/op; esperado proporcional ao OPT (< 4 KiB)", bpo)
	}
}

// BenchmarkBuildQueryEDNS mede o evento de uma consulta UDP com cookie, ECS e padding.
func BenchmarkBuildQueryEDNS(b *testing.B) {
	z := newDualZone()
	m := ednsQuery(b,
		&mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("200.1.2.0").To4()},
		&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708"},
		&mdns.EDNS0_PADDING{Padding: make([]byte, 12)},
	)
	raw, err := m.Pack()
	if err != nil {
		b.Fatal(err)
	}
	q := &Query{
		At: eventT0, Proto: "udp", Src: netip.MustParseAddrPort("198.51.100.7:40123"),
		Dst: netip.MustParseAddrPort("172.233.24.85:53"), Raw: raw, Req: m,
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = z.BuildQuery(q)
	}
}

// FuzzOptionTLVs: mensagens com OPT arbitrário passam por Unpack e optionTLVs sem pânico, com o mesmo
// resultado da referência (valida que mdns.Len(opt) basta para o reempacotamento).
func FuzzOptionTLVs(f *testing.F) {
	for _, opts := range ednsCases() {
		raw, err := ednsQuery(f, opts...).Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var m mdns.Msg
		if m.Unpack(raw) != nil {
			return
		}
		opt := m.IsEdns0()
		if opt == nil {
			return
		}
		got, want := optionTLVs(opt), optionTLVsReference(opt)
		if len(got) != len(want) || (len(got) > 0 && !reflect.DeepEqual(got, want)) {
			t.Fatalf("optionTLVs = %+v, referência %+v", got, want)
		}
	})
}
