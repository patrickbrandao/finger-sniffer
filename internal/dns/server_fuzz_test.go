package dns

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"

	mdns "github.com/miekg/dns"
)

// fuzzSeedQueries são consultas reais para a semente do FuzzHandle: apex, NS/SOA, A/AAAA/HTTPS com e sem prefixo de
// porta e rótulos de controle, TXT do ACME, tipos sem dados, fora da zona e EDNS (ECS, cookie, padding, versão 1).
func fuzzSeedQueries(f *testing.F) [][]byte {
	f.Helper()
	var msgs []*mdns.Msg
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"finger-west-01.badblock.net.br.", mdns.TypeSOA},
		{"Finger-West-01.BadBlock.net.br.", mdns.TypeNS},
		{"finger-west-01.badblock.net.br.", mdns.TypeHTTPS},
		{"abcdef12.finger-west-01.badblock.net.br.", mdns.TypeA},
		{"abcdef12.finger-west-01.badblock.net.br.", mdns.TypeAAAA},
		{"AbCdEf12.finger-west-01.BADBLOCK.net.br.", mdns.TypeHTTPS},
		{"p8443.abcdef12.finger-west-01.badblock.net.br.", mdns.TypeHTTPS},
		{"p8080-abcdef12.finger-west-01.badblock.net.br.", mdns.TypeA},
		{"v6.abcdef12.finger-west-01.badblock.net.br.", mdns.TypeAAAA},
		{"_acme-challenge.abcdef12.finger-west-01.badblock.net.br.", mdns.TypeTXT},
		{"_acme-challenge.finger-west-01.badblock.net.br.", mdns.TypeTXT},
		{"finger-west-01.badblock.net.br.", mdns.TypeCAA},
		{"abcdef12.finger-west-01.badblock.net.br.", mdns.TypeANY},
		{"example.com.", mdns.TypeA},
		{".", mdns.TypeNS},
	} {
		msgs = append(msgs, query(q.name, q.qtype))
	}
	for _, opts := range ednsCases() {
		msgs = append(msgs, ednsQuery(f, opts...))
	}
	bad := ednsQuery(f)
	bad.IsEdns0().SetVersion(1)
	msgs = append(msgs, bad)
	resp := query("finger-west-01.badblock.net.br.", mdns.TypeSOA)
	resp.Response = true
	msgs = append(msgs, resp)

	var out [][]byte
	for i, m := range msgs {
		m.Id = uint16(0x1000 + i)
		raw, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, raw)
	}
	// Cabeçalho legível com a pergunta cortada (FORMERR), curto demais e vazio.
	out = append(out, []byte{0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05, 'a'}, []byte{1, 2, 3}, nil)
	return out
}

// FuzzHandle: o caminho inteiro de um datagrama UDP 53 (ou mensagem TCP) recebido de qualquer um — handle →
// answer → Zone.Answer/classify/records/https → RRL — e o evento fs.v1.dns.query (BuildQuery) sem pânico. A
// resposta, quando há, desempacota, tem o mesmo ID da consulta e cabe no limite do transporte (task 398).
// repeat repete a mesma consulta da mesma origem para passar do RRL (TC=1 em UDP).
func FuzzHandle(f *testing.F) {
	for _, raw := range fuzzSeedQueries(f) {
		f.Add(raw, false, uint8(0))
		f.Add(raw, true, uint8(0))
	}
	seeds := fuzzSeedQueries(f)
	f.Add(seeds[3], false, uint8(30)) // A repetido acima do RRL de 20/s
	f.Fuzz(func(t *testing.T, raw []byte, tcp bool, repeat uint8) {
		z := newDualZone()
		if err := z.SetACME("_acme-challenge.abcdef12.finger-west-01.badblock.net.br.", "token-for-fuzz"); err != nil {
			t.Fatal(err)
		}
		srv := NewServer(z.cfg, z, nil, nil)
		src := netip.MustParseAddrPort("198.51.100.7:40123")
		if tcp {
			src = netip.MustParseAddrPort("[2001:db8::7]:40123")
		}
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		for range 1 + int(repeat%32) {
			out, req, resp, limited := srv.handle(raw, tcp, src.Addr())
			if out != nil {
				var m mdns.Msg
				if err := m.Unpack(out); err != nil {
					t.Fatalf("response does not unpack: %v (%x)", err, out)
				}
				if len(raw) >= 2 && m.Id != binary.BigEndian.Uint16(raw[0:2]) {
					t.Fatalf("response id %#04x, query id %#04x", m.Id, binary.BigEndian.Uint16(raw[0:2]))
				}
				if !m.Response {
					t.Fatalf("response without QR: %v", &m)
				}
				if limit := udpMaxEDNS; !tcp && len(out) > limit {
					t.Fatalf("udp response %d bytes, limit %d", len(out), limit)
				}
				if len(out) > mdns.MaxMsgSize {
					t.Fatalf("response %d bytes", len(out))
				}
			}
			if limited && tcp {
				t.Fatal("tcp must not be rate limited")
			}
			q := &Query{
				At: eventT0, Proto: proto, Src: src, Dst: netip.MustParseAddrPort("172.233.24.85:53"),
				Raw: raw, Req: req, Resp: resp, RateLimited: limited,
			}
			if _, err := json.Marshal(z.BuildQuery(q)); err != nil {
				t.Fatalf("event json: %v", err)
			}
		}
	})
}
