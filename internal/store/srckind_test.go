package store

import (
	"net/netip"
	"testing"
)

// TestSrcKind: um endereço por valor de ip.src_kind e as bordas de cada prefixo da ADR 0031.
func TestSrcKind(t *testing.T) {
	cases := map[string]string{
		// loopback
		"127.0.0.1": "loopback", "127.255.255.255": "loopback", "::1": "loopback",
		// link_local
		"169.254.0.1": "link_local", "169.254.255.255": "link_local", "fe80::1": "link_local",
		"febf:ffff::1": "link_local", "169.255.0.0": "global",
		// private (RFC 1918 e ULA) e as bordas de 172.16.0.0/12
		"10.0.0.1": "private", "172.16.0.0": "private", "172.31.255.255": "private", "192.168.1.1": "private",
		"fc00::1": "private", "fdff::1": "private", "172.15.255.255": "global", "172.32.0.0": "global",
		"11.0.0.0": "global", "fe00::1": "global",
		// shared e as bordas de 100.64.0.0/10
		"100.64.0.0": "shared", "100.127.255.255": "shared", "100.63.255.255": "global", "100.128.0.0": "global",
		// teredo e a borda de 2001::/32
		"2001::1": "teredo", "2001:0:ffff:ffff::1": "teredo", "2001:1::": "global",
		// 6to4
		"2002:c000:204::1": "6to4", "2002:ffff::1": "6to4", "2003::1": "global",
		// nat64 nos dois prefixos e a borda de 64:ff9b::/96
		"64:ff9b::192.0.2.1": "nat64", "64:ff9b:1::1": "nat64", "64:ff9b:1:ffff::1": "nat64",
		"64:ff9b:0:0:1::": "global", "64:ff9b:2::1": "global",
		// other: não unicast e uso especial
		"0.0.0.0": "other", "224.0.0.1": "other", "239.255.255.255": "other", "240.0.0.1": "other",
		"255.255.255.255": "other", "192.0.0.8": "other", "192.0.2.1": "other", "198.51.100.1": "other",
		"203.0.113.1": "other", "198.18.0.1": "other", "198.19.255.255": "other", "198.20.0.0": "global",
		"::": "other", "ff02::1": "other", "::ffff:8.8.8.8": "other", "100::1": "other", "100:0:0:1::": "global",
		"2001:db8::7": "other", "3fff::1": "other", "3fff:fff::1": "other", "2001:2::1": "other",
		"2001:2:1::": "global",
		// global
		"8.8.8.8": "global", "172.233.24.85": "global", "2600:3c0d::1": "global", "2804:14c::1": "global",
	}
	for in, want := range cases {
		if got := srcKind(netip.MustParseAddr(in)); got != want {
			t.Errorf("srcKind(%s) = %s, quer %s", in, got, want)
		}
	}
	// zona IPv6 não muda a classificação
	if got := srcKind(netip.MustParseAddr("fe80::1%eth0")); got != "link_local" {
		t.Errorf("fe80::1%%eth0 = %s", got)
	}
}

// TestSrcKindRecord: ip.src_kind no registro, a partir do endereço do cliente, em TCP (IPv4 e IPv6) e UDP.
func TestSrcKindRecord(t *testing.T) {
	for cli, want := range map[string]string{
		"100.64.1.2:40000":     "shared",
		"10.1.2.3:40000":       "private",
		"8.8.4.4:40000":        "global",
		"[2001::5]:40000":      "teredo",
		"[2804:14c::9]:40000":  "global",
		"[64:ff9b::a]:40000":   "nat64",
		"[2002:c000::1]:40000": "6to4",
	} {
		c := netip.MustParseAddrPort(cli)
		srv := mirror
		if c.Addr().Is6() {
			srv = netip.MustParseAddrPort("[2600:3c0d::1]:443")
		}
		s := newSession(1, 2, 3)
		s.handshake(64)
		s.fin(300, 64, 0)
		in, db := newTestIngestor(t, nil)
		run(t, in, 60_000, segBatch(c, srv, s.segs))
		_, rec := onlyConn(t, db)
		if rec.IP == nil || rec.IP.SrcKind != want {
			t.Errorf("%s: ip = %+v, quer src_kind %s", cli, rec.IP, want)
		}
	}

	// UDP (QUIC): quicClient é 192.0.2.10, bloco de documentação.
	in, _ := newTestIngestor(t, nil)
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	run(t, in, 1100, msgs[6])
	run(t, in, 3100)
	_, rec := onlyConn(t, in.db)
	if rec.IP == nil || rec.IP.SrcKind != "other" {
		t.Fatalf("udp ip = %+v", rec.IP)
	}
	if rec.TCP != nil && (rec.TCP.SynMSS != nil || rec.TCP.MTUImplied != nil || rec.TCP.MSSReduction != nil) {
		t.Fatalf("udp tcp = %+v", rec.TCP)
	}
}
