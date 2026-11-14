package store

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// mssOpts devolve as opções de um SYN com MSS m, SACK, NOP e WS 7.
func mssOpts(m uint16) []byte {
	return []byte{2, 4, byte(m >> 8), byte(m), 4, 2, 1, 3, 3, 7}
}

func intOrNil(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// mssSession processa um handshake cujo SYN do cliente tem as opções dadas e devolve o bloco tcp.
func mssSession(t *testing.T, cli netip.AddrPort, synOpts []byte) *tcpJSON {
	t.Helper()
	srv := mirror
	if cli.Addr().Is6() {
		srv = netip.MustParseAddrPort("[2600:3c0d::1]:443")
	}
	s := newSession(1, 2, 3)
	s.handshake(64)
	s.segs[0].opts = synOpts
	s.fin(300, 64, 0)
	in, db := newTestIngestor(t, nil)
	run(t, in, 60_000, segBatch(cli, srv, s.segs))
	_, rec := onlyConn(t, db)
	if rec.TCP == nil {
		t.Fatal("sem bloco tcp")
	}
	return rec.TCP
}

// TestSynMSS: syn_mss, mtu_implied e mss_reduction da tabela dos critérios da spec 013 RF-06a.
func TestSynMSS(t *testing.T) {
	v4 := netip.MustParseAddrPort("8.8.4.4:40000")
	v6 := netip.MustParseAddrPort("[2804:14c::9]:40000")
	for _, c := range []struct {
		cli                 netip.AddrPort
		mss, mtu, reduction int
	}{
		{v4, 1460, 1500, 0},
		{v4, 1452, 1492, 8},
		{v4, 1440, 1480, 20},
		{v4, 1380, 1420, 80},
		{v4, 8960, 9000, -7500},
		{v6, 1440, 1500, 0},
		{v6, 1432, 1492, 8},
		{v6, 1220, 1280, 220},
	} {
		tc := mssSession(t, c.cli, mssOpts(uint16(c.mss))) //nolint:gosec // teste
		if intOrNil(tc.SynMSS) != c.mss || intOrNil(tc.MTUImplied) != c.mtu || intOrNil(tc.MSSReduction) != c.reduction {
			t.Errorf("%s mss %d: syn_mss/mtu/reduction = %v/%v/%v, quer %d/%d/%d", c.cli, c.mss,
				intOrNil(tc.SynMSS), intOrNil(tc.MTUImplied), intOrNil(tc.MSSReduction), c.mss, c.mtu, c.reduction)
		}
		// syn_mss igual ao ["mss",N] de tcp.syn.options
		if tc.Syn == nil || len(tc.Syn.Options) == 0 || tc.Syn.Options[0][0] != "mss" || tc.Syn.Options[0][1] != float64(c.mss) {
			t.Errorf("%s mss %d: options = %v", c.cli, c.mss, tc.Syn)
		}
	}

	// Com timestamps no SYN o MTU não soma os 12 B (linuxSYN: MSS 1460 + TS).
	tc := mssSession(t, v4, linuxSYN(9))
	if intOrNil(tc.MTUImplied) != 1500 {
		t.Errorf("com TS: mtu_implied = %v", intOrNil(tc.MTUImplied))
	}

	// Duas opções MSS: vale a primeira.
	tc = mssSession(t, v4, append(mssOpts(1400), 2, 4, 0x05, 0xb4))
	if intOrNil(tc.SynMSS) != 1400 {
		t.Errorf("duas MSS: syn_mss = %v", intOrNil(tc.SynMSS))
	}

	// SYN sem a opção MSS: os três nulos e serializados como null (sem omitempty).
	tc = mssSession(t, v4, []byte{4, 2, 1, 3, 3, 7})
	if tc.SynMSS != nil || tc.MTUImplied != nil || tc.MSSReduction != nil {
		t.Errorf("sem MSS: %v/%v/%v", intOrNil(tc.SynMSS), intOrNil(tc.MTUImplied), intOrNil(tc.MSSReduction))
	}
	b, err := json.Marshal(tc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"syn_mss", "mtu_implied", "mss_reduction"} {
		if v, ok := m[k]; !ok || v != nil {
			t.Errorf("sem MSS: %s = %v (presente %v), quer null", k, v, ok)
		}
	}
}

// TestSynMSSRetransmit: o SYN retransmitido com outro MSS não substitui o primeiro.
func TestSynMSSRetransmit(t *testing.T) {
	s := newSession(1, 2, 3)
	s.handshake(64)
	s.segs[0].opts = mssOpts(1460)
	re := s.segs[0]
	re.ms, re.opts = 20, mssOpts(1200)
	s.segs = append([]seg{s.segs[0], re}, s.segs[1:]...)
	s.fin(300, 64, 0)
	rec := ingestSession(t, nil, client, s.segs)
	if rec.TCP == nil || intOrNil(rec.TCP.SynMSS) != 1460 || intOrNil(rec.TCP.MSSReduction) != 0 {
		t.Fatalf("retransmissão: tcp = %+v", rec.TCP)
	}
}

// TestSynMSSNoSyn: conexão vista sem o SYN (capture começou no meio; o evento de aplicação a mantém como
// conexão) tem os três nulos.
func TestSynMSSNoSyn(t *testing.T) {
	s := newSession(1, 2, 3)
	s.cliData(10, 100, 64, 7)
	s.srvData(20, 100)
	s.fin(300, 64, 0)
	in, db := newTestIngestor(t, nil)
	run(t, in, 60_000, segBatch(client, mirror, s.segs),
		appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 5, "", map[string]any{"mode": "echo"}))
	_, rec := onlyConn(t, db)
	if rec.TCP == nil {
		t.Fatal("sem bloco tcp")
	}
	if rec.TCP.Syn != nil || rec.TCP.SynMSS != nil || rec.TCP.MTUImplied != nil || rec.TCP.MSSReduction != nil {
		t.Fatalf("sem SYN: tcp = %+v", rec.TCP)
	}
}

// TestMSSDerived: a conta pura, sem MSS e pelas duas famílias.
func TestMSSDerived(t *testing.T) {
	if a, b, c := mssDerived(nil, 4); a != nil || b != nil || c != nil {
		t.Fatal("nil deve dar três nulos")
	}
	m := 1280
	if a, b, c := mssDerived(&m, 6); *a != 1280 || *b != 1340 || *c != 160 {
		t.Fatalf("v6 1280 = %d/%d/%d", *a, *b, *c)
	}
	m = 0
	if a, b, c := mssDerived(&m, 4); *a != 0 || *b != 40 || *c != 1460 {
		t.Fatalf("v4 0 = %d/%d/%d", *a, *b, *c)
	}
}
