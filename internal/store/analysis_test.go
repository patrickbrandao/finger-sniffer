package store

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// seg descreve um pacote TCP sintético com todos os campos que a análise lê.
type seg struct {
	ms      float64
	fromCli bool
	flags   byte
	seq     uint32
	ack     uint32
	win     uint16
	opts    []byte
	payload int
	ttl     uint8
	id      uint16
	df      bool
	mf      bool
	tos     uint8
	flow    uint32
	urg     uint16
	ipOpts  []byte
}

// tcpFrame monta o frame Ethernet + IPv4/IPv6 + TCP de um seg.
func tcpFrame(src, dst netip.AddrPort, s seg) []byte {
	opts := append([]byte(nil), s.opts...)
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	tcp := make([]byte, 20, 20+len(opts)+s.payload)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], s.seq)
	binary.BigEndian.PutUint32(tcp[8:], s.ack)
	tcp[12] = byte((20+len(opts))/4) << 4
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:], s.win)
	binary.BigEndian.PutUint16(tcp[18:], s.urg)
	tcp = append(append(tcp, opts...), make([]byte, s.payload)...)
	ttl := s.ttl
	if ttl == 0 {
		ttl = 64
	}
	f := make([]byte, 12)
	if src.Addr().Is4() {
		f = binary.BigEndian.AppendUint16(f, 0x0800)
		hl := 20 + len(s.ipOpts)
		ip := make([]byte, hl)
		ip[0], ip[1], ip[8], ip[9] = 0x40|byte(hl/4), s.tos, ttl, protoTCP
		binary.BigEndian.PutUint16(ip[2:], uint16(hl+len(tcp))) //nolint:gosec // teste
		binary.BigEndian.PutUint16(ip[4:], s.id)
		var fo uint16
		if s.df {
			fo |= 0x4000
		}
		if s.mf {
			fo |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], fo)
		a, b := src.Addr().As4(), dst.Addr().As4()
		copy(ip[12:], a[:])
		copy(ip[16:], b[:])
		copy(ip[20:], s.ipOpts)
		f = append(f, ip...)
	} else {
		f = binary.BigEndian.AppendUint16(f, 0x86dd)
		ip := make([]byte, 40)
		binary.BigEndian.PutUint32(ip[0:], 6<<28|uint32(s.tos)<<20|s.flow)
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp))) //nolint:gosec // teste
		ip[6], ip[7] = protoTCP, ttl
		a, b := src.Addr().As16(), dst.Addr().As16()
		copy(ip[8:], a[:])
		copy(ip[24:], b[:])
		f = append(f, ip...)
	}
	return append(f, tcp...)
}

// segBatch monta um lote FSPB com os segs da conversa cli <-> srv.
func segBatch(cli, srv netip.AddrPort, segs []seg) fakeMsg {
	var buf []byte
	for _, s := range segs {
		src, dst, dir := cli, srv, event.DirIn
		if !s.fromCli {
			src, dst, dir = srv, cli, event.DirOut
		}
		f := tcpFrame(src, dst, s)
		buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(s.ms*1e6), Dir: dir, WireLen: uint32(len(f)), Frame: f}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

// tsOpt devolve opções NOP NOP TS com os valores dados.
func tsOpt(val, ecr uint32) []byte {
	b := []byte{1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], val)
	binary.BigEndian.PutUint32(b[8:], ecr)
	return b
}

// linuxSYN são as opções de um SYN do Linux: MSS 1460, SACK, TS, NOP, WS 7.
func linuxSYN(tsval uint32) []byte {
	b := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7}
	binary.BigEndian.PutUint32(b[8:], tsval)
	return b
}

// session gera uma conversa TCP coerente: handshake, dados nos dois sentidos e FIN dos dois lados.
type session struct {
	cliISN, srvISN uint32
	cliNext        uint32
	srvNext        uint32
	tsBase         uint32
	segs           []seg
}

func newSession(cliISN, srvISN, tsBase uint32) *session {
	return &session{cliISN: cliISN, srvISN: srvISN, cliNext: cliISN + 1, srvNext: srvISN + 1, tsBase: tsBase}
}

// tsAt devolve o TSval do cliente a 1000 Hz no instante ms.
func (s *session) tsAt(ms float64) uint32 { return s.tsBase + uint32(ms) }

func (s *session) handshake(ttl uint8) {
	s.segs = append(s.segs,
		seg{ms: 0, fromCli: true, flags: tcpSYN, seq: s.cliISN, win: 64240, opts: linuxSYN(s.tsAt(0)), ttl: ttl, id: 100, df: true},
		seg{ms: 50, flags: tcpSYN | tcpACK, seq: s.srvISN, ack: s.cliNext, win: 65160, opts: linuxSYN(777)},
		seg{ms: 100.25, fromCli: true, flags: tcpACK, seq: s.cliNext, ack: s.srvNext, win: 502, opts: tsOpt(s.tsAt(100), 777), ttl: ttl, id: 101, df: true},
	)
}

func (s *session) cliData(ms float64, n int, ttl uint8, id uint16) {
	s.segs = append(s.segs, seg{ms: ms, fromCli: true, flags: tcpACK | tcpPSH, seq: s.cliNext, ack: s.srvNext, win: 502, opts: tsOpt(s.tsAt(ms), 777), payload: n, ttl: ttl, id: id, df: true})
	s.cliNext += uint32(n) //nolint:gosec // teste
}

func (s *session) srvData(ms float64, n int) {
	s.segs = append(s.segs, seg{ms: ms, flags: tcpACK, seq: s.srvNext, ack: s.cliNext, win: 509, opts: tsOpt(888, s.tsAt(ms)), payload: n})
	s.srvNext += uint32(n) //nolint:gosec // teste
}

func (s *session) cliAck(ms float64, ttl uint8, id uint16) {
	s.segs = append(s.segs, seg{ms: ms, fromCli: true, flags: tcpACK, seq: s.cliNext, ack: s.srvNext, win: 502, opts: tsOpt(s.tsAt(ms), 888), ttl: ttl, id: id, df: true})
}

func (s *session) fin(ms float64, ttl uint8, id uint16) {
	s.segs = append(s.segs,
		seg{ms: ms, flags: tcpFIN | tcpACK, seq: s.srvNext, ack: s.cliNext, win: 509, opts: tsOpt(889, s.tsAt(ms))},
		seg{ms: ms + 1, fromCli: true, flags: tcpFIN | tcpACK, seq: s.cliNext, ack: s.srvNext + 1, win: 502, opts: tsOpt(s.tsAt(ms+1), 889), ttl: ttl, id: id, df: true},
		seg{ms: ms + 2, flags: tcpACK, seq: s.srvNext + 1, ack: s.cliNext + 1, win: 509, opts: tsOpt(890, s.tsAt(ms+1))},
	)
}

// ingestSession processa a conversa e devolve o registro final.
func ingestSession(t *testing.T, mut func(*IngestConfig), cli netip.AddrPort, segs []seg) connectionJSON {
	t.Helper()
	in, db := newTestIngestor(t, mut)
	run(t, in, 60_000, segBatch(cli, mirror, segs))
	_, rec := onlyConn(t, db)
	return rec
}

func TestAnalysisFullSession(t *testing.T) {
	s := newSession(1_000_000, 5_000_000, 40_000)
	s.handshake(57)
	s.cliData(120, 300, 57, 102)
	for i := range 6 {
		s.srvData(200+float64(i), 1448)
		s.cliAck(240+float64(i), 57, uint16(103+i)) //nolint:gosec // teste
	}
	s.fin(700, 57, 110)
	rec := ingestSession(t, nil, client, s.segs)

	ip := rec.IP
	if ip == nil || ip.TTL != 57 || ip.TTLInitial != 64 || ip.Hops != 7 || !ip.DF || ip.IPIDSyn == nil || *ip.IPIDSyn != 100 ||
		ip.IPIDPattern != "incremental" || ip.ECN != "not-ect" || ip.FlowLabel != nil || ip.Fragmented {
		t.Fatalf("ip = %+v", ip)
	}
	tc := rec.TCP
	if tc == nil || tc.Syn == nil {
		t.Fatalf("tcp = %+v", tc)
	}
	sy := tc.Syn
	if sy.ISN != 1_000_000 || sy.Window != 64240 || sy.Flags != "S" || sy.HeaderLen != 40 || sy.PayloadB64 != nil || sy.TFO {
		t.Fatalf("syn = %+v", sy)
	}
	if got := optsString(sy.Options); got != "mss=1460 sack_perm ts=40000,0 nop wscale=7" {
		t.Fatalf("opções = %s", got)
	}
	if tc.JA4T == nil || *tc.JA4T != "64240_2-4-8-1-3_1460_7" {
		t.Fatalf("ja4t = %v", tc.JA4T)
	}
	if tc.P0F == nil || *tc.P0F != "4:57+7:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0" || tc.OSGuess != nil {
		t.Fatalf("p0f = %v os = %v", tc.P0F, tc.OSGuess)
	}
	if tc.RTTHandshakeMs == nil || *tc.RTTHandshakeMs != 50.25 {
		t.Fatalf("rtt = %v", tc.RTTHandshakeMs)
	}
	if tc.TSInitial == nil || *tc.TSInitial != 40000 || tc.TSClockHz == nil || *tc.TSClockHz < 990 || *tc.TSClockHz > 1010 {
		t.Fatalf("ts = %v hz = %v", tc.TSInitial, tc.TSClockHz)
	}
	if tc.TSClockGroup == nil || !strings.HasPrefix(*tc.TSClockGroup, "clk-") {
		t.Fatalf("grupo = %v", tc.TSClockGroup)
	}
	// janela: SYN cru, depois 502 << 7
	if len(tc.WindowSeries) != 2 || tc.WindowSeries[0][1] != 64240 || tc.WindowSeries[1][1] != 502<<7 || tc.WindowSeries[1][0] != 100.25 {
		t.Fatalf("janela = %v", tc.WindowSeries)
	}
	if tc.AckPattern != "immediate" || !tc.PSHUsed || tc.ZeroWindow || tc.RSTWithData || len(tc.KeepaliveProbes) != 0 {
		t.Fatalf("comportamento = %+v", tc)
	}
	if len(tc.SegmentsIn) != 1 || tc.SegmentsIn[0] != (timedLen{120, 300}) || len(tc.SegmentsOut) != 6 {
		t.Fatalf("segmentos = %v / %v", tc.SegmentsIn, tc.SegmentsOut)
	}
	if rec.Totals.In.Retransmits != 0 || rec.Totals.In.OutOfOrder != 0 || rec.Totals.Out.Retransmits != 0 || tc.RetransmitsIn != 0 {
		t.Fatalf("totais = %+v", rec.Totals)
	}
	if tc.RTTAppMs != nil || tc.SynCookieServer {
		t.Fatalf("rtt app / cookie = %+v", tc)
	}
}

func optsString(opts [][]any) string {
	var parts []string
	for _, o := range opts {
		p := o[0].(string)
		var vals []string
		for _, v := range o[1:] {
			switch x := v.(type) {
			case int:
				vals = append(vals, itoa64(int64(x)))
			case int64:
				vals = append(vals, itoa64(x))
			case float64: // registro lido de volta do JSON
				vals = append(vals, itoa64(int64(x)))
			case string:
				vals = append(vals, x)
			}
		}
		if len(vals) > 0 {
			p += "=" + strings.Join(vals, ",")
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

func itoa64(v int64) string {
	if v < 0 {
		return "-" + itoa64(-v)
	}
	if v < 10 {
		return string(rune('0' + v))
	}
	return itoa64(v/10) + string(rune('0'+v%10))
}

func TestAnalysisRetransmitAndOutOfOrder(t *testing.T) {
	s := newSession(10, 20, 1)
	s.handshake(64)
	start := s.cliNext
	s.cliData(110, 100, 64, 1) // [0,100)
	s.cliNext += 100           // pula [100,200): chega depois
	s.cliData(112, 100, 64, 2) // [200,300)
	gap := s.cliNext
	s.cliNext = start + 100
	s.cliData(114, 100, 64, 3) // [100,200) fora de ordem
	s.cliNext = start
	s.cliData(116, 100, 64, 4) // [0,100) retransmitido
	s.cliNext = gap
	// SYN retransmitido (mesmo ISN) logo depois do primeiro, e FIN retransmitido
	synAgain := seg{ms: 1, fromCli: true, flags: tcpSYN, seq: 10, win: 64240, opts: linuxSYN(2)}
	s.segs = append(s.segs[:1], append([]seg{synAgain}, s.segs[1:]...)...)
	s.fin(200, 64, 5)
	last := s.segs[len(s.segs)-2]
	last.ms += 3
	s.segs = append(s.segs, last)
	rec := ingestSession(t, nil, client, s.segs)
	if rec.Totals.In.Retransmits != 3 || rec.Totals.In.OutOfOrder != 1 || rec.TCP.RetransmitsIn != 3 {
		t.Fatalf("totais = %+v tcp.retransmits_in = %d", rec.Totals.In, rec.TCP.RetransmitsIn)
	}
	if len(rec.TCP.SegmentsIn) != 4 {
		t.Fatalf("segmentos = %v", rec.TCP.SegmentsIn)
	}
}

func TestAnalysisZeroWindowKeepaliveRST(t *testing.T) {
	s := newSession(100, 200, 5)
	s.handshake(64)
	s.cliData(110, 10, 64, 1)
	// janela zero, keepalive de 1 byte (seq = próximo - 1) e de 0 byte, RST com dados
	s.segs = append(s.segs,
		seg{ms: 150, fromCli: true, flags: tcpACK, seq: s.cliNext, ack: s.srvNext, win: 0},
		seg{ms: 5150, fromCli: true, flags: tcpACK, seq: s.cliNext - 1, ack: s.srvNext, win: 502, payload: 1},
		seg{ms: 10150, fromCli: true, flags: tcpACK, seq: s.cliNext - 1, ack: s.srvNext, win: 502},
		seg{ms: 10200, fromCli: true, flags: tcpRST | tcpACK, seq: s.cliNext, ack: s.srvNext, win: 0, payload: 4},
	)
	rec := ingestSession(t, nil, client, s.segs)
	tc := rec.TCP
	if !tc.ZeroWindow || !tc.RSTWithData || len(tc.KeepaliveProbes) != 2 ||
		tc.KeepaliveProbes[0] != (timedLen{5150, 1}) || tc.KeepaliveProbes[1] != (timedLen{10150, 0}) {
		t.Fatalf("tcp = %+v", tc)
	}
	if rec.Totals.In.Retransmits != 0 {
		t.Fatalf("keepalive contado como retransmissão: %+v", rec.Totals.In)
	}
	if tc.AckPattern != "unknown" {
		t.Fatalf("ack = %+v", tc)
	}
}

func TestAnalysisDelayedAck(t *testing.T) {
	s := newSession(1, 2, 3)
	s.handshake(64)
	for i := range 8 {
		s.srvData(200+float64(i), 1448)
		if i%2 == 1 {
			s.cliAck(240+float64(i), 64, uint16(i)) //nolint:gosec // teste
		}
	}
	s.fin(400, 64, 50)
	rec := ingestSession(t, nil, client, s.segs)
	if rec.TCP.AckPattern != "delayed" {
		t.Fatalf("ack = %s", rec.TCP.AckPattern)
	}
}

func TestAnalysisIPVariants(t *testing.T) {
	// IPv4: fragmento (MF), TOS com ECN CE, opções IP, sem DF e IP ID zero
	s := newSession(1, 2, 3)
	s.handshake(120)
	s.segs[0].mf, s.segs[0].tos, s.segs[0].df, s.segs[0].id = true, 0x2b, false, 0
	s.segs[0].ipOpts = []byte{0x94, 0x04, 0, 0}
	s.segs[2].id = 0
	s.fin(300, 120, 0)
	rec := ingestSession(t, nil, client, s.segs)
	ip := rec.IP
	if !ip.Fragmented || ip.TOS != 0x2b || ip.DSCP != 0x0a || ip.ECN != "ce" || ip.OptionsHex != "94040000" || ip.DF ||
		ip.IPIDPattern != "zero" || ip.TTLInitial != 128 || ip.Hops != 8 {
		t.Fatalf("ip v4 = %+v", ip)
	}

	// IPv6: flow label e traffic class
	cli6 := netip.MustParseAddrPort("[2001:db8::7]:40000")
	s = newSession(1, 2, 3)
	s.handshake(250)
	for i := range s.segs {
		s.segs[i].flow, s.segs[i].tos = 0x12345, 0x02
	}
	s.fin(300, 250, 0)
	in, db := newTestIngestor(t, nil)
	segs := s.segs
	run(t, in, 60_000, segBatch(cli6, netip.MustParseAddrPort("[2600:3c0d::1]:443"), segs))
	_, rec = onlyConn(t, db)
	ip = rec.IP
	if ip.FlowLabel == nil || *ip.FlowLabel != 0x12345 || ip.TrafficClass == nil || *ip.TrafficClass != 2 || ip.ECN != "ect0" ||
		ip.IPIDSyn != nil || ip.IPIDPattern != "unknown" || ip.TTLInitial != 255 || ip.Hops != 5 {
		t.Fatalf("ip v6 = %+v", ip)
	}
}

func TestAnalysisTFOAndOptions(t *testing.T) {
	o := parseOpts([]byte{
		2, 4, 5, 0xb4, 1, 3, 3, 14, 4, 2, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0,
		34, 6, 1, 2, 3, 4, 254, 6, 0xf9, 0x89, 7, 7, 19, 4, 0xaa, 0xbb, 30, 3, 9, 99, 3, 1, 0,
	})
	want := "mss=1460 nop wscale=14 sack_perm sack=1,2 ts=9,0 tfo=01020304 tfo=0707 md5=aabb mptcp=09 unknown=99,01 eol"
	if got := optsString(o.list); got != want || !o.tfo || !o.sackPerm || !o.hasTS || o.ws != 14 {
		t.Fatalf("opções = %s", got)
	}
	// tamanho inválido encerra com unknown e o resto em hex
	o = parseOpts([]byte{2, 4, 5, 0xb4, 30, 1, 1, 1})
	if got := optsString(o.list); got != "mss=1460 unknown=30,1e010101" {
		t.Fatalf("malformada = %s", got)
	}
	// SYN com dados (TFO)
	s := newSession(1, 2, 3)
	s.handshake(64)
	s.segs[0].opts = append(linuxSYN(3), 1, 1, 34, 10, 1, 2, 3, 4, 5, 6, 7, 8)
	s.segs[0].payload = 5
	s.cliNext += 5
	s.fin(300, 64, 1)
	rec := ingestSession(t, nil, client, s.segs)
	if !rec.TCP.Syn.TFO || rec.TCP.Syn.PayloadB64 == nil || *rec.TCP.Syn.PayloadB64 != "AAAAAAA=" {
		t.Fatalf("syn = %+v", rec.TCP.Syn)
	}
}

func TestIPIDPattern(t *testing.T) {
	cases := map[string][]uint16{
		"unknown":     {},
		"zero":        {0},
		"constant":    {7, 7, 7},
		"incremental": {65534, 65535, 0, 3},
		"random":      {1, 40000, 3},
	}
	for want, ids := range cases {
		if got := ipIDPattern(ids); got != want {
			t.Errorf("%v = %s, quer %s", ids, got, want)
		}
	}
	if ipIDPattern([]uint16{0, 0}) != "zero" || ipIDPattern([]uint16{5}) != "unknown" {
		t.Fatal("zero/unknown")
	}
}

// TestClockGroup: duas conexões do mesmo host (mesmo relógio TSval) por IPs de origem diferentes ficam no
// mesmo ts_clock_group; outro host com relógio defasado fica em outro grupo (spec 013, critério de aceite).
func TestClockGroup(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	conv := func(cli netip.AddrPort, at float64, tsBase uint32) fakeMsg {
		s := newSession(1000, 2000, tsBase)
		s.handshake(64)
		s.cliData(150, 10, 64, 1)
		s.fin(400, 64, 2)
		for i := range s.segs {
			s.segs[i].ms += at
		}
		return segBatch(cli, mirror, s.segs)
	}
	hostA1 := netip.MustParseAddrPort("192.0.2.10:40001")
	hostA2 := netip.MustParseAddrPort("198.51.100.20:40002")
	hostB := netip.MustParseAddrPort("203.0.113.30:40003")
	// relógio do host A: TSval = 1_000_000 + ms (1000 Hz); a segunda conexão começa 30 s depois
	run(t, in, 10_000, conv(hostA1, 0, 1_000_000))
	run(t, in, 60_000, conv(hostA2, 30_000, 1_030_000))
	run(t, in, 90_000, conv(hostB, 31_000, 5_000_000))
	groups := map[string]string{}
	rows, err := db.Query("SELECT src_ip, json_extract(record_json, '$.tcp.ts_clock_group') FROM connections")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var ip string
		var g *string
		if err := rows.Scan(&ip, &g); err != nil {
			t.Fatal(err)
		}
		if g == nil {
			t.Fatalf("%s sem grupo", ip)
		}
		groups[ip] = *g
	}
	if groups["192.0.2.10"] != groups["198.51.100.20"] || groups["192.0.2.10"] == groups["203.0.113.30"] {
		t.Fatalf("grupos = %v", groups)
	}
}

func TestClockRegistryEdges(t *testing.T) {
	var r clockRegistry
	c := &conn{id: "A", ana: newAnalysis()}
	if r.assign(c, true) != nil {
		t.Fatal("sem TS deveria ficar sem grupo")
	}
	// uma amostra só: sem frequência, não cria grupo
	c.ana.tsCount, c.ana.tsFirst, c.ana.tsLast = 1, tsSample{base, 10}, tsSample{base, 10}
	if r.assign(c, true) != nil {
		t.Fatal("sem frequência não cria grupo")
	}
	// 250 Hz: cria grupo e uma conexão curta (sem frequência) no mesmo relógio entra nele
	c.ana.tsCount, c.ana.tsLast = 2, tsSample{base + 1e9, 260}
	g := r.assign(c, true)
	if g == nil || r.entries[0].hz != 250 {
		t.Fatalf("grupo = %v entries = %+v", g, r.entries)
	}
	d := &conn{id: "B", ana: newAnalysis()}
	d.ana.tsCount, d.ana.tsFirst, d.ana.tsLast = 1, tsSample{base + 5e9, 1260}, tsSample{base + 5e9, 1260}
	if h := r.assign(d, false); h == nil || *h != *g {
		t.Fatalf("conexão curta = %v", h)
	}
	// relógio esquecido depois de clockKeep
	d.ana.tsFirst, d.ana.tsLast = tsSample{base + 2*clockKeep.Nanoseconds(), 1}, tsSample{base + 2*clockKeep.Nanoseconds(), 1}
	if r.assign(d, false) != nil || len(r.entries) != 0 {
		t.Fatal("relógio velho deveria sumir")
	}
	if snapHz(1003) != 1000 || snapHz(97) != 100 || snapHz(700) != 700 {
		t.Fatal("snapHz")
	}
}

func TestSynCookie(t *testing.T) {
	var h cookieHistory
	if h.rose(base) {
		t.Fatal("sem leituras")
	}
	h.add(base, 5)
	h.add(base+1e9, 5)
	h.add(base+2e9, 6)
	if h.rose(base+5e8) || !h.rose(base+15e8) || h.rose(base+3e9) {
		t.Fatal("rose")
	}
	h.add(base+clockKeep.Nanoseconds()+3e9, 6)
	if len(h.samples) != 1 {
		t.Fatalf("poda: %d", len(h.samples))
	}

	a := newAnalysis()
	if a.synCookie(true) {
		t.Fatal("sem SYN-ACK")
	}
	a.synAckSeen = true
	// sem timestamps: cookie não tem window scale nem SACK
	if !a.synCookie(true) || a.synCookie(false) {
		t.Fatal("sem TS")
	}
	a.srvWS = 7
	if a.synCookie(true) {
		t.Fatal("SYN-ACK com WS sem TS não é cookie")
	}
	// com timestamps: TSval & 0x0f = WS do cliente, bit 4 = SACK
	a.cliTS, a.srvTS, a.cliWS, a.cliSACK = true, true, 7, true
	a.srvTSval = 0xabcd00 | 0x10 | 7
	if !a.synCookie(true) {
		t.Fatal("TS com WS 7 e SACK")
	}
	a.cliWS = -1
	a.srvTSval = 0xabcd00 | 0x10 | 0x0f
	if !a.synCookie(true) {
		t.Fatal("TS sem WS")
	}
	a.srvTSval = 0xabcd00 | 7
	if a.synCookie(true) {
		t.Fatal("TSval sem a codificação")
	}
}

// TestSynCookieIngest: com o contador subindo no intervalo do SYN-ACK, o registro marca syn_cookie_server.
func TestSynCookieIngest(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.flows.sampleCookies(base-1e9, 10)
	in.flows.sampleCookies(base+1e9, 11)
	s := newSession(1, 2, 3)
	s.handshake(64)
	// SYN-ACK de cookie com TS: TSval codifica WS 7 e SACK
	binary.BigEndian.PutUint32(s.segs[1].opts[8:], 0x12340000|0x10|7)
	s.fin(300, 64, 1)
	run(t, in, 60_000, segBatch(client, mirror, s.segs))
	_, rec := onlyConn(t, db)
	if !rec.TCP.SynCookieServer {
		t.Fatalf("cookie = %+v", rec.TCP)
	}
}

func TestLiveRecordHasAnalysis(t *testing.T) {
	in, _ := newTestIngestor(t, nil)
	s := newSession(1, 2, 3)
	s.handshake(64)
	s.cliData(400, 10, 64, 9)
	src := []msgSource{segBatch(client, mirror, s.segs)}
	if err := in.process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	var id string
	for k := range in.flows.byID {
		id = k
	}
	r, ok := in.flows.live(id)
	if !ok || r.TCP == nil || r.TCP.JA4T == nil || r.IP == nil || r.TCP.TSClockGroup != nil {
		t.Fatalf("ao vivo = %+v", r)
	}
}

// TestAnalysisFinWithDataRetransmit: FIN com dados reenviado conta uma retransmissão só (como o tshark).
func TestAnalysisFinWithDataRetransmit(t *testing.T) {
	s := newSession(1, 2, 3)
	s.handshake(64)
	s.cliData(110, 50, 64, 1)
	finData := seg{ms: 120, flags: tcpFIN | tcpPSH | tcpACK, seq: s.srvNext, ack: s.cliNext, win: 509, payload: 3}
	again := finData
	again.ms = 160
	s.segs = append(s.segs, finData, again,
		seg{ms: 200, fromCli: true, flags: tcpFIN | tcpACK, seq: s.cliNext, ack: s.srvNext + 4, win: 502},
		seg{ms: 201, flags: tcpACK, seq: s.srvNext + 4, ack: s.cliNext + 1, win: 509},
	)
	rec := ingestSession(t, nil, client, s.segs)
	if rec.Totals.Out.Retransmits != 1 {
		t.Fatalf("retransmissões out = %d", rec.Totals.Out.Retransmits)
	}
}
