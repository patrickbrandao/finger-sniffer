package store

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

var (
	quicClient = netip.MustParseAddrPort("192.0.2.10:52000")
	quicMirror = netip.MustParseAddrPort("172.233.24.85:443")
	dcidA      = []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	dcidB      = []byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8}
)

// udpFrame monta um frame Ethernet IPv4/UDP com os dados dados.
func udpFrame(src, dst netip.AddrPort, data []byte) []byte {
	f := frame(src, dst, protoUDP, 0, len(data))
	copy(f[len(f)-len(data):], data)
	return f
}

// quicInitial devolve os dados de um datagrama Initial QUIC v1 (cabeçalho longo) com o DCID dado, preenchido
// até 1200 bytes. O conteúdo cifrado é irrelevante para o store.
func quicInitial(dcid []byte) []byte {
	p := []byte{0xc3}
	p = binary.BigEndian.AppendUint32(p, 1)
	p = append(p, byte(len(dcid)))
	p = append(p, dcid...)
	p = append(p, 0) // SCID vazio
	return append(p, make([]byte, 1200-len(p))...)
}

// quicShort devolve um pacote de cabeçalho curto (1-RTT).
func quicShort(n int) []byte { return append([]byte{0x43}, make([]byte, n)...) }

type udpPkt struct {
	ms      int
	fromCli bool
	data    []byte
}

func udpBatch(cli, srv netip.AddrPort, pkts []udpPkt) fakeMsg {
	var buf []byte
	for _, p := range pkts {
		src, dst, dir := cli, srv, event.DirIn
		if !p.fromCli {
			src, dst, dir = srv, cli, event.DirOut
		}
		f := udpFrame(src, dst, p.data)
		buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(p.ms)*1e6, Dir: dir, WireLen: uint32(len(f)), Frame: f}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

// quicPackets é o handshake QUIC e algumas trocas 1-RTT, de 0 a 60 ms.
func quicPackets(dcid []byte, at int) []udpPkt {
	return []udpPkt{
		{at, true, quicInitial(dcid)},
		{at + 10, false, quicInitial([]byte{1, 2, 3, 4})},
		{at + 20, true, quicShort(60)},
		{at + 40, false, quicShort(900)},
		{at + 60, true, quicShort(30)},
	}
}

// h3Conn monta um payload de fs.v1.web.http3.connection como o web publica: alpn negociado, SETTINGS opcional e
// close opcional.
func h3Conn(alpn string, settings bool, cl *event.HTTP3Close) event.HTTP3Info {
	neg := map[string]any{"version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "group": "X25519", "alpn": alpn, "resumed": false}
	if alpn == "" {
		neg = nil
	}
	hello, _ := json.Marshal(map[string]any{"sni": probeID + ".dns-monitor.tmsoft.com.br", "ja4": "q13d0312h3_55b375c5d22e_06cda9e17597", "negotiated": neg, "handshake_ms": 12.5})
	info := event.HTTP3Info{
		Version: "00000001", DCIDHex: hex.EncodeToString(dcidA), SCIDHex: "", TokenLen: 0, TokenHex: "",
		InitialLength: 1182, InitialPacketNumber: 0, InitialDatagramSize: 1200, PaddedTo1200: true, CoalescedPackets: 1,
		ClientHelloDatagrams: 1, InitialFrames: []string{"CRYPTO", "PADDING"},
		TransportParams: []event.TransportParam{{ID: 1, Name: "max_idle_timeout", ValueHex: "8000ea60"}},
		ClientHello:     hello, H3Settings: [][2]uint64{}, Close: cl, Requests: []event.HTTP3Request{},
	}
	if settings {
		info.H3Settings, info.H3ControlStreamSeen = [][2]uint64{{1, 0}, {6, 16384}, {7, 0}}, true
	}
	return info
}

func h3Req(stream int64, path string, status int) event.HTTP3Request {
	f := false
	idx := 17
	return event.HTTP3Request{
		StreamID: stream, PseudoOrder: []string{":method", ":scheme", ":authority", ":path"},
		Fields: []event.QPACKField{
			{Name: ":method", Value: "GET", Repr: "indexed", Static: ptrTo(true), Index: &idx},
			{Name: ":path", Value: path, Repr: "literal-name-ref", Static: ptrTo(true), Index: ptrTo(1), NeverIndexed: &f, HuffmanValue: &f},
		},
		BodyLen: 0, Status: status,
	}
}

func ptrTo[T any](v T) *T { return &v }

// h3Msg monta o evento h3 com flow.l4 = udp e flow.quic_dcid_hex.
func h3Msg(t *testing.T, subject string, cli netip.AddrPort, dcid []byte, ms int, payload any) fakeMsg {
	t.Helper()
	flow := &event.Flow{
		L4: "udp", SrcIP: cli.Addr().String(), SrcPort: int(cli.Port()), DstIP: quicMirror.Addr().String(),
		DstPort: int(quicMirror.Port()), QUICDCIDHex: hex.EncodeToString(dcid),
	}
	env, err := event.New(event.ServiceWeb, "test", time.Unix(0, base+int64(ms)*1e6), flow, payload)
	if err != nil {
		t.Fatal(err)
	}
	p := probeID
	env.ProbeID = &p
	data, _ := json.Marshal(env)
	return fakeMsg{subject: subject, data: data}
}

// h3Session devolve os pacotes e eventos de uma conexão h3 completa: 3 versões de http3.connection, 2 requisições
// (uma publicada duas vezes, substituída por stream_id) e close do cliente em closeMs.
func h3Session(t *testing.T, closeMs int) []fakeMsg {
	cl := &event.HTTP3Close{By: "client", How: event.QUICCloseApplication, ErrorCode: ptrTo(uint64(0x100)), Reason: ptrTo("")}
	return []fakeMsg{
		udpBatch(quicClient, quicMirror, quicPackets(dcidA, 0)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, h3Conn("h3", false, nil)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 35, h3Conn("h3", true, nil)),
		h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 50, h3Req(0, "/", 0)),
		h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 55, h3Req(0, "/", 200)),
		h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 70, h3Req(4, "/favicon.ico", 404)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, closeMs, h3Conn("h3", true, cl)),
	}
}

// http3JSON é a parte do registro conferida pelos testes.
type http3JSON struct {
	Version    string          `json:"version"`
	H3Settings [][2]uint64     `json:"h3_settings"`
	Close      json.RawMessage `json:"close"`
	Requests   []struct {
		StreamID int64 `json:"stream_id"`
		Status   int   `json:"status"`
	} `json:"requests"`
}

func checkH3Record(t *testing.T, r connectionJSON, closeMs int) {
	t.Helper()
	var h3 http3JSON
	if err := json.Unmarshal(r.HTTP3, &h3); err != nil {
		t.Fatalf("http3: %v %s", err, r.HTTP3)
	}
	if r.Proto != "quic/h3" || r.L4 != "udp" || r.Requests != 2 || len(h3.Requests) != 2 || h3.Requests[0].Status != 200 || h3.Requests[1].StreamID != 4 {
		t.Fatalf("proto=%s requests=%d h3=%+v", r.Proto, r.Requests, h3)
	}
	if len(h3.H3Settings) != 3 || h3.Version != "00000001" || string(h3.Close) == "null" {
		t.Fatalf("connection level must be the last version: %s", r.HTTP3)
	}
	if r.Close.How != "quic_close" || r.Close.By != "client" || r.Ended == nil {
		t.Fatalf("close=%+v ended=%v", r.Close, r.Ended)
	}
	end := parseTs(*r.Ended)
	if final := base + int64(closeMs)*1e6; end < final || end > final+int64(3*time.Second) {
		t.Fatalf("end %d ms after the final event", (end-final)/1e6)
	}
	var tls struct {
		SNI        string `json:"sni"`
		Negotiated struct {
			ALPN string `json:"alpn"`
		} `json:"negotiated"`
	}
	if err := json.Unmarshal(r.TLS, &tls); err != nil || tls.SNI == "" || tls.Negotiated.ALPN != "h3" {
		t.Fatalf("tls must be the Initial ClientHello: %s", r.TLS)
	}
	if r.Times == nil || r.Times.TLSDone == nil || parseTs(*r.Times.TLSDone) != base+30e6 {
		t.Fatalf("times=%+v", r.Times)
	}
	if r.ProbeID == nil || *r.ProbeID != probeID {
		t.Fatal("probe_id")
	}
}

// TestHTTP3Record: pacotes UDP + 3 versões de http3.connection + 2 requisições → registro quic/h3 que fecha 2 s
// depois do close do web, com close.how = quic_close.
func TestHTTP3Record(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	id, _ := onlyConn(t, db)
	if r := recordOf(t, in, id); r.Proto != "quic/h3" || r.Requests != 2 || r.Ended != nil || r.Close.How != "open" {
		t.Fatalf("live record: proto=%s requests=%d close=%+v", r.Proto, r.Requests, r.Close)
	}
	run(t, in, 1100, msgs[6])
	run(t, in, 2900) // ainda dentro da folga de 2 s
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL") != 1 {
		t.Fatal("closed before the 2 s grace")
	}
	run(t, in, 3001)
	if count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL AND proto = 'quic/h3'") != 1 {
		t.Fatal("QUIC connection not closed 2 s after the web close")
	}
	checkH3Record(t, recordOf(t, in, id), 1000)
	if count(t, db, "SELECT count(*) FROM pcaps WHERE conn_id = ?", id) != 1 {
		t.Fatal("pcap")
	}
}

// TestHTTP3IdleTimeoutClose: close do web por idle_timeout vira close.how = timeout.
func TestHTTP3IdleTimeoutClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	cl := &event.HTTP3Close{By: "server", How: event.QUICCloseIdleTimeout}
	run(t, in, 100, udpBatch(quicClient, quicMirror, quicPackets(dcidA, 0)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, h3Conn("h3", true, nil)))
	run(t, in, 5000, h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 4000, h3Conn("h3", true, cl)))
	run(t, in, 6100)
	_, r := onlyConn(t, db)
	if r.Ended == nil || r.Close.How != "timeout" || r.Close.By != "server" || r.Requests != 0 {
		t.Fatalf("%+v", r.Close)
	}
}

// TestHTTP3IdleStaysOpen: QUIC sem close ocioso por 60 s continua aberto (ociosidade do TCP, não a de UDP); um
// fluxo UDP comum fecha em 30 s.
func TestHTTP3IdleStaysOpen(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	other := netip.MustParseAddrPort("192.0.2.30:53000")
	run(t, in, 100, udpBatch(quicClient, quicMirror, quicPackets(dcidA, 0)), udpBatch(other, quicMirror, quicPackets(dcidB, 0)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, h3Conn("h3", true, nil)))
	run(t, in, 61000)
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NULL AND proto = 'quic/h3'"); n != 1 {
		t.Fatalf("idle QUIC connection must stay open: %d", n)
	}
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL AND proto = 'udp'"); n != 1 {
		t.Fatalf("plain UDP flow must close after 30 s: %d", n)
	}
	// Mais tráfego depois de 60 s cai no mesmo registro.
	run(t, in, 61500, udpBatch(quicClient, quicMirror, []udpPkt{{61000, true, quicShort(40)}}),
		h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 61010, h3Req(8, "/late", 200)))
	if n := count(t, db, "SELECT count(*) FROM connections WHERE src_port = ?", int(quicClient.Port())); n != 1 {
		t.Fatalf("QUIC connection split in %d records", n)
	}
	id := ""
	_ = db.QueryRow("SELECT conn_id FROM connections WHERE proto = 'quic/h3'").Scan(&id)
	if r := recordOf(t, in, id); r.Requests != 1 || r.Totals.In.Segments != 4 {
		t.Fatalf("requests=%d in=%d", r.Requests, r.Totals.In.Segments)
	}
	// Sem pacotes nem eventos além de FS_IDLE_DEFAULT + 30 s (150 s no teste), fecha por ociosidade.
	run(t, in, 61000+151000)
	if r := recordOf(t, in, id); r.Ended == nil || r.Close.How != "timeout" {
		t.Fatalf("close=%+v", r.Close)
	}
}

// TestHTTP3NewDCIDAfterClose: na mesma 5-tupla, um Initial com DCID novo depois do close abre um segundo conn_id
// (o reservado por fs.v1.store.conn_id com l4=udp); evento atrasado da primeira conexão continua nela.
func TestHTTP3NewDCIDAfterClose(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	in.flows.newID = fixedIDs()
	flow := event.Flow{L4: "udp", SrcIP: quicClient.Addr().String(), SrcPort: int(quicClient.Port()), DstIP: quicMirror.Addr().String(), DstPort: int(quicMirror.Port())}
	req, _ := json.Marshal(event.ConnIDRequest{Flow: flow, Ts: event.FormatTime(time.Unix(0, base))})
	connIDOf := func(now int64) event.ConnIDReply {
		data, err := replyConnID(in.flows, req, now)
		if err != nil {
			t.Fatal(err)
		}
		var rep event.ConnIDReply
		_ = json.Unmarshal(data, &rep)
		return rep
	}
	first := connIDOf(base)
	if !first.Reserved {
		t.Fatalf("%+v", first)
	}
	cl := &event.HTTP3Close{By: "client", How: event.QUICCloseConnection}
	run(t, in, 200, udpBatch(quicClient, quicMirror, quicPackets(dcidA, 0)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, h3Conn("h3", true, nil)))
	if rep := connIDOf(base + 100e6); rep.Reserved || rep.ConnID != first.ConnID {
		t.Fatalf("open UDP connection: %+v want %s", rep, first.ConnID)
	}
	run(t, in, 600, h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 500, h3Conn("h3", true, cl)))
	// Fechando: a próxima conexão QUIC da 5-tupla recebe um ID novo, reservado.
	second := connIDOf(base + 700e6)
	if !second.Reserved || second.ConnID == first.ConnID {
		t.Fatalf("closing connection must reserve a new ID: %+v", second)
	}
	// Initial com o mesmo DCID (retransmissão) não abre conexão; com DCID novo abre, ainda dentro da folga.
	run(t, in, 800, udpBatch(quicClient, quicMirror, []udpPkt{{750, true, quicInitial(dcidA)}}))
	if n := count(t, db, "SELECT count(*) FROM connections"); n != 1 {
		t.Fatalf("same DCID opened a connection: %d", n)
	}
	run(t, in, 1000, udpBatch(quicClient, quicMirror, quicPackets(dcidB, 900)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidB, 930, h3Conn("h3", true, nil)),
		// Evento atrasado da primeira conexão (DCID antigo, anterior ao início da segunda).
		h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 450, h3Req(0, "/first", 200)))
	run(t, in, 4000)
	rows := map[string]bool{}
	r, err := db.Query("SELECT conn_id FROM connections ORDER BY started_ns")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for r.Next() {
		var id string
		_ = r.Scan(&id)
		ids = append(ids, id)
		rows[id] = true
	}
	_ = r.Close()
	if len(ids) != 2 || ids[0] != first.ConnID || ids[1] != second.ConnID {
		t.Fatalf("conn_ids %v want %s, %s", ids, first.ConnID, second.ConnID)
	}
	one, two := recordOf(t, in, first.ConnID), recordOf(t, in, second.ConnID)
	if one.Close.How != "quic_close" || one.Requests != 1 || two.Ended != nil || two.Requests != 0 || two.Proto != "quic/h3" {
		t.Fatalf("first=%+v/%d second=%v/%d", one.Close, one.Requests, two.Ended, two.Requests)
	}
}

// TestQUICProto: Initial analisado sem h3 (handshake falho, outro ALPN) é quic; sem prefixo tls/.
func TestQUICProto(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{{"h3", "quic/h3"}, {"", "quic"}, {"hq-interop", "quic"}}
	for _, c := range cases {
		var l layers
		m := h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 0, h3Conn(c.alpn, false, nil))
		ev, err := parseAppEvent(m.subject, m.data)
		if err != nil {
			t.Fatal(err)
		}
		l.addLayer(ev)
		if got := l.proto("udp"); got != c.want {
			t.Errorf("alpn %q: %s want %s", c.alpn, got, c.want)
		}
	}
	var l layers
	m := h3Msg(t, event.SubjectWebHTTP3Request, quicClient, dcidA, 0, h3Req(0, "/", 200))
	ev, _ := parseAppEvent(m.subject, m.data)
	l.addLayer(ev)
	if l.proto("udp") != "quic/h3" {
		t.Fatal("request without connection event")
	}
}

func TestQUICInitialDCID(t *testing.T) {
	udp := func(p []byte) []byte { return append(make([]byte, 8), p...) }
	v2 := []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf, 2, 0xab, 0xcd, 0}
	v2Handshake := []byte{0xe0, 0x6b, 0x33, 0x43, 0xcf, 2, 0xab, 0xcd, 0}
	for _, c := range []struct {
		name string
		p    []byte
		dcid string
		ok   bool
	}{
		{"v1 initial", quicInitial(dcidA), hex.EncodeToString(dcidA), true},
		{"v2 initial", v2, "abcd", true},
		{"v2 handshake", v2Handshake, "", false},
		{"v1 handshake", []byte{0xe3, 0, 0, 0, 1, 1, 0xff, 0}, "", false},
		{"short", quicShort(20), "", false},
		{"version negotiation", []byte{0x80, 0, 0, 0, 0, 1, 0xff, 0}, "", false},
		{"dcid too long", []byte{0xc0, 0, 0, 0, 1, 21, 0, 0}, "", false},
		{"truncated", []byte{0xc0, 0, 0, 0, 1, 8, 0}, "", false},
	} {
		dcid, ok := quicInitialDCID(udp(c.p))
		if dcid != c.dcid || ok != c.ok {
			t.Errorf("%s: %q %v", c.name, dcid, ok)
		}
	}
}

// TestIntegrationHTTP3: NATS embutido, store real; pacotes UDP + http3.connection (3 versões) + 2 http3.request →
// registro quic/h3 em /api/v1/connections/{id} com close.how = quic_close, fechado ≤ 3 s depois do evento final.
func TestIntegrationHTTP3(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	storeSvc, err := service.New(event.ServiceStore)
	if err != nil {
		t.Fatal(err)
	}
	_, path := testDB(t)
	port := freePort(t)
	cfg := Config{
		DBPath: path, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", port), Retention: "10m", MaxBytes: 1 << 30,
		DownAfter: time.Minute, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
		Ingest: IngestConfig{
			PcapMax: 16 << 20, TCPIdle: time.Minute, UDPIdle: 30 * time.Second, CloseGrace: 100 * time.Millisecond,
			MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
		},
	}
	st, err := New(ctx, storeSvc, cfg, []byte("openapi: 3.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = st.Run(ctx) }()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	eventually(t, 5*time.Second, func() bool {
		s, err := js.Stream(ctx, StreamName)
		return err == nil && s.CachedInfo() != nil
	}, "stream not created")

	// Tudo no relógio atual: o close vale a partir de agora.
	shift := time.Now().UnixNano() - base
	closeMs := 200
	for _, m := range h3Session(t, closeMs) {
		var data []byte
		if m.subject == event.SubjectCapturePacket {
			var buf []byte
			_, _ = event.DecodePackets(m.data, func(p event.Packet) error {
				p.TsNs += shift
				buf = event.AppendPacket(buf, p)
				return nil
			})
			data = buf
		} else {
			env, _ := event.Decode(m.data)
			when, _ := env.Time()
			env.Ts = event.FormatTime(when.Add(time.Duration(shift)))
			data, _ = json.Marshal(env)
		}
		if _, err := js.Publish(ctx, m.subject, data); err != nil {
			t.Fatal(err)
		}
	}
	final := time.Unix(0, base+shift+int64(closeMs)*1e6)
	var id string
	eventually(t, 5*time.Second, func() bool {
		return st.db.QueryRow("SELECT conn_id FROM connections WHERE ended_ns IS NOT NULL").Scan(&id) == nil
	}, "QUIC connection never closed")
	if d := time.Since(final); d > 3*time.Second {
		t.Fatalf("closed %v after the final event", d)
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/connections/%s", port, id)) //nolint:noctx,gosec // teste
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var r connectionJSON
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	// Os tempos foram deslocados: confere contra o close deslocado.
	checkH3Record(t, shiftRecord(r, -shift), closeMs)
}

// shiftRecord desloca ended e times.tls_done para comparar com os tempos relativos a base.
func shiftRecord(r connectionJSON, d int64) connectionJSON {
	sh := func(s *string) *string {
		if s == nil {
			return nil
		}
		return tsPtr(parseTs(*s) + d)
	}
	r.Ended = sh(r.Ended)
	if r.Times != nil {
		t := *r.Times
		t.TLSDone = sh(t.TLSDone)
		r.Times = &t
	}
	return r
}
