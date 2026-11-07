package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

var (
	client = netip.MustParseAddrPort("192.0.2.10:41234")
	mirror = netip.MustParseAddrPort("172.233.24.85:7700")
)

// frame monta um frame Ethernet IPv4 (ou IPv6) com TCP/UDP.
func frame(src, dst netip.AddrPort, proto byte, flags byte, payload int) []byte {
	f := make([]byte, 12)
	var l4 []byte
	switch proto {
	case protoTCP:
		l4 = make([]byte, 20+payload)
		l4[12] = 5 << 4
		l4[13] = flags
	case protoUDP:
		l4 = make([]byte, 8+payload)
	default:
		l4 = make([]byte, 8)
	}
	if proto == protoTCP || proto == protoUDP {
		binary.BigEndian.PutUint16(l4[0:2], src.Port())
		binary.BigEndian.PutUint16(l4[2:4], dst.Port())
	}
	if src.Addr().Is4() {
		f = binary.BigEndian.AppendUint16(f, 0x0800)
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, proto
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4))) //nolint:gosec // teste
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(ip[12:16], s[:])
		copy(ip[16:20], d[:])
		f = append(f, ip...)
	} else {
		f = binary.BigEndian.AppendUint16(f, 0x86dd)
		ip := make([]byte, 40)
		ip[0], ip[6], ip[7] = 0x60, proto, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(l4))) //nolint:gosec // teste
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(ip[8:24], s[:])
		copy(ip[24:40], d[:])
		f = append(f, ip...)
	}
	return append(f, l4...)
}

type pkt struct {
	ms      int // instante relativo (ms)
	fromCli bool
	flags   byte
	payload int
}

type fakeMsg struct {
	subject string
	data    []byte
}

func (m fakeMsg) Subject() string { return m.subject }
func (m fakeMsg) Data() []byte    { return m.data }

var base = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixNano()

// batch monta um lote FSPB com os pacotes da conversa cli <-> srv.
func batch(cli, srv netip.AddrPort, proto byte, pkts []pkt) fakeMsg {
	var buf []byte
	for _, p := range pkts {
		src, dst, dir := cli, srv, event.DirIn
		if !p.fromCli {
			src, dst, dir = srv, cli, event.DirOut
		}
		f := frame(src, dst, proto, p.flags, p.payload)
		buf = event.AppendPacket(buf, event.Packet{TsNs: base + int64(p.ms)*1e6, Dir: dir, WireLen: uint32(len(f)), Frame: f}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: buf}
}

func newTestIngestor(t *testing.T, mut func(*IngestConfig)) (*Ingestor, *sql.DB) {
	t.Helper()
	db, _ := testDB(t)
	cfg := IngestConfig{
		PcapMax: 16 << 20, TCPIdle: 150 * time.Second, UDPIdle: 30 * time.Second, CloseGrace: time.Second,
		MaxOpen: 200, MaxNewPerS: 50, Snaplen: 65535,
	}
	if mut != nil {
		mut(&cfg)
	}
	in := NewIngestor(db, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), service.NewMetrics())
	in.now = func() time.Time { return time.Unix(0, base) }
	return in, db
}

// run processa os lotes e encerra o que estiver vencido em at (ms relativos).
func run(t *testing.T, in *Ingestor, atMs int, msgs ...fakeMsg) {
	t.Helper()
	src := make([]msgSource, len(msgs))
	for i, m := range msgs {
		src[i] = m
	}
	if err := in.process(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if err := in.Finalize(context.Background(), in.flows.due(base+int64(atMs)*1e6)); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func onlyConn(t *testing.T, db *sql.DB) (string, connectionJSON) {
	t.Helper()
	var id, raw string
	if err := db.QueryRow("SELECT conn_id, record_json FROM connections").Scan(&id, &raw); err != nil {
		t.Fatal(err)
	}
	var r connectionJSON
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	return id, r
}

var fullTCP = []pkt{
	{0, true, tcpSYN, 0},
	{10, false, tcpSYN | tcpACK, 0},
	{20, true, tcpACK, 0},
	{25, true, tcpACK | tcpPSH, 100},
	{35, false, tcpACK | tcpPSH, 1000},
	{40, true, tcpACK, 0},
	{1040, true, tcpFIN | tcpACK, 0},
	{1050, false, tcpFIN | tcpACK, 0},
	{1060, true, tcpACK, 0},
}

func TestIngestFullTCPConnection(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 6 {
		t.Fatalf("open connection must keep packets: %d", n)
	}
	run(t, in, 3000, batch(client, mirror, protoTCP, fullTCP[6:]))

	id, r := onlyConn(t, db)
	if r.Src.Port != 41234 || r.Dst.Port != 7700 || r.L4 != "tcp" || r.Family != 4 || r.Ended == nil {
		t.Fatalf("%+v", r)
	}
	if r.Times.Syn == nil || r.Times.SynAck == nil || r.Times.Established == nil || r.Times.FirstData == nil ||
		*r.Times.Established != event.FormatTime(time.Unix(0, base+20e6)) {
		t.Fatalf("times %+v", r.Times)
	}
	if r.Close.By != "client" || r.Close.How != "fin" || r.Close.IdleBeforeCloseMs == nil || *r.Close.IdleBeforeCloseMs != 1005 || r.Close.HalfClose {
		t.Fatalf("close %+v", r.Close)
	}
	if r.Totals.In.AppBytes != 100 || r.Totals.Out.AppBytes != 1000 || r.Totals.In.Segments != 6 || r.Totals.Out.Segments != 3 || r.Totals.In.DataSegments != 1 {
		t.Fatalf("totals %+v", r.Totals)
	}
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 0 {
		t.Fatalf("packets must be deleted after pcap: %d", n)
	}
	var data []byte
	if err := db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data); err != nil {
		t.Fatal(err)
	}
	checkPcap(t, data, len(fullTCP))
}

// checkPcap lê o pcap com o gopacket e, se houver tshark, com o tshark.
func checkPcap(t *testing.T, data []byte, want int) {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	var prev time.Time
	for {
		_, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if ci.Timestamp.Before(prev) {
			t.Fatal("pcap out of order")
		}
		prev = ci.Timestamp
		n++
	}
	if n != want {
		t.Fatalf("pcap has %d packets, want %d", n, want)
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Log("tshark ausente: conferência pulada")
		return
	}
	path := filepath.Join(t.TempDir(), "c.pcap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tshark, "-r", path, "-T", "fields", "-e", "tcp.flags.str").CombinedOutput() //nolint:gosec // teste
	if err != nil {
		t.Fatalf("tshark: %v %s", err, out)
	}
	if lines := strings.Count(strings.TrimSpace(string(out)), "\n") + 1; lines != want {
		t.Fatalf("tshark read %d packets, want %d:\n%s", lines, want, out)
	}
}

func TestIngestRSTWithoutConnectionIsStray(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 0, batch(client, mirror, protoTCP, []pkt{{0, true, tcpRST, 0}}))
	if count(t, db, "SELECT count(*) FROM connections") != 0 || count(t, db, "SELECT count(*) FROM stray_packets") != 1 {
		t.Fatal("RST without connection must be stray")
	}
	var raw string
	_ = db.QueryRow("SELECT record_json FROM stray_packets").Scan(&raw)
	if !strings.Contains(raw, `"tcp_flags":"R"`) || !strings.Contains(raw, `"dir":"in"`) {
		t.Fatal(raw)
	}
}

func TestIngestSYNWithoutAnswerBecomesStray(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 0, batch(client, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {1000, true, tcpSYN, 0}}))
	if count(t, db, "SELECT count(*) FROM connections") != 1 {
		t.Fatal("pending connection expected while waiting")
	}
	run(t, in, 200_000) // passa a ociosidade de 150 s
	if count(t, db, "SELECT count(*) FROM connections") != 0 || count(t, db, "SELECT count(*) FROM stray_packets") != 2 {
		t.Fatal("unanswered SYNs must become stray packets")
	}
}

func TestIngestRefusedSYNIsStray(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	// Porta fechada: o kernel responde RST ao SYN; não houve conexão.
	run(t, in, 5000, batch(client, mirror, protoTCP, []pkt{{0, true, tcpSYN, 0}, {1, false, tcpRST | tcpACK, 0}}))
	if count(t, db, "SELECT count(*) FROM connections") != 0 || count(t, db, "SELECT count(*) FROM stray_packets") != 2 {
		t.Fatal("refused SYN and its RST must be stray packets")
	}
}

func TestIngestReuseOfFiveTuple(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	second := make([]pkt, len(fullTCP))
	for i, p := range fullTCP {
		p.ms += 1200 // começa antes de a folga do primeiro acabar
		second[i] = p
	}
	run(t, in, 0, batch(client, mirror, protoTCP, fullTCP))
	run(t, in, 10_000, batch(client, mirror, protoTCP, second))
	if n := count(t, db, "SELECT count(*) FROM connections WHERE ended_ns IS NOT NULL"); n != 2 {
		t.Fatalf("reused 5-tuple must create a second connection: %d", n)
	}
	if count(t, db, "SELECT count(*) FROM pcaps") != 2 {
		t.Fatal("two pcaps expected")
	}
}

func TestIngestServerInitiatedFlow(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	ntp := netip.MustParseAddrPort("203.0.113.5:123")
	local := netip.MustParseAddrPort("172.233.24.85:40000")
	// O servidor manda primeiro: ele é o "cliente" da conexão (quem iniciou).
	run(t, in, 0, batch(local, ntp, protoUDP, []pkt{{0, true, 0, 48}, {20, false, 0, 48}}))
	run(t, in, 60_000)
	_, r := onlyConn(t, db)
	if r.Src.IP != "172.233.24.85" || r.Dst.Port != 123 || r.L4 != "udp" || r.Times != nil || r.Close.How != "timeout" {
		t.Fatalf("%+v", r)
	}
}

func TestIngestUDPSoloAndICMPAreStray(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	icmp := frame(client, mirror, protoICMP, 0, 0)
	b := event.AppendPacket(nil, event.Packet{TsNs: base, WireLen: uint32(len(icmp)), Frame: icmp}) //nolint:gosec // teste
	b = event.AppendPacket(b, event.Packet{TsNs: base, WireLen: 3, Frame: []byte{1, 2, 3}})
	run(t, in, 0, fakeMsg{subject: event.SubjectCapturePacket, data: b}, batch(client, mirror, protoUDP, []pkt{{0, true, 0, 10}}))
	run(t, in, 60_000)
	if count(t, db, "SELECT count(*) FROM connections") != 0 || count(t, db, "SELECT count(*) FROM stray_packets") != 3 {
		t.Fatalf("stray=%d", count(t, db, "SELECT count(*) FROM stray_packets"))
	}
}

func TestIngestPcapTruncation(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.PcapMax = 300 })
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP))
	id, r := onlyConn(t, db)
	if !r.PcapTruncated || count(t, db, "SELECT pcap_truncated FROM connections") != 1 {
		t.Fatal("must be truncated")
	}
	var data []byte
	_ = db.QueryRow("SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&data)
	pr, _ := pcapgo.NewReader(bytes.NewReader(data))
	var sawCut bool
	for {
		d, ci, err := pr.ReadPacketData()
		if err != nil {
			break
		}
		if ci.CaptureLength < ci.Length {
			sawCut = true
			if len(d) != 54 { // Ethernet + IPv4 + TCP
				t.Fatalf("truncated frame keeps %d bytes, want headers only (54)", len(d))
			}
		}
	}
	if !sawCut {
		t.Fatal("no truncated packet in pcap")
	}
}

func TestIngestDegradedMode(t *testing.T) {
	in, db := newTestIngestor(t, func(c *IngestConfig) { c.MaxNewPerS = 1 })
	other := netip.MustParseAddrPort("192.0.2.11:5000")
	run(t, in, 0, batch(client, mirror, protoTCP, fullTCP[:3]), batch(other, mirror, protoTCP, fullTCP[:3]))
	if n := count(t, db, "SELECT count(*) FROM connections WHERE degraded = 1"); n != 1 {
		t.Fatalf("degraded=%d", n)
	}
	if n := count(t, db, "SELECT count(*) FROM packets"); n != 3 {
		t.Fatalf("degraded connection must not store packets: %d", n)
	}
	run(t, in, 200_000)
	if count(t, db, "SELECT count(*) FROM pcaps") != 1 {
		t.Fatal("degraded connection has no pcap")
	}
	if in.metrics.Get("store_degraded_connections_total") != 1 {
		t.Fatal("metric")
	}
}

func TestIngestHalfCloseAndRST(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	pk := append(append([]pkt(nil), fullTCP[:6]...),
		pkt{100, true, tcpFIN | tcpACK, 0}, pkt{110, false, tcpACK | tcpPSH, 500}, pkt{120, false, tcpRST, 0})
	run(t, in, 5000, batch(client, mirror, protoTCP, pk))
	_, r := onlyConn(t, db)
	if r.Close.By != "client" || r.Close.How != "fin" || !r.Close.HalfClose || r.Times.ServerRst == nil {
		t.Fatalf("%+v %+v", r.Close, r.Times)
	}
}

func TestIngestIgnoresOtherSubjectsAndBadBatches(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 0, fakeMsg{subject: event.SubjectHeartbeat, data: []byte("{}")},
		fakeMsg{subject: event.SubjectCapturePacket, data: []byte{1, 2, 3}})
	if count(t, db, "SELECT count(*) FROM connections") != 0 || in.metrics.Get("store_bad_batches_total") != 1 {
		t.Fatal("bad batch must be counted and nothing stored")
	}
}

func TestIngestIPv6(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	c6 := netip.MustParseAddrPort("[2001:db8::10]:40000")
	m6 := netip.MustParseAddrPort("[2600:3c0d::f03c:93ff:fe26:8fd9]:443")
	run(t, in, 5000, batch(c6, m6, protoTCP, fullTCP))
	_, r := onlyConn(t, db)
	if r.Family != 6 || r.Src.IP != "2001:db8::10" || r.Close.How != "fin" {
		t.Fatalf("%+v", r)
	}
}

func TestRecoverOrphans(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 500, batch(client, mirror, protoTCP, fullTCP[:6]))
	// Novo ingest (reinício do store) com a mesma base.
	in2 := NewIngestor(db, in.cfg, in.log, service.NewMetrics())
	if err := in2.recoverOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, r := onlyConn(t, db)
	if r.Ended == nil || r.Close.How != "timeout" || count(t, db, "SELECT count(*) FROM pcaps") != 1 || count(t, db, "SELECT count(*) FROM packets") != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestRetention(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP), batch(client, mirror, protoTCP, []pkt{{0, true, tcpRST, 0}}))
	open := netip.MustParseAddrPort("192.0.2.99:1")
	run(t, in, 5000, batch(open, mirror, protoTCP, fullTCP[:3])) // continua aberta

	r := NewRetention(db, 10*time.Minute, 1<<30)
	if n, err := r.RunOnce(context.Background(), time.Unix(0, base).Add(5*time.Minute)); err != nil || n != 0 {
		t.Fatalf("nothing expires before 10 min: %d %v", n, err)
	}
	n, err := r.RunOnce(context.Background(), time.Unix(0, base).Add(11*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("expunged %d %v", n, err)
	}
	if count(t, db, "SELECT count(*) FROM connections") != 1 || count(t, db, "SELECT count(*) FROM stray_packets") != 0 || count(t, db, "SELECT count(*) FROM pcaps") != 0 {
		t.Fatal("only the open connection must remain")
	}
}

func TestRetentionSizeCap(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	empty, _ := NewRetention(db, time.Hour, 0).logicalSize(context.Background())
	for i := range 50 {
		cli := netip.AddrPortFrom(client.Addr(), uint16(10000+i)) //nolint:gosec // teste
		big := append([]pkt(nil), fullTCP...)
		big[4].payload = 1400
		run(t, in, 5000, batch(cli, mirror, protoTCP, big))
	}
	full, _ := NewRetention(db, time.Hour, 0).logicalSize(context.Background())
	limit := empty + (full-empty)/2
	r := NewRetention(db, time.Hour, limit)
	r.batch = 5 // lotes pequenos para o teste ver o expurgo parar no teto
	if _, err := r.RunOnce(context.Background(), time.Unix(0, base)); err != nil {
		t.Fatal(err)
	}
	size, _ := r.logicalSize(context.Background())
	if size > limit {
		t.Fatalf("logical size %d above cap", size)
	}
	if n := count(t, db, "SELECT count(*) FROM connections"); n == 0 || n == 50 {
		t.Fatalf("expected oldest connections removed, kept %d", n)
	}
}

func TestTCPFlagsString(t *testing.T) {
	if s := tcpFlagsString(0xff); s != "SAFRPUEC" {
		t.Fatal(s)
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(frame(client, mirror, protoTCP, tcpSYN, 10))
	f.Add(frame(netip.MustParseAddrPort("[2001:db8::1]:1"), netip.MustParseAddrPort("[2001:db8::2]:2"), protoUDP, 0, 5))
	f.Fuzz(func(t *testing.T, b []byte) {
		fi := parseFrame(b)
		if fi.payload < 0 || fi.headers > len(b) {
			t.Fatalf("%+v for %d bytes", fi, len(b))
		}
	})
}
