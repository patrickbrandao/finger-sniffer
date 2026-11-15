package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	gplayers "github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Golden de MSS/MTU (spec 013 RF-06a) e de ip.src_kind (RF-05a), ADR 0031, task 197. Cada caso é um pcap
// sintético em testdata/synth/ (um handshake TCP completo, ou um fluxo UDP) gerado por este arquivo com
// `go test ./internal/store -run TestSynthGolden -update`; sem -update o teste confere que o pcap gravado é o
// mesmo que o gerador produz. O pcap passa pelo caminho real do store (lote FSPB → correlação → análise →
// record_json) e os campos saem conferidos contra a tabela dos critérios da spec 013 e contra o golden
// testdata/synth/mss-srckind.json.

const synthDir = "testdata/synth"

var (
	synthSrv4 = netip.MustParseAddrPort("170.247.40.86:8443")
	synthSrv6 = netip.MustParseAddrPort("[2804:231c:e500:cafe::86]:8443")
)

// synthCase é um pcap sintético e o que o registro dele deve trazer.
type synthCase struct {
	name string
	cli  string // ip:porta do cliente
	// kind do conteúdo: "mss" (handshake com a opção MSS de valor mss), "nomss" (SYN sem a opção), "retx"
	// (SYN retransmitido com outro MSS), "nosyn" (conexão vista sem o SYN) e "udp" (fluxo UDP).
	kind string
	mss  int
	// esperado; mtu/reduction só valem quando wantMSS > 0 (0 = os três nulos)
	wantMSS, wantMTU, wantRed int
	wantKind                  string
}

// mssCase e kindCase montam os casos das duas tabelas.
func mssCase(name, cli string, mss, mtu, red int) synthCase {
	return synthCase{name: name, cli: cli, kind: "mss", mss: mss, wantMSS: mss, wantMTU: mtu, wantRed: red, wantKind: "global"}
}

func kindCase(name, cli, kind string) synthCase {
	c := synthCase{name: name, cli: cli, kind: "mss", mss: 1460, wantMSS: 1460, wantMTU: 1500, wantRed: 0, wantKind: kind}
	if netip.MustParseAddrPort(cli).Addr().Is6() {
		c.mss, c.wantMSS = 1440, 1440
	}
	return c
}

var synthCases = []synthCase{
	// MSS: tabela dos critérios de aceite da spec 013 (RF-06a)
	mssCase("v4-mss1460", "8.8.4.4:40001", 1460, 1500, 0),
	mssCase("v4-mss1452", "8.8.4.4:40002", 1452, 1492, 8),
	mssCase("v4-mss1440", "8.8.4.4:40003", 1440, 1480, 20),
	mssCase("v4-mss1380", "8.8.4.4:40004", 1380, 1420, 80),
	mssCase("v4-mss8960", "8.8.4.4:40005", 8960, 9000, -7500),
	{name: "v4-nomss", cli: "8.8.4.4:40006", kind: "nomss", wantKind: "global"},
	mssCase("v6-mss1440", "[2804:14c::9]:40001", 1440, 1500, 0),
	mssCase("v6-mss1432", "[2804:14c::9]:40002", 1432, 1492, 8),
	mssCase("v6-mss1220", "[2804:14c::9]:40003", 1220, 1280, 220),
	// SYN retransmitido com MSS 1200: vale o primeiro (1460)
	{name: "v4-syn-retx", cli: "8.8.4.4:40007", kind: "retx", mss: 1460, wantMSS: 1460, wantMTU: 1500, wantKind: "global"},
	// sem SYN e UDP: os três nulos
	{name: "v4-nosyn", cli: "8.8.4.4:40008", kind: "nosyn", wantKind: "global"},
	{name: "v4-udp", cli: "8.8.4.4:40009", kind: "udp", wantKind: "global"},
	{name: "v6-udp", cli: "[2804:14c::9]:40009", kind: "udp", wantKind: "global"},

	// ip.src_kind: um caso por valor da tabela da ADR 0031
	kindCase("kind-global-v4", "8.8.8.8:40100", "global"),
	kindCase("kind-global-v6", "[2804:14c::1]:40100", "global"),
	kindCase("kind-private-10", "10.1.2.3:40100", "private"),
	kindCase("kind-private-172", "172.16.0.1:40100", "private"),
	kindCase("kind-private-192", "192.168.1.1:40100", "private"),
	kindCase("kind-private-ula", "[fd00::1]:40100", "private"),
	kindCase("kind-shared", "100.64.0.1:40100", "shared"),
	kindCase("kind-loopback-v4", "127.0.0.1:40100", "loopback"),
	kindCase("kind-loopback-v6", "[::1]:40100", "loopback"),
	kindCase("kind-link-local-v4", "169.254.1.1:40100", "link_local"),
	kindCase("kind-link-local-v6", "[fe80::1]:40100", "link_local"),
	kindCase("kind-teredo", "[2001::5]:40100", "teredo"),
	kindCase("kind-6to4", "[2002:c000:204::1]:40100", "6to4"),
	kindCase("kind-nat64-wkp", "[64:ff9b::c000:201]:40100", "nat64"),
	kindCase("kind-nat64-local", "[64:ff9b:1::1]:40100", "nat64"),
	kindCase("kind-other-doc-v4", "198.51.100.10:40100", "other"),
	kindCase("kind-other-doc-v6", "[2001:db8::7]:40100", "other"),
	kindCase("kind-other-mcast-v4", "224.0.0.1:40100", "other"),
	kindCase("kind-other-mcast-v6", "[ff02::1]:40100", "other"),
	// IPv4 mapeado como origem de um pacote IPv6 não é o IPv4: other
	kindCase("kind-other-mapped", "[::ffff:8.8.8.8]:40100", "other"),
	// bordas da task 196 no registro completo
	kindCase("edge-nat64-out", "[64:ff9b:0:0:1::]:40100", "global"),
	kindCase("edge-teredo-out", "[2001:1::]:40100", "global"),
	kindCase("edge-172-15", "172.15.255.255:40100", "global"),
	kindCase("edge-172-32", "172.32.0.0:40100", "global"),
	kindCase("edge-shared-low", "100.63.255.255:40100", "global"),
	kindCase("edge-shared-high", "100.128.0.0:40100", "global"),
	kindCase("edge-link-local-out", "169.255.0.0:40100", "global"),
	kindCase("edge-6to4-out", "[2003::1]:40100", "global"),
	kindCase("edge-ula-out", "[fe00::1]:40100", "global"),
}

// synthFrames gera os frames (instante relativo em ms, frame Ethernet) de um caso.
func synthFrames(c synthCase) (cli, srv netip.AddrPort, frames []timedFrame) {
	cli = netip.MustParseAddrPort(c.cli)
	srv = synthSrv4
	if cli.Addr().Is6() {
		srv = synthSrv6
	}
	if c.kind == "udp" {
		for i, d := range []struct {
			ms      float64
			fromCli bool
			n       int
		}{{0, true, 40}, {20, false, 120}, {40, true, 40}} {
			src, dst := cli, srv
			if !d.fromCli {
				src, dst = srv, cli
			}
			f := udpFrame(src, dst, bytes.Repeat([]byte{byte(i + 1)}, d.n))
			frames = append(frames, timedFrame{d.ms, f})
		}
		return cli, srv, frames
	}
	s := newSession(1_000_000, 5_000_000, 40_000)
	switch c.kind {
	case "mss":
		s.handshake(64)
		s.segs[0].opts = mssOpts(uint16(c.mss)) //nolint:gosec // teste
	case "nomss":
		s.handshake(64)
		s.segs[0].opts = []byte{4, 2, 1, 3, 3, 7}
	case "retx":
		s.handshake(64)
		s.segs[0].opts = mssOpts(uint16(c.mss)) //nolint:gosec // teste
		re := s.segs[0]
		re.ms, re.opts = 20, mssOpts(1200)
		s.segs = append([]seg{s.segs[0], re}, s.segs[1:]...)
	case "nosyn":
		s.cliData(10, 100, 64, 7)
		s.srvData(20, 100)
	}
	if c.kind != "nosyn" {
		s.cliData(120, 100, 64, 102)
		s.srvData(150, 300)
	}
	s.fin(300, 64, 0)
	for _, sg := range s.segs {
		src, dst := cli, srv
		if !sg.fromCli {
			src, dst = srv, cli
		}
		frames = append(frames, timedFrame{sg.ms, tcpFrame(src, dst, sg)})
	}
	return cli, srv, frames
}

type timedFrame struct {
	ms    float64
	frame []byte
}

// synthPcap grava os frames num pcap Ethernet (µs, instantes a partir de base).
func synthPcap(t *testing.T, frames []timedFrame) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(65535, gplayers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		ci := gopacket.CaptureInfo{
			Timestamp: time.Unix(0, base+int64(f.ms*1e6)).UTC(), CaptureLength: len(f.frame), Length: len(f.frame),
		}
		if err := w.WritePacket(ci, f.frame); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// pcapBatchDir lê um pcap e monta o lote FSPB com o sentido de cada frame (out = origem no servidor).
func pcapBatchDir(t *testing.T, b []byte, srv netip.AddrPort) fakeMsg {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		dir := event.DirIn
		if src, ok := frameSrc(data); ok && src == srv.Addr() {
			dir = event.DirOut
		}
		out = event.AppendPacket(out, event.Packet{TsNs: ci.Timestamp.UnixNano(), Dir: dir, WireLen: uint32(ci.Length), Frame: data}) //nolint:gosec // teste
	}
	return fakeMsg{subject: event.SubjectCapturePacket, data: out}
}

// frameSrc devolve o endereço de origem de um frame Ethernet IPv4/IPv6.
func frameSrc(f []byte) (netip.Addr, bool) {
	if len(f) < 14 {
		return netip.Addr{}, false
	}
	switch {
	case f[12] == 0x08 && f[13] == 0x00 && len(f) >= 34:
		return netip.AddrFrom4([4]byte(f[26:30])), true
	case f[12] == 0x86 && f[13] == 0xdd && len(f) >= 54:
		return netip.AddrFrom16([16]byte(f[22:38])), true
	}
	return netip.Addr{}, false
}

// synthResult é o que o golden guarda de cada caso.
type synthResult struct {
	Family       int    `json:"family"`
	L4           string `json:"l4"`
	SrcKind      string `json:"src_kind"`
	SynMSS       *int   `json:"syn_mss"`
	MTUImplied   *int   `json:"mtu_implied"`
	MSSReduction *int   `json:"mss_reduction"`
	SynOptMSS    *int   `json:"syn_options_mss"` // primeiro ["mss",N] de tcp.syn.options
}

// synthRecord passa o pcap pelo store e devolve o registro gravado.
func synthRecord(t *testing.T, c synthCase, cli, srv netip.AddrPort, pcap []byte) connectionJSON {
	t.Helper()
	in, db := newTestIngestor(t, nil)
	msgs := []fakeMsg{pcapBatchDir(t, pcap, srv)}
	if c.kind == "nosyn" {
		// sem o SYN, o evento de aplicação é o que mantém o fluxo como conexão (como no capture começando no meio)
		msgs = append(msgs, appMsg(t, event.SubjectRawSession, "tcp", cli, srv, 5, "", map[string]any{"mode": "echo"}))
	}
	run(t, in, 60_000, msgs...)
	_, rec := onlyConn(t, db)
	return rec
}

func resultOf(rec connectionJSON) synthResult {
	r := synthResult{Family: rec.Family, L4: rec.L4}
	if rec.IP != nil {
		r.SrcKind = rec.IP.SrcKind
	}
	if tc := rec.TCP; tc != nil {
		r.SynMSS, r.MTUImplied, r.MSSReduction = tc.SynMSS, tc.MTUImplied, tc.MSSReduction
		if tc.Syn != nil {
			for _, o := range tc.Syn.Options {
				if len(o) == 2 && o[0] == "mss" {
					if v, ok := o[1].(float64); ok {
						n := int(v)
						r.SynOptMSS = &n
					}
					break
				}
			}
		}
	}
	return r
}

func TestSynthGolden(t *testing.T) {
	if err := os.MkdirAll(synthDir, 0o750); err != nil {
		t.Fatal(err)
	}
	got := map[string]synthResult{}
	for _, c := range synthCases {
		t.Run(c.name, func(t *testing.T) {
			cli, srv, frames := synthFrames(c)
			gen := synthPcap(t, frames)
			path := filepath.Join(synthDir, c.name+".pcap")
			if *update {
				if err := os.WriteFile(path, gen, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			disk, err := os.ReadFile(path) //nolint:gosec // testdata
			if err != nil {
				t.Fatalf("%v (rode com -update)", err)
			}
			if !bytes.Equal(disk, gen) {
				t.Fatalf("%s difere do gerador (rode com -update)", path)
			}
			rec := synthRecord(t, c, cli, srv, disk)
			r := resultOf(rec)
			got[c.name] = r
			checkSynth(t, c, cli, r)
		})
	}

	goldenPath := filepath.Join(synthDir, "mss-srckind.json")
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(goldenPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath) //nolint:gosec // testdata
	if err != nil {
		t.Fatalf("%v (rode com -update)", err)
	}
	if !bytes.Equal(want, b) {
		t.Fatalf("%s difere do resultado (rode com -update e revise o diff):\n%s", goldenPath, b)
	}
}

// checkSynth confere um caso contra a tabela da spec 013 (independente do golden).
func checkSynth(t *testing.T, c synthCase, cli netip.AddrPort, r synthResult) {
	t.Helper()
	fam := 4
	if cli.Addr().Is6() {
		fam = 6
	}
	if r.Family != fam {
		t.Errorf("family = %d, quer %d", r.Family, fam)
	}
	if r.SrcKind != c.wantKind {
		t.Errorf("ip.src_kind = %q, quer %q", r.SrcKind, c.wantKind)
	}
	if c.wantMSS == 0 {
		if r.SynMSS != nil || r.MTUImplied != nil || r.MSSReduction != nil {
			t.Errorf("syn_mss/mtu_implied/mss_reduction = %v/%v/%v, quer os três nulos",
				intOrNil(r.SynMSS), intOrNil(r.MTUImplied), intOrNil(r.MSSReduction))
		}
		wantL4 := "tcp"
		if c.kind == "udp" {
			wantL4 = "udp"
		}
		if r.L4 != wantL4 {
			t.Errorf("l4 = %q, quer %q", r.L4, wantL4)
		}
		return
	}
	if intOrNil(r.SynMSS) != c.wantMSS || intOrNil(r.MTUImplied) != c.wantMTU || intOrNil(r.MSSReduction) != c.wantRed {
		t.Errorf("syn_mss/mtu_implied/mss_reduction = %v/%v/%v, quer %d/%d/%d",
			intOrNil(r.SynMSS), intOrNil(r.MTUImplied), intOrNil(r.MSSReduction), c.wantMSS, c.wantMTU, c.wantRed)
	}
	if intOrNil(r.SynOptMSS) != intOrNil(r.SynMSS) {
		t.Errorf("syn_mss %v diferente do [\"mss\",N] de tcp.syn.options (%v)", intOrNil(r.SynMSS), intOrNil(r.SynOptMSS))
	}
}

// TestSynMSSRealPcaps: syn_mss dos pcaps reais igual ao do tshark 4.4 no mesmo arquivo:
// tshark -r <pcap> -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e tcp.options.mss_val
// O IP do cliente macOS foi trocado por 198.51.100.10 (documentação → other); os pcaps linux-* foram gravados
// do lado cliente no servidor anterior (IPs globais).
func TestSynMSSRealPcaps(t *testing.T) {
	for _, c := range []struct {
		file           string
		tsharkMSS      int
		family         int
		kind           string
		mtu, reduction int
	}{
		{"linux-https-v4.pcap", 1460, 4, "global", 1500, 0},
		{"linux-https-v6.pcap", 1440, 6, "global", 1500, 0},
		{"macos-http-finretx.pcap", 1430, 4, "other", 1470, 30},
		{"macos-http-keepalive.pcap", 1412, 4, "other", 1452, 48},
		{"macos-https-keepalive.pcap", 1412, 4, "other", 1452, 48},
		{"raw-close-rst.pcap", 1412, 4, "other", 1452, 48},
	} {
		t.Run(c.file, func(t *testing.T) {
			in, db := newTestIngestor(t, nil)
			run(t, in, 0, pcapBatch(t, filepath.Join("testdata", c.file)))
			if err := in.Finalize(t.Context(), in.flows.due(1<<62)); err != nil {
				t.Fatal(err)
			}
			_, rec := onlyConn(t, db)
			r := resultOf(rec)
			if intOrNil(r.SynMSS) != c.tsharkMSS || intOrNil(r.SynOptMSS) != c.tsharkMSS {
				t.Errorf("syn_mss = %v (options %v), tshark tcp.options.mss_val = %d", intOrNil(r.SynMSS), intOrNil(r.SynOptMSS), c.tsharkMSS)
			}
			if intOrNil(r.MTUImplied) != c.mtu || intOrNil(r.MSSReduction) != c.reduction {
				t.Errorf("mtu_implied/mss_reduction = %v/%v, quer %d/%d", intOrNil(r.MTUImplied), intOrNil(r.MSSReduction), c.mtu, c.reduction)
			}
			if r.Family != c.family || r.SrcKind != c.kind {
				t.Errorf("family/src_kind = %d/%q, quer %d/%q", r.Family, r.SrcKind, c.family, c.kind)
			}
		})
	}
}
