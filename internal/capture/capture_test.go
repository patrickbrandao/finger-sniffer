package capture

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

func TestBatcher(t *testing.T) {
	b := NewBatcher(3, 5*time.Millisecond, "eth0")
	if b.Take() != nil {
		t.Fatal("empty batch must return nil")
	}
	now := time.Now()
	frame := []byte{1, 2, 3}
	if b.Add(event.Packet{TsNs: 1, Frame: frame}, now) {
		t.Fatal("not full yet")
	}
	frame[0] = 9 // o lote precisa ter copiado o frame
	if b.Due(now.Add(time.Millisecond)) || !b.Due(now.Add(5*time.Millisecond)) {
		t.Fatal("due logic")
	}
	b.Add(event.Packet{TsNs: 2, Dir: event.DirOut, Frame: []byte{4}}, now)
	if !b.Add(event.Packet{TsNs: 3, Frame: nil}, now) || b.Len() != 3 {
		t.Fatal("must be full at 3")
	}
	msg := b.Take()
	if msg.Subject != event.SubjectCapturePacket || msg.Header.Get(event.HeaderFormat) != event.FSPBFormat ||
		msg.Header.Get(event.HeaderCount) != "3" || msg.Header.Get(event.HeaderService) != event.ServiceCapture ||
		msg.Header.Get(event.HeaderIface) != "eth0" || msg.Header.Get(event.HeaderSchemaVersion) != strconv.Itoa(event.SchemaVersion) {
		t.Fatalf("headers %v", msg.Header)
	}
	var got []event.Packet
	if _, err := event.DecodePackets(msg.Data, func(p event.Packet) error { got = append(got, p); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Frame[0] != 1 || got[1].Dir != event.DirOut {
		t.Fatalf("%+v", got)
	}
	if b.Len() != 0 || b.Due(now.Add(time.Hour)) {
		t.Fatal("batch must be empty after Take")
	}
}

func TestParseFrameAndClassifier(t *testing.T) {
	local := netip.MustParseAddr("172.233.24.85")
	c := &classifier{local: map[netip.Addr]bool{local: true}, excluded: toSetTest(48022), mtu: 1500}

	in := parseFrame(buildFrame(frameOpt{proto: 6, sport: 41234, dport: 443}))
	if !in.ok || !in.ports || in.sport != 41234 || in.dport != 443 || in.dst != local || c.direction(in) != event.DirIn {
		t.Fatalf("%+v", in)
	}
	out := parseFrame(buildFrame(frameOpt{proto: 6, src: local.AsSlice(), dst: []byte{192, 0, 2, 1}, sport: 443, dport: 41234}))
	if c.direction(out) != event.DirOut {
		t.Fatal("must be out")
	}
	if !c.excludedPort(parseFrame(buildFrame(frameOpt{proto: 6, sport: 48022, dport: 1}))) {
		t.Fatal("48022 must be excluded")
	}
	v6 := parseFrame(buildFrame(frameOpt{vlan: true, v6: true, proto: 17, sport: 1, dport: 53}))
	if !v6.ok || v6.dport != 53 || !v6.src.Is6() {
		t.Fatalf("%+v", v6)
	}
	frag := parseFrame(buildFrame(frameOpt{proto: 6, fragOff: 1, sport: 48022, dport: 1}))
	if !frag.ok || frag.ports || c.excludedPort(frag) {
		t.Fatalf("fragment must have no ports: %+v", frag)
	}
	icmp := parseFrame(buildFrame(frameOpt{proto: 1}))
	if !icmp.ok || icmp.ports {
		t.Fatalf("%+v", icmp)
	}
	for _, bad := range [][]byte{nil, make([]byte, 13), buildFrame(frameOpt{proto: 6})[:20]} {
		if parseFrame(bad).ok {
			t.Fatalf("short frame accepted: %d", len(bad))
		}
	}
	arp := buildFrame(frameOpt{})
	arp[12], arp[13] = 0x08, 0x06
	if fr := parseFrame(arp); fr.ok || c.direction(fr) != event.DirIn {
		t.Fatal("arp: not ok, direction in")
	}
	vlanShort := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x00, 0}
	if parseFrame(vlanShort).ok {
		t.Fatal("short vlan")
	}
	badIHL := buildFrame(frameOpt{proto: 6})
	badIHL[14] = 0x41
	if parseFrame(badIHL).ok {
		t.Fatal("ihl < 5 must fail")
	}
	if parseFrame(buildFrame(frameOpt{v6: true, proto: 6})[:40]).ok {
		t.Fatal("short v6")
	}

	if f := c.flags(1514, 1514); f != 0 {
		t.Fatalf("flags %d", f)
	}
	if f := c.flags(9000, 1514); f != event.FlagOffloadSuspect|event.FlagTruncated || !c.oversize(9000) || c.oversize(1518) {
		t.Fatalf("flags %d", f)
	}
}

// Com offload de agregação ligado, todo pacote sai com offload_suspect, mesmo os pequenos (spec 003 RF-06).
func TestFlagsAggregating(t *testing.T) {
	h := NewHealth("eth0", filepath.Join(t.TempDir(), "none.json"))
	features := "generic-receive-offload: on\n"
	h.features = func(context.Context, string) (string, error) { return features, nil }
	c := &classifier{mtu: 1500, aggregating: h.Aggregating}
	if c.flags(60, 60) != 0 {
		t.Fatal("before the first refresh: no flag")
	}
	if on, err := h.Refresh(); err != nil || len(on) != 1 {
		t.Fatalf("%v %v", on, err)
	}
	for _, n := range []int{60, 1514, 64000} {
		if c.flags(n, n)&event.FlagOffloadSuspect == 0 {
			t.Fatalf("frame %d without offload_suspect", n)
		}
	}
	features = "generic-receive-offload: off\n"
	if st, _ := h.Status(); st != event.StatusOK || c.flags(60, 60) != 0 {
		t.Fatal("offload off again: no flag")
	}
	// Sem leitura possível, fica o último estado conhecido.
	features = "generic-receive-offload: on\n"
	_, _ = h.Refresh()
	h.features = func(context.Context, string) (string, error) { return "", errors.New("no ethtool") }
	if _, err := h.Refresh(); err == nil || !h.Aggregating() {
		t.Fatal("must keep the last known state")
	}
}

// IPv6 com cabeçalhos de extensão: portas achadas depois deles e conferidas pelo excludedPort (spec 003 RF-02).
func TestParseFrameIPv6Ext(t *testing.T) {
	c := &classifier{excluded: toSetTest(9001)}
	for _, tt := range []struct {
		name     string
		o        frameOpt
		ports    bool
		excluded bool
	}{
		{"hbh 9001", frameOpt{v6: true, v6ext: []byte{ipv6HopByHop}, proto: 6, sport: 1, dport: 9001}, true, true},
		{"vlan dst+frag+ah udp", frameOpt{vlan: true, v6: true, v6ext: []byte{60, 44, 51}, proto: 17, sport: 9001, dport: 1}, true, true},
		{"seven ext", frameOpt{v6: true, v6ext: []byte{0, 60, 43, 44, 51, 60, 60}, proto: 6, sport: 1, dport: 9001}, true, true},
		{"non-first fragment", frameOpt{v6: true, v6ext: []byte{44}, v6fragOff: 2, proto: 6, sport: 1, dport: 9001}, false, false},
		{"icmp6 after hbh", frameOpt{v6: true, v6ext: []byte{0}, proto: 58}, false, false},
		{"hbh 443", frameOpt{v6: true, v6ext: []byte{0}, proto: 6, sport: 1, dport: 443}, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fr := parseFrame(buildFrame(tt.o))
			if !fr.ok || fr.ports != tt.ports || c.excludedPort(fr) != tt.excluded {
				t.Fatalf("%+v", fr)
			}
		})
	}
	// Extensão truncada ou cadeia longa demais: sem portas.
	f := buildFrame(frameOpt{v6: true, v6ext: []byte{0}, proto: 6, sport: 1, dport: 9001})
	if fr := parseFrame(f[:14+40+6]); !fr.ok || fr.ports {
		t.Fatalf("truncated ext: %+v", fr)
	}
	if fr := parseFrame(f[:14+40+10]); !fr.ok || fr.ports {
		t.Fatalf("truncated ext body: %+v", fr)
	}
	if fr := parseFrame(buildFrame(frameOpt{v6: true, v6ext: []byte{44}, proto: 6})[:14+40+4]); fr.ports {
		t.Fatalf("truncated fragment: %+v", fr)
	}
	long := make([]byte, 17)
	if fr := parseFrame(buildFrame(frameOpt{v6: true, v6ext: long, proto: 6, sport: 1, dport: 9001})); fr.ports {
		t.Fatalf("17 hop-by-hop: %+v", fr)
	}
}

// Frames de 64 KiB (agregação ligada) nunca geram lote acima do teto em bytes (spec 003 RF-04, max_payload 1 MB).
func TestBatcherMaxBytes(t *testing.T) {
	b := NewBatcher(256, time.Hour, "eth0")
	now := time.Now()
	frame := make([]byte, 64<<10)
	var msgs int
	publish := func() {
		if msg := b.Take(); msg != nil {
			msgs++
			size := len(msg.Data)
			for k, v := range msg.Header {
				size += len(k) + len(v[0]) + 4
			}
			if len(msg.Data) > BatchMaxBytes || size > 1<<20 {
				t.Fatalf("batch of %d bytes (%d with headers)", len(msg.Data), size)
			}
		}
	}
	for range 1000 {
		p := event.Packet{Frame: frame, WireLen: uint32(len(frame))}
		if !b.Fits(p) {
			publish()
		}
		if b.Add(p, now) {
			publish()
		}
	}
	publish()
	if msgs < 1000/14 {
		t.Fatalf("only %d batches", msgs)
	}
	// Pacotes pequenos continuam fechando por contagem.
	for i := range 256 {
		if full := b.Add(event.Packet{Frame: make([]byte, 60)}, now); full != (i == 255) {
			t.Fatalf("full=%v at %d", full, i)
		}
	}
	// Um pacote gigante sozinho cabe no lote vazio.
	_ = b.Take()
	if !b.Fits(event.Packet{Frame: make([]byte, maxSnap)}) {
		t.Fatal("empty batch must accept any packet")
	}
}

func TestInitMetrics(t *testing.T) {
	m := service.NewMetrics()
	m.Add("capture_batches_total", 7)
	initMetrics(m)
	snap := m.Snapshot()
	for _, name := range []string{"dropped_events_total", "capture_kernel_drops_total", "capture_packets_in_total", "capture_packets_out_total"} {
		if v, ok := snap[name]; !ok || v != 0 {
			t.Fatalf("%s=%v (%v)", name, v, ok)
		}
	}
	if snap["capture_batches_total"] != 7 {
		t.Fatal("existing value must be kept")
	}
}

func toSetTest(ports ...uint16) map[uint16]bool { return toSet(ports) }

func TestLoadConfig(t *testing.T) {
	for _, k := range []string{"FS_CAPTURE_IFACE", "FS_CAPTURE_SNAPLEN", "FS_CAPTURE_BATCH_MAX", "FS_CAPTURE_BATCH_WAIT", "FS_CAPTURE_BLOCK_TIMEOUT", "FS_CAPTURE_EXCLUDE_PORTS"} {
		t.Setenv(k, "")
	}
	c, err := LoadConfig()
	if err != nil || c.Iface != "eth0" || c.Snaplen != 65535 || c.BatchMax != 256 || c.BatchWait != 5*time.Millisecond ||
		c.BlockTimeout != 10*time.Millisecond || len(c.Exclude) != 4 {
		t.Fatalf("%+v %v", c, err)
	}
	for k, v := range map[string]string{
		"FS_CAPTURE_SNAPLEN": "x", "FS_CAPTURE_BATCH_MAX": "x", "FS_CAPTURE_BATCH_WAIT": "x",
		"FS_CAPTURE_BLOCK_TIMEOUT": "x", "FS_CAPTURE_EXCLUDE_PORTS": "22,abc",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	for _, v := range []string{"0", "63", "262145"} {
		t.Setenv("FS_CAPTURE_SNAPLEN", v)
		if _, err := LoadConfig(); err == nil {
			t.Fatalf("snaplen %s accepted", v)
		}
	}
	t.Setenv("FS_CAPTURE_SNAPLEN", "128")
	if c, err := LoadConfig(); err != nil || c.Snaplen != 128 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestParsePorts(t *testing.T) {
	p, err := ParsePorts(" 1, 65535 ,,")
	if err != nil || len(p) != 2 || p[1] != 65535 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"0", "65536", "-1"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestHealth(t *testing.T) {
	dir := t.TempDir()
	ns := filepath.Join(dir, "net-status.json")
	h := NewHealth("eth0", ns)
	features := "generic-receive-offload: off\nrx-gro-hw: off\nlarge-receive-offload: off [fixed]\n"
	h.features = func(context.Context, string) (string, error) { return features, nil }

	if st, r := h.Status(); st != event.StatusOK || r != nil {
		t.Fatalf("%s %v", st, r)
	}
	features = "generic-receive-offload: on\nrx-gro-hw: on [requested off]\n"
	if st, r := h.Status(); st != event.StatusDegraded || !strings.Contains(r[0], "generic-receive-offload,rx-gro-hw") {
		t.Fatalf("%s %v", st, r)
	}
	features = "generic-receive-offload: off\n"

	// Perdas e frames suspeitos contam uma vez, no heartbeat seguinte.
	h.ObserveDrops(5)
	h.ObserveSuspect(2)
	if st, r := h.Status(); st != event.StatusDegraded || len(r) != 2 {
		t.Fatalf("%s %v", st, r)
	}
	h.ObserveDrops(5)
	if st, _ := h.Status(); st != event.StatusOK {
		t.Fatal("no new drops: must be ok")
	}

	// Sem ethtool: cai para o arquivo da unit de rede.
	h.features = func(context.Context, string) (string, error) { return "", errors.New("no ethtool") }
	if _, r := h.Status(); len(r) != 1 || r[0] != "offload state unavailable" {
		t.Fatalf("%v", r)
	}
	_ = os.WriteFile(ns, []byte(`{"offloads":{"rx-gro-hw":"on","tcp-segmentation-offload":"on"}}`), 0o600)
	if _, r := h.Status(); len(r) != 1 || !strings.Contains(r[0], "rx-gro-hw") {
		t.Fatalf("%v", r)
	}
	_ = os.WriteFile(ns, []byte(`{`), 0o600)
	if _, r := h.Status(); r[0] != "net status invalid" {
		t.Fatalf("%v", r)
	}
	_ = os.WriteFile(ns, []byte(`{"offloads":{"rx-gro-hw":"off"}}`), 0o600)
	if st, _ := h.Status(); st != event.StatusOK {
		t.Fatal("file says off: ok")
	}
}

func TestEthtoolFeatures(t *testing.T) {
	// Sem ethtool (Mac) ou com interface inexistente: erro, nunca pânico.
	if _, err := ethtoolFeatures(context.Background(), "nonexistent0"); err == nil {
		t.Skip("ethtool answered for a nonexistent interface")
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(buildFrame(frameOpt{proto: 6, sport: 1, dport: 2}))
	f.Add(buildFrame(frameOpt{vlan: true, v6: true, proto: 17, sport: 1, dport: 2}))
	f.Add(buildFrame(frameOpt{v6: true, v6ext: []byte{0, 43, 44, 51, 60}, proto: 6, sport: 1, dport: 2}))
	f.Fuzz(func(t *testing.T, b []byte) { _ = parseFrame(b) })
}
