package store

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Vazão do ingest no mix da carga oficial (ADR 0041 item 2, task 242): sem NATS, pelo process, banco em disco
// com WAL. Mix do loadgen (h1=15, h1tls=15, h2=20, h3=20, raw-echo=10, raw-banner=12, raw-sink=8), 100 novas/s,
// vida de 3,8 s, 3 trocas por conexão; pacotes em lotes FSPB de janelas de 5 ms (FS_CAPTURE_BATCH_WAIT), cada
// evento de aplicação numa mensagem; o store busca 64 mensagens por lote, como no Run.

const (
	benchConns = 1000 // conexões por iteração (10 s de captura a 100/s)
	benchRate  = 100  // novas/s
	benchLife  = 3800 // ms
)

// benchItem é um pacote ou um evento de aplicação no instante ts (ms relativos a base).
type benchItem struct {
	ms  int
	pkt *event.Packet
	app *fakeMsg
}

// benchKinds é o ciclo do mix (100 conexões por ciclo).
func benchKinds() []string {
	var out []string
	for _, k := range []struct {
		name string
		n    int
	}{{"h1", 15}, {"h1tls", 15}, {"h2", 20}, {"h3", 20}, {"raw-echo", 10}, {"raw-banner", 12}, {"raw-sink", 8}} {
		for range k.n {
			out = append(out, k.name)
		}
	}
	return out
}

// benchWorkload monta as mensagens da carga, em ordem de chegada ao stream, e o instante (ms) de cada uma.
func benchWorkload(b testing.TB, conns int) ([]fakeMsg, []int) {
	b.Helper()
	return benchWorkloadRate(b, conns, benchRate)
}

// benchWorkloadRate é benchWorkload com rate conexões novas por segundo.
func benchWorkloadRate(b testing.TB, conns, rate int) ([]fakeMsg, []int) {
	b.Helper()
	kinds := benchKinds()
	var items []benchItem
	addPkt := func(at int, src, dst netip.AddrPort, proto, flags byte, payload int, dir uint8, data []byte) {
		var f []byte
		if data != nil {
			f = udpFrame(src, dst, data)
		} else {
			f = frame(src, dst, proto, flags, payload)
		}
		p := event.Packet{TsNs: base + int64(at)*1e6, Dir: dir, WireLen: uint32(len(f)), Frame: f} //nolint:gosec // teste
		items = append(items, benchItem{ms: at, pkt: &p})
	}
	addApp := func(at int, m fakeMsg) { items = append(items, benchItem{ms: at + 1, app: &m}) } // publicado 1 ms depois
	for i := range conns {
		kind := kinds[i%len(kinds)]
		s := i*1000/rate + i%5 // o handshake cai às vezes entre duas janelas do capture
		cli := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 40000)
		if kind == "h3" {
			srv := quicMirror
			c2s := func(at, n int) { addPkt(s+at, cli, srv, protoUDP, 0, 0, event.DirIn, quicShort(n)) }
			s2c := func(at, n int) { addPkt(s+at, srv, cli, protoUDP, 0, 0, event.DirOut, quicShort(n)) }
			addPkt(s, cli, srv, protoUDP, 0, 0, event.DirIn, quicInitial(dcidA))
			addPkt(s+1, srv, cli, protoUDP, 0, 0, event.DirOut, quicInitial([]byte{1, 2, 3, 4}))
			c2s(2, 60)
			addApp(s+3, h3Msg(b, event.SubjectWebHTTP3Connection, cli, dcidA, s+3, h3Conn("h3", true, nil)))
			for r := range 3 {
				at := 10 + r*1200
				c2s(at, 80)
				s2c(at+2, 1200)
				c2s(at+3, 30)
				addApp(s+at+2, h3Msg(b, event.SubjectWebHTTP3Request, cli, dcidA, s+at+2, h3Req(int64(4*r), "/", 200)))
			}
			cl := &event.HTTP3Close{By: "client", How: event.QUICCloseApplication, ErrorCode: ptrTo(uint64(0x100)), Reason: ptrTo("")}
			c2s(benchLife, 30)
			addApp(s+benchLife, h3Msg(b, event.SubjectWebHTTP3Connection, cli, dcidA, s+benchLife, h3Conn("h3", true, cl)))
			continue
		}
		srv := netip.AddrPortFrom(mirror.Addr(), 443)
		switch kind {
		case "h1":
			srv = netip.AddrPortFrom(mirror.Addr(), 80)
		case "raw-echo", "raw-banner", "raw-sink":
			srv = netip.AddrPortFrom(mirror.Addr(), 7700)
		}
		c2s := func(at int, fl byte, n int) { addPkt(s+at, cli, srv, protoTCP, fl, n, event.DirIn, nil) }
		s2c := func(at int, fl byte, n int) { addPkt(s+at, srv, cli, protoTCP, fl, n, event.DirOut, nil) }
		app := func(at int, subject string, payload any) {
			addApp(s+at, appMsg(b, subject, "tcp", cli, srv, s+at, probeID, payload))
		}
		c2s(0, tcpSYN, 0)
		s2c(1, tcpSYN|tcpACK, 0)
		c2s(2, tcpACK, 0)
		tls := kind == "h1tls" || kind == "h2"
		if tls {
			c2s(3, tcpACK|tcpPSH, 517)
			app(3, event.SubjectWebTLSClientHello, tlsHelloPayload(clientHelloRaw(512)))
			s2c(4, tcpACK|tcpPSH, 2800)
			c2s(5, tcpACK|tcpPSH, 80)
			app(5, event.SubjectWebTLSHandshake, handshakePayload())
		}
		for r := range 3 {
			at := 10 + r*1200
			c2s(at, tcpACK|tcpPSH, 200)
			s2c(at+2, tcpACK|tcpPSH, 1200)
			c2s(at+3, tcpACK, 0)
			switch kind {
			case "h1", "h1tls":
				app(at+2, event.SubjectWebHTTP1Request, http1Payload(r, "HTTP/1.1"))
			case "h2":
				app(at+2, event.SubjectWebHTTP2Stream, map[string]any{"stream_id": 2*r + 1, "status": 200})
			}
		}
		c2s(benchLife, tcpFIN|tcpACK, 0)
		s2c(benchLife+1, tcpFIN|tcpACK, 0)
		c2s(benchLife+2, tcpACK, 0)
		switch kind {
		case "h2":
			app(benchLife+1, event.SubjectWebHTTP2Connection, map[string]any{"mode": "alpn", "preface_ok": true, "streams": []any{}})
		case "raw-echo", "raw-banner", "raw-sink":
			app(benchLife+1, event.SubjectRawSession, map[string]any{"mode": kind[4:]})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ms < items[j].ms })
	// Lotes do capture: pacotes de cada janela de 5 ms (até 256) numa mensagem, publicada no fim da janela.
	var msgs []fakeMsg
	var at []int
	var buf []byte
	n, win := 0, -1
	flush := func() {
		if n > 0 {
			msgs = append(msgs, fakeMsg{subject: event.SubjectCapturePacket, data: buf})
			at = append(at, (win+1)*5)
			buf, n = nil, 0
		}
	}
	for _, it := range items {
		if it.pkt != nil {
			if w := it.ms / 5; w != win || n == 256 {
				flush()
				win = w
			}
			buf = event.AppendPacket(buf, *it.pkt)
			n++
			continue
		}
		msgs = append(msgs, *it.app)
		at = append(at, it.ms)
	}
	flush()
	// ordem de chegada ao stream
	idx := make([]int, len(msgs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool { return at[idx[i]] < at[idx[j]] })
	om, oa := make([]fakeMsg, len(msgs)), make([]int, len(msgs))
	for i, k := range idx {
		om[i], oa[i] = msgs[k], at[k]
	}
	return om, oa
}

func benchIngest(b *testing.B, lag time.Duration) {
	msgs, at := benchWorkload(b, benchConns)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := IngestConfig{
		PcapMax: 1 << 20, TCPIdle: 630 * time.Second, QUICIdle: 330 * time.Second, UDPIdle: 30 * time.Second,
		CloseGrace: DefaultCloseGrace, MaxOpen: 1000, MaxNewPerS: 150, Snaplen: 65535, SegmentsTracked: 32,
	}
	ctx := context.Background()
	var elapsed time.Duration
	var conns, strays int
	for range b.N {
		b.StopTimer()
		db, _ := testDB(b)
		in := NewIngestor(db, cfg, log, service.NewMetrics())
		b.StartTimer()
		start := time.Now()
		for i := 0; i < len(msgs); i += 64 {
			j := min(i+64, len(msgs))
			wall := time.Unix(0, base).Add(time.Duration(at[j-1])*time.Millisecond + lag)
			in.now = func() time.Time { return wall }
			src := make([]msgSource, j-i)
			for k := range src {
				src[k] = msgs[i+k]
			}
			if err := in.process(ctx, src); err != nil {
				b.Fatal(err)
			}
			in.afterBatch(ctx)
		}
		// fim da carga: 5 s sem tráfego fecham o que faltar pela folga
		end := time.Unix(0, base).Add(time.Duration(at[len(at)-1])*time.Millisecond + lag + 5*time.Second)
		in.now = func() time.Time { return end }
		in.afterBatch(ctx)
		elapsed += time.Since(start)
		b.StopTimer()
		_ = db.QueryRow("SELECT count(*) FROM connections").Scan(&conns)
		_ = db.QueryRow("SELECT count(*) FROM stray_packets").Scan(&strays)
		_ = db.Close()
		b.StartTimer()
	}
	sec := elapsed.Seconds()
	b.ReportMetric(float64(benchConns*b.N)/sec, "conns/s")
	b.ReportMetric(float64(len(msgs)*b.N)/sec, "msgs/s")
	b.ReportMetric(float64(conns), "records")
	b.ReportMetric(float64(strays), "strays")
}

// BenchmarkIngestOfficialMix mede conexões/s e mensagens/s num núcleo; lag=20s simula o ingest atrasado (cada
// lote processado 20 s depois da captura), que antes da ADR 0041 multiplicava o custo (avulsos e fragmentos).
func BenchmarkIngestOfficialMix(b *testing.B) {
	b.Run("lag=0", func(b *testing.B) { benchIngest(b, 0) })
	b.Run("lag=20s", func(b *testing.B) { benchIngest(b, 20*time.Second) })
}
