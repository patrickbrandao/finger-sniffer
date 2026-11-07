package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// startNATS sobe um nats-server com JetStream na porta dada (0 = livre).
func startNATS(t *testing.T, port int) *server.Server {
	t.Helper()
	if port == 0 {
		port = server.RANDOM_PORT
	}
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: port, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	return ns
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func eventually(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(msg)
}

func getHealth(t *testing.T, url string) (Health, error) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx,gosec // teste
	if err != nil {
		return Health{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var h Health
	return h, json.NewDecoder(resp.Body).Decode(&h)
}

// TestIntegrationHealth: store + 4 serviços reais via NATS; todos ok; parar um vira down; stream em memória.
func TestIntegrationHealth(t *testing.T) {
	ns := startNATS(t, 0)
	defer ns.Shutdown()
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_HEARTBEAT_INTERVAL", "100ms")
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
		DownAfter: 600 * time.Millisecond, Host: hostFixture(t, false), RetentionDur: 10 * time.Minute,
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
	go func() { _ = heartbeatsOnly(ctx, storeSvc) }()

	stops := map[string]context.CancelFunc{}
	for _, name := range []string{event.ServiceCapture, event.ServiceWeb, event.ServiceRaw, event.ServiceDNS} {
		svc, err := service.New(name)
		if err != nil {
			t.Fatal(err)
		}
		c, stop := context.WithCancel(ctx)
		stops[name] = stop
		go func() { _ = heartbeatsOnly(c, svc) }()
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", port)
	eventually(t, 5*time.Second, func() bool {
		h, err := getHealth(t, url)
		return err == nil && h.OK && len(h.Services) == 5
	}, "all services never became ok")

	// Stream criado em memória (ADR 0016).
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	eventually(t, 5*time.Second, func() bool {
		s, err := js.Stream(ctx, StreamName)
		if err != nil {
			return false
		}
		info, err := s.Info(ctx)
		return err == nil && info.Config.Storage == jetstream.MemoryStorage && info.Config.MaxBytes == streamMaxMem
	}, "stream FS_EVENTS not created in memory")

	// Ingest ponta a ponta: um lote FSPB publicado no JetStream vira conexão com pcap.
	msg := batch(client, mirror, protoTCP, fullTCP)
	shift := time.Now().UnixNano() - base // tempos atuais, para a folga de fechamento vencer
	var buf []byte
	_, _ = event.DecodePackets(msg.data, func(p event.Packet) error {
		p.TsNs += shift
		buf = event.AppendPacket(buf, p)
		return nil
	})
	if _, err := js.Publish(ctx, event.SubjectCapturePacket, buf); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, func() bool {
		var n int
		_ = st.db.QueryRow("SELECT count(*) FROM connections c JOIN pcaps p USING (conn_id) WHERE c.ended_ns IS NOT NULL").Scan(&n)
		return n == 1
	}, "published batch never became a finished connection with pcap")

	// Parar o web: vira down depois de DownAfter, e ok fica false.
	stops[event.ServiceWeb]()
	eventually(t, 5*time.Second, func() bool {
		h, err := getHealth(t, url)
		return err == nil && !h.OK && h.Services[event.ServiceWeb].Status == event.StatusDown
	}, "web never went down")
}

// heartbeatsOnly publica heartbeats no intervalo da configuração até ctx terminar (como Service.Run, sem sinais).
func heartbeatsOnly(ctx context.Context, svc *service.Service) error {
	tick := time.NewTicker(svc.Config.HeartbeatInterval)
	defer tick.Stop()
	for {
		msg, err := svc.HeartbeatMessage(time.Now())
		if err != nil {
			return err
		}
		svc.Producer.Publish(msg)
		svc.Producer.Flush()
		select {
		case <-ctx.Done():
			svc.NC.Close()
			return nil
		case <-tick.C:
		}
	}
}

// TestIntegrationProducerBuffer: com o NATS fora, o produtor guarda; quando ele volta, entrega na ordem.
func TestIntegrationProducerBuffer(t *testing.T) {
	port := freePort(t)
	ns := startNATS(t, port)
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	svc, err := service.New(event.ServiceWeb)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.NC.Close()

	ns.Shutdown()
	eventually(t, 5*time.Second, func() bool { return !svc.NC.IsConnected() }, "client still connected")
	for i := range 3 {
		svc.Producer.Publish(&nats.Msg{Subject: "fs.v1.test", Data: []byte{byte('a' + i)}})
	}
	if svc.Producer.Buffered() != 3 {
		t.Fatalf("buffered=%d", svc.Producer.Buffered())
	}

	ns2 := startNATS(t, port)
	defer ns2.Shutdown()
	sub, err := nats.Connect(ns2.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	got := make(chan string, 3)
	if _, err := sub.Subscribe("fs.v1.test", func(m *nats.Msg) { got <- string(m.Data) }); err != nil {
		t.Fatal(err)
	}
	_ = sub.Flush()
	eventually(t, 10*time.Second, func() bool { svc.Producer.Flush(); return svc.NC.IsConnected() && svc.Producer.Buffered() == 0 }, "buffer never flushed")
	for _, want := range []string{"a", "b", "c"} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("got %q want %q", g, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("missing %q", want)
		}
	}
	if svc.Metrics.Get(service.MetricDropped) != 0 {
		t.Fatal("nothing should be dropped")
	}
}
