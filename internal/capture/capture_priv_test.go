//go:build linux && linux_priv

package capture

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestCaptureLive roda na vps602 como root (verify-full): captura de verdade na eth0, publica num NATS embutido
// e confere direção, tráfego gerado e que a porta de gerência (a sessão ssh deste teste) não aparece.
func TestCaptureLive(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	defer ns.Shutdown()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")

	sub, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	var mu sync.Mutex
	var pkts []event.Packet
	var batches int
	if _, err := sub.Subscribe(event.SubjectCapturePacket, func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		batches++
		_, err := event.DecodePackets(m.Data, func(p event.Packet) error {
			p.Frame = append([]byte(nil), p.Frame...)
			pkts = append(pkts, p)
			return nil
		})
		if err != nil {
			t.Errorf("decode: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	_ = sub.Flush()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(event.ServiceCapture)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, svc, cfg) }()

	time.Sleep(500 * time.Millisecond)
	// Tráfego que passa pela eth0: TCP de saída para um host externo e ping para o gateway.
	if c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second); err == nil {
		_ = c.Close()
	} else {
		t.Logf("dial 1.1.1.1:443: %v", err)
	}
	if out, err := exec.Command("sh", "-c", "ip route show default | awk '{print $3; exit}'").Output(); err == nil {
		_ = exec.Command("ping", "-c", "3", "-i", "0.2", strings.TrimSpace(string(out))).Run()
	}
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if batches == 0 || len(pkts) == 0 {
		t.Fatalf("no packets captured (batches=%d)", batches)
	}
	var in, out, tcp443, icmp int
	for _, p := range pkts {
		fr := parseFrame(p.Frame)
		if fr.ports && (fr.sport == 48022 || fr.dport == 48022 || fr.sport == 9001 || fr.dport == 9001) {
			t.Fatalf("excluded port captured: %+v", fr)
		}
		if p.Dir == event.DirIn {
			in++
		} else {
			out++
		}
		if fr.ports && (fr.dport == 443 || fr.sport == 443) {
			tcp443++
		}
		if !fr.ports && fr.ok {
			icmp++
		}
		if p.WireLen > 1514+4 {
			t.Errorf("frame of %d bytes: offload not disabled?", p.WireLen)
		}
	}
	t.Logf("pacotes=%d lotes=%d in=%d out=%d tcp443=%d sem_portas=%d filtrados_userspace=%v drops=%v",
		len(pkts), batches, in, out, tcp443, icmp, svc.Metrics.Get("capture_filtered_userspace_total"), svc.Metrics.Get("capture_kernel_drops_total"))
	if in == 0 || out == 0 {
		t.Fatalf("both directions expected: in=%d out=%d", in, out)
	}
	if tcp443 == 0 && icmp == 0 {
		t.Fatal("generated traffic not seen")
	}
}
