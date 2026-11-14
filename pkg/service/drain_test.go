package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Subject e quantidade usados pelos testes de encerramento.
const (
	drainSubject = "fs.test.drain"
	drainCount   = 1000
)

// startNATS sobe um NATS embutido em porta aleatória para o teste.
func startNATS(t *testing.T) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	t.Cleanup(ns.Shutdown)
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	return ns
}

// publishAndReturn é o main dos testes: publica drainCount mensagens pelo Producer e retorna na hora.
func publishAndReturn(svc *Service) func(context.Context) error {
	return func(context.Context) error {
		for i := range drainCount {
			svc.Producer.Publish(&nats.Msg{Subject: drainSubject, Data: []byte(strconv.Itoa(i))})
		}
		return nil
	}
}

// TestDrainHelperProcess é o processo filho de TestRunDeliversBeforeExit: roda Run e sai do processo logo em
// seguida, como o main dos binários. Fora desse papel não faz nada.
func TestDrainHelperProcess(t *testing.T) {
	if os.Getenv("FS_TEST_DRAIN_CHILD") != "1" {
		t.Skip("helper process")
	}
	svc, err := New(event.ServiceRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// Espera a conexão inicial (assíncrona) para que as publicações não caiam só no buffer do Producer.
	if !waitConnected(svc.NC, 5*time.Second) {
		fmt.Fprintln(os.Stderr, "not connected")
		os.Exit(2)
	}
	_ = svc.Run(publishAndReturn(svc))
	os.Exit(0)
}

// TestRunDeliversBeforeExit confere, num processo de verdade que sai logo depois de Run, que todas as mensagens
// publicadas como última ação de main chegam a um assinante externo (task 190). O filho roda com GOMAXPROCS=1.
func TestRunDeliversBeforeExit(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess")
	}
	ns := startNATS(t)
	obs, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer obs.Close()
	sub, err := obs.SubscribeSync(drainSubject)
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.SetPendingLimits(-1, -1); err != nil {
		t.Fatal(err)
	}
	if err := obs.Flush(); err != nil {
		t.Fatal(err)
	}

	for run := range 5 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDrainHelperProcess$")
		cmd.Env = append(os.Environ(), "FS_TEST_DRAIN_CHILD=1", "GOMAXPROCS=1",
			"FS_NATS_URL="+ns.ClientURL(), "FS_LOG_LEVEL=error", "FS_HEARTBEAT_INTERVAL=1h")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		got := 0
		for {
			if _, err := sub.NextMsg(500 * time.Millisecond); err != nil {
				break
			}
			got++
		}
		if got != drainCount {
			t.Fatalf("run %d: subscriber got %d of %d messages", run, got, drainCount)
		}
	}
}

// TestRunWaitsForDrain confere que Run só retorna com a conexão NATS já fechada (drain concluído).
func TestRunWaitsForDrain(t *testing.T) {
	ns := startNATS(t)
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	t.Setenv("FS_HEARTBEAT_INTERVAL", "1h")
	svc, err := New(event.ServiceRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !waitConnected(svc.NC, 5*time.Second) {
		t.Fatal("not connected")
	}
	start := time.Now()
	if err := svc.Run(publishAndReturn(svc)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > drainTimeout {
		t.Fatalf("Run took %v", d)
	}
	if !svc.NC.IsClosed() {
		t.Fatal("Run returned before the NATS connection closed")
	}
}

// TestRunWithNATSDown confere que, com o NATS fora do ar, Run retorna dentro do tempo máximo em vez de travar.
func TestRunWithNATSDown(t *testing.T) {
	ns := startNATS(t)
	t.Setenv("FS_NATS_URL", ns.ClientURL())
	t.Setenv("FS_LOG_LEVEL", "error")
	t.Setenv("FS_HEARTBEAT_INTERVAL", "1h")
	svc, err := New(event.ServiceRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !waitConnected(svc.NC, 5*time.Second) {
		t.Fatal("not connected")
	}
	ns.Shutdown()
	ns.WaitForShutdown()
	start := time.Now()
	if err := svc.Run(publishAndReturn(svc)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > drainTimeout+time.Second {
		t.Fatalf("Run took %v with NATS down", d)
	}
	if !svc.NC.IsClosed() {
		t.Fatal("connection not closed")
	}
}

func waitConnected(nc *nats.Conn, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if nc.IsConnected() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
