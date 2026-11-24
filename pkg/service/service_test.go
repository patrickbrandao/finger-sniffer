package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

func TestLoadConfigDefaults(t *testing.T) {
	for _, k := range []string{"FS_NATS_URL", "FS_LOG_LEVEL", "FS_PRODUCER_BUFFER_MAX_AGE", "FS_PRODUCER_BUFFER_MAX_BYTES", "FS_HEARTBEAT_INTERVAL", event.EnvEventInlineMax, event.EnvRawStreamMaxBytes} {
		t.Setenv(k, "")
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.NATSURL != "nats://127.0.0.1:4222" || c.LogLevel != slog.LevelInfo || c.BufferMaxAge != 30*time.Second ||
		c.BufferMaxBytes != 16<<20 || c.HeartbeatInterval != 5*time.Second || c.EventInlineMax != 128<<10 ||
		c.RawStreamMaxBytes != 16<<20 {
		t.Fatalf("%+v", c)
	}
}

func TestLoadConfigValues(t *testing.T) {
	t.Setenv("FS_NATS_URL", "nats://x:1")
	t.Setenv("FS_LOG_LEVEL", "debug")
	t.Setenv("FS_PRODUCER_BUFFER_MAX_AGE", "2s")
	t.Setenv("FS_PRODUCER_BUFFER_MAX_BYTES", "100")
	t.Setenv("FS_HEARTBEAT_INTERVAL", "1s")
	t.Setenv(event.EnvEventInlineMax, "4096")
	t.Setenv(event.EnvRawStreamMaxBytes, "0")
	c, err := LoadConfig()
	if err != nil || c.NATSURL != "nats://x:1" || c.LogLevel != slog.LevelDebug || c.BufferMaxAge != 2*time.Second ||
		c.BufferMaxBytes != 100 || c.HeartbeatInterval != time.Second || c.EventInlineMax != 4096 || c.RawStreamMaxBytes != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	for k, v := range map[string]string{
		"FS_LOG_LEVEL": "loud", "FS_PRODUCER_BUFFER_MAX_AGE": "x", "FS_PRODUCER_BUFFER_MAX_BYTES": "x", "FS_HEARTBEAT_INTERVAL": "x",
		event.EnvEventInlineMax: "500000", event.EnvRawStreamMaxBytes: "-1",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	// task 377: intervalo zero ou negativo fazia time.NewTicker entrar em pânico; buffer negativo não tem sentido.
	for _, kv := range [][2]string{
		{"FS_HEARTBEAT_INTERVAL", "0"},
		{"FS_HEARTBEAT_INTERVAL", "-5s"},
		{"FS_PRODUCER_BUFFER_MAX_AGE", "-1s"},
		{"FS_PRODUCER_BUFFER_MAX_BYTES", "-1"},
	} {
		t.Run(kv[0]+"="+kv[1], func(t *testing.T) {
			t.Setenv(kv[0], kv[1])
			if _, err := LoadConfig(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	// Zero no buffer continua valendo (descarta assim que o NATS cai).
	t.Setenv("FS_PRODUCER_BUFFER_MAX_AGE", "0s")
	t.Setenv("FS_PRODUCER_BUFFER_MAX_BYTES", "0")
	if _, err := LoadConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	m.Add("a", 2)
	m.Add("a", 3)
	m.Set("b", 7)
	if m.Get("a") != 5 || m.Get("b") != 7 || m.Get("c") != 0 {
		t.Fatalf("%v", m.Snapshot())
	}
	s := m.Snapshot()
	s["a"] = 0
	if m.Get("a") != 5 {
		t.Fatal("snapshot must be a copy")
	}
}

// fakeConn simula a conexão NATS.
type fakeConn struct {
	connected bool
	fail      bool
	sent      []string
}

func (f *fakeConn) IsConnected() bool { return f.connected }
func (f *fakeConn) PublishMsg(m *nats.Msg) error {
	if f.fail {
		return errors.New("publish failed")
	}
	f.sent = append(f.sent, string(m.Data))
	return nil
}

func msg(s string) *nats.Msg {
	return &nats.Msg{Subject: "fs.v1.x", Data: []byte(s), Header: nats.Header{"K": []string{"v"}}}
}

func TestProducerConnected(t *testing.T) {
	c := &fakeConn{connected: true}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("a"))
	if len(c.sent) != 1 || m.Get(MetricPublished) != 1 || p.Buffered() != 0 {
		t.Fatalf("sent=%v metrics=%v", c.sent, m.Snapshot())
	}
}

func TestProducerBuffersAndFlushesInOrder(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	p := NewProducer(c, time.Minute, 1<<20, m)
	p.Publish(msg("a"))
	p.Publish(msg("b"))
	c.connected = true
	// Com fila pendente, a nova mensagem não fura a fila.
	p.Publish(msg("c"))
	if len(c.sent) != 0 || p.Buffered() != 3 || m.Get(MetricBuffered) != 3 {
		t.Fatalf("sent=%v buffered=%d", c.sent, p.Buffered())
	}
	p.Flush()
	if got := c.sent; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("order: %v", got)
	}
	if p.Buffered() != 0 || m.Get(MetricBufferedSize) != 0 || m.Get(MetricPublished) != 3 {
		t.Fatalf("metrics: %v", m.Snapshot())
	}
}

func TestProducerPublishErrorBuffers(t *testing.T) {
	c := &fakeConn{connected: true, fail: true}
	p := NewProducer(c, time.Minute, 1<<20, NewMetrics())
	p.Publish(msg("a"))
	p.Flush() // continua falhando: fica no buffer
	if p.Buffered() != 1 {
		t.Fatalf("buffered=%d", p.Buffered())
	}
}

func TestProducerDropsByAge(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	p := NewProducer(c, 30*time.Second, 1<<20, m)
	now := time.Now()
	p.now = func() time.Time { return now }
	p.Publish(msg("old"))
	now = now.Add(31 * time.Second)
	p.Publish(msg("new"))
	c.connected = true
	p.Flush()
	if len(c.sent) != 1 || c.sent[0] != "new" || m.Get(MetricDropped) != 1 {
		t.Fatalf("sent=%v metrics=%v", c.sent, m.Snapshot())
	}
}

func TestProducerDropsBySize(t *testing.T) {
	c := &fakeConn{}
	m := NewMetrics()
	// Cada mensagem ocupa 7 (subject) + 2 (header) + 4 (dados) = 13 bytes.
	p := NewProducer(c, time.Minute, 30, m)
	for _, s := range []string{"aaaa", "bbbb", "cccc"} {
		p.Publish(msg(s))
	}
	if p.Buffered() != 2 || m.Get(MetricDropped) != 1 {
		t.Fatalf("buffered=%d metrics=%v", p.Buffered(), m.Snapshot())
	}
	c.connected = true
	p.Flush()
	if c.sent[0] != "bbbb" {
		t.Fatalf("oldest must be dropped first: %v", c.sent)
	}
}

func TestHeartbeatMessage(t *testing.T) {
	s := &Service{Name: event.ServiceWeb, Metrics: NewMetrics(), started: time.Unix(0, 0)}
	s.Metrics.Set("x", 1)
	now := time.Date(2026, 11, 7, 0, 0, 0, 5, time.UTC)

	check := func(wantStatus string, wantReasons int) {
		t.Helper()
		m, err := s.HeartbeatMessage(now)
		if err != nil {
			t.Fatal(err)
		}
		if m.Subject != event.SubjectHeartbeat {
			t.Fatalf("subject %q", m.Subject)
		}
		env, err := event.Decode(m.Data)
		if err != nil {
			t.Fatal(err)
		}
		var hb event.Heartbeat
		if err := json.Unmarshal(env.Payload, &hb); err != nil {
			t.Fatal(err)
		}
		if env.Service != event.ServiceWeb || hb.Status != wantStatus || len(hb.Reasons) != wantReasons || hb.Metrics["x"] != 1 ||
			env.Ts != "2026-11-07T00:00:00.000000005Z" {
			t.Fatalf("%+v %+v", env, hb)
		}
	}
	check(event.StatusOK, 0)
	s.SetStatus(func() (string, []string) { return event.StatusDegraded, []string{"offload on"} })
	check(event.StatusDegraded, 1)
}

const testPassword = "s3cr3t-0123456789abcdef"

// clearNATSAuth zera as chaves de autenticação, para o teste não herdar o ambiente de quem roda.
func clearNATSAuth(t *testing.T) {
	t.Helper()
	for _, k := range []string{"FS_NATS_USER", "FS_NATS_PASSWORD", "FS_NATS_PASSWORD_FILE"} {
		t.Setenv(k, "")
	}
}

func writePasswordFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw.password")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigNATSAuth(t *testing.T) {
	clearNATSAuth(t)
	c, err := LoadConfig()
	if err != nil || c.NATSUser != "" || c.NATSPassword != "" {
		t.Fatalf("sem usuário: %+v %v", c, err)
	}

	t.Run("direct", func(t *testing.T) {
		t.Setenv("FS_NATS_USER", "raw")
		t.Setenv("FS_NATS_PASSWORD", testPassword)
		c, err := LoadConfig()
		if err != nil || c.NATSUser != "raw" || c.NATSPassword.Reveal() != testPassword {
			t.Fatalf("%v %v", c.NATSUser, err)
		}
	})
	t.Run("file trims trailing whitespace", func(t *testing.T) {
		t.Setenv("FS_NATS_USER", "raw")
		t.Setenv("FS_NATS_PASSWORD_FILE", writePasswordFile(t, testPassword+" \r\n\n"))
		c, err := LoadConfig()
		if err != nil || c.NATSPassword.Reveal() != testPassword {
			t.Fatalf("%q %v", c.NATSPassword.Reveal(), err)
		}
	})
}

func TestLoadConfigNATSAuthErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"user without password":  {"FS_NATS_USER": "raw"},
		"user with empty file":   {"FS_NATS_USER": "raw", "FS_NATS_PASSWORD_FILE": "@empty"},
		"user with blank file":   {"FS_NATS_USER": "raw", "FS_NATS_PASSWORD_FILE": "@blank"},
		"both password and file": {"FS_NATS_USER": "raw", "FS_NATS_PASSWORD": testPassword, "FS_NATS_PASSWORD_FILE": "@secret"},
		"unreadable file":        {"FS_NATS_USER": "raw", "FS_NATS_PASSWORD_FILE": "@missing"},
		"password without user":  {"FS_NATS_PASSWORD": testPassword},
		"file without user":      {"FS_NATS_PASSWORD_FILE": "@secret"},
		"directory as file":      {"FS_NATS_USER": "raw", "FS_NATS_PASSWORD_FILE": "@dir"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			clearNATSAuth(t)
			for k, v := range env {
				switch v {
				case "@empty":
					v = writePasswordFile(t, "")
				case "@blank":
					v = writePasswordFile(t, " \n\r\n")
				case "@secret":
					v = writePasswordFile(t, testPassword)
				case "@missing":
					v = filepath.Join(t.TempDir(), "nope")
				case "@dir":
					v = t.TempDir()
				}
				t.Setenv(k, v)
			}
			_, err := LoadConfig()
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Fatalf("senha no erro: %v", err)
			}
		})
	}
}

// A senha não aparece em nenhuma formatação comum da Config.
func TestSecretRedacted(t *testing.T) {
	c := Config{NATSUser: "raw", NATSPassword: Secret(testPassword)}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "cfg", c, "pw", c.NATSPassword)
	j, _ := json.Marshal(c)
	for _, s := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(c.NATSPassword), string(j), buf.String()} {
		if strings.Contains(s, testPassword) {
			t.Fatalf("senha exposta: %s", s)
		}
	}
}

// authServer sobe um NATS embutido que exige usuário e senha.
func authServer(t *testing.T) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true,
		Users: []*server.User{{Username: "raw", Password: testPassword}},
	})
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

// syncBuffer é um io.Writer seguro para o log escrito por goroutines do cliente NATS.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := logOutput
	logOutput = buf
	t.Cleanup(func() { logOutput = prev })
	return buf
}

// Com as credenciais (direta e por arquivo), o serviço conecta e publica no NATS com autenticação.
func TestNewWithNATSAuth(t *testing.T) {
	ns := authServer(t)
	for name, set := range map[string]func(t *testing.T){
		"direct": func(t *testing.T) { t.Setenv("FS_NATS_PASSWORD", testPassword) },
		"file":   func(t *testing.T) { t.Setenv("FS_NATS_PASSWORD_FILE", writePasswordFile(t, testPassword+"\n")) },
	} {
		t.Run(name, func(t *testing.T) {
			clearNATSAuth(t)
			captureLog(t)
			t.Setenv("FS_NATS_URL", ns.ClientURL())
			t.Setenv("FS_NATS_USER", "raw")
			set(t)

			obs, err := nats.Connect(ns.ClientURL(), nats.UserInfo("raw", testPassword))
			if err != nil {
				t.Fatal(err)
			}
			defer obs.Close()
			sub, err := obs.SubscribeSync(event.SubjectHeartbeat)
			if err != nil {
				t.Fatal(err)
			}
			_ = obs.Flush()

			svc, err := New(event.ServiceRaw)
			if err != nil {
				t.Fatal(err)
			}
			defer svc.NC.Close()
			msg, err := svc.HeartbeatMessage(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.NC.PublishMsg(msg); err != nil {
				t.Fatal(err)
			}
			if _, err := sub.NextMsg(5 * time.Second); err != nil {
				t.Fatalf("heartbeat não chegou: %v", err)
			}
		})
	}
}

// Sem credencial ou com senha errada, o NATS recusa; a recusa vai para o log com o usuário e sem a senha.
func TestNATSAuthRefused(t *testing.T) {
	ns := authServer(t)
	if _, err := nats.Connect(ns.ClientURL()); err == nil {
		t.Fatal("conexão sem credencial aceita")
	}
	if _, err := nats.Connect(ns.ClientURL(), nats.UserInfo("raw", "wrong")); err == nil {
		t.Fatal("senha errada aceita")
	}

	for name, user := range map[string]string{"no credentials": "", "wrong password": "raw"} {
		t.Run(name, func(t *testing.T) {
			clearNATSAuth(t)
			logs := captureLog(t)
			t.Setenv("FS_NATS_URL", ns.ClientURL())
			t.Setenv("FS_NATS_USER", user)
			if user != "" {
				t.Setenv("FS_NATS_PASSWORD", "wrong-"+testPassword)
			}
			svc, err := New(event.ServiceRaw)
			if err != nil {
				t.Fatal(err)
			}
			defer svc.NC.Close()
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(logs.String(), "nats authorization failed") && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			out := logs.String()
			if !strings.Contains(out, "nats authorization failed") {
				t.Fatalf("recusa fora do log: %s", out)
			}
			if svc.NC.IsConnected() {
				t.Fatal("conectado sem credencial válida")
			}
			if user != "" && !strings.Contains(out, `"nats_user":"raw"`) {
				t.Fatalf("usuário fora do log: %s", out)
			}
			if strings.Contains(out, testPassword) {
				t.Fatalf("senha no log: %s", out)
			}
			// Segue tentando: a conexão não foi fechada de vez pela recusa repetida.
			time.Sleep(2500 * time.Millisecond)
			if svc.NC.IsClosed() {
				t.Fatal("conexão fechada depois de recusas repetidas")
			}
		})
	}
}
