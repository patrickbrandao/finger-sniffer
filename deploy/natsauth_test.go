package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/patrickbrandao/finger-sniffer/internal/store"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// natsUsers são os usuários do NATS, um por serviço (ADR 0075 item 1.1).
var natsUsers = []string{"capture", "web", "raw", "dns", "store", "bot"}

// natsAuth é um nats-server embutido com o nats.conf do repositório e um auth.conf gerado pelas mesmas funções do
// deploy (ensure_nats_passwords e render_nats_auth do install-lib.sh), no layout do servidor: o include relativo
// "../../etc/nats/auth.conf" sai de <raiz>/eventbus/nats/ e chega em <raiz>/etc/nats/.
type natsAuth struct {
	url  string
	conf string            // caminho do nats.conf copiado
	pw   map[string]string // senha de cada usuário
	opts *server.Options
}

func startAuthNATS(t *testing.T) *natsAuth {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash ausente")
	}
	root := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "eventbus", "nats", "nats.conf"))
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "eventbus", "nats", "nats.conf")
	putFile(t, conf, string(src))
	etc := filepath.Join(root, "etc", "nats")
	out, err := exec.Command("bash", "-c",
		`set -euo pipefail; . ./install-lib.sh; ensure_nats_passwords "$1" >/dev/null; render_nats_auth "$1" >"$1/auth.conf"`,
		"x", etc).CombinedOutput()
	if err != nil {
		t.Fatalf("gerar auth.conf: %v\n%s", err, out)
	}
	a := &natsAuth{conf: conf, pw: map[string]string{}}
	for _, u := range natsUsers {
		b, err := os.ReadFile(filepath.Join(etc, u+".password"))
		if err != nil {
			t.Fatal(err)
		}
		a.pw[u] = strings.TrimSpace(string(b))
	}
	opts, err := server.ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("nats.conf: %v", err)
	}
	a.opts = opts
	// mesma configuração, com porta livre e JetStream num diretório do teste
	run := *opts
	run.Port = server.RANDOM_PORT
	run.StoreDir = t.TempDir()
	run.NoLog, run.NoSigs = true, true
	ns, err := server.NewServer(&run)
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server não ficou pronto")
	}
	t.Cleanup(ns.Shutdown)
	a.url = ns.ClientURL()
	return a
}

// natsClient é uma conexão autenticada que guarda os erros assíncronos (violações de permissão).
type natsClient struct {
	nc   *nats.Conn
	mu   sync.Mutex
	errs []string
}

func (a *natsAuth) connect(t *testing.T, user string) *natsClient {
	t.Helper()
	c := &natsClient{}
	nc, err := nats.Connect(a.url, nats.UserInfo(user, a.pw[user]),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			c.mu.Lock()
			c.errs = append(c.errs, err.Error())
			c.mu.Unlock()
		}))
	if err != nil {
		t.Fatalf("%s: %v", user, err)
	}
	t.Cleanup(nc.Close)
	c.nc = nc
	return c
}

// waitDenied espera a violação de permissão do servidor para o subject (publish ou subscribe).
func (c *natsClient) waitDenied(t *testing.T, op, subject string) {
	t.Helper()
	want := strings.ToLower("permissions violation for " + op + ` to "` + subject + `"`)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.errs {
			if strings.Contains(strings.ToLower(e), want) {
				c.mu.Unlock()
				return
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("sem violação de permissão para %s %s; erros: %v", op, subject, c.errors())
}

func (c *natsClient) errors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.errs)
}

// noErrors confere, depois de um flush, que o servidor não recusou nada da conexão.
func (c *natsClient) noErrors(t *testing.T, user string) {
	t.Helper()
	if err := c.nc.Flush(); err != nil {
		t.Errorf("%s: flush: %v", user, err)
	}
	time.Sleep(50 * time.Millisecond)
	if e := c.errors(); len(e) > 0 {
		t.Errorf("%s: erros do servidor: %v", user, e)
	}
}

// ADR 0075 item 1 (task 353): o nats.conf tem authorization com os 6 usuários, cada um com a senha da variável do
// auth.conf incluído (o nats-server fixado resolve variável definida no arquivo incluído); sem usuário sem senha,
// sem no_auth_user, sem nkeys e sem a monitoração HTTP 8222.
func TestNATSConfAuthorization(t *testing.T) {
	a := startAuthNATS(t)
	var got []string
	for _, u := range a.opts.Users {
		got = append(got, u.Username)
		if u.Password == "" {
			t.Errorf("usuário %s sem senha", u.Username)
		}
		if u.Password != a.pw[u.Username] || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(u.Password) {
			t.Errorf("usuário %s: senha não é a do auth.conf (64 hex)", u.Username)
		}
		if u.Permissions == nil || u.Permissions.Publish == nil || len(u.Permissions.Publish.Allow) == 0 {
			t.Errorf("usuário %s sem lista de permissão de publicação", u.Username)
		}
		if u.Permissions != nil && u.Permissions.Subscribe == nil {
			t.Errorf("usuário %s sem regra de assinatura (assinaria qualquer subject)", u.Username)
		}
	}
	slices.Sort(got)
	want := slices.Clone(natsUsers)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("usuários = %v, quer %v", got, want)
	}
	if a.opts.NoAuthUser != "" || len(a.opts.Nkeys) > 0 || a.opts.Authorization != "" || a.opts.Username != "" {
		t.Errorf("autenticação extra: no_auth_user=%q nkeys=%d token=%v user=%q",
			a.opts.NoAuthUser, len(a.opts.Nkeys), a.opts.Authorization != "", a.opts.Username)
	}
	if a.opts.HTTPPort != 0 || a.opts.HTTPSPort != 0 {
		t.Errorf("monitoração HTTP ligada (%d/%d); ADR 0075 item 1.5 a tira", a.opts.HTTPPort, a.opts.HTTPSPort)
	}
	if a.opts.Host != "127.0.0.1" || a.opts.Port != 4222 {
		t.Errorf("listen = %s:%d, quer 127.0.0.1:4222", a.opts.Host, a.opts.Port)
	}
	raw, err := os.ReadFile(filepath.Join("..", "eventbus", "nats", "nats.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "8222") || strings.Contains(line, "no_auth_user") || strings.HasPrefix(line, "http") {
			t.Errorf("nats.conf: %q", line)
		}
	}
	// o include vem antes do bloco que usa as variáveis
	if i, j := strings.Index(string(raw), `include "../../etc/nats/auth.conf"`), strings.Index(string(raw), "authorization {"); i < 0 || j < 0 || i > j {
		t.Errorf("include do auth.conf ausente ou depois de authorization (%d, %d)", i, j)
	}
}

// Sem credencial, ou com a senha de outro usuário, a conexão é recusada (ADR 0075 item 1.1).
func TestNATSAuthRejectsWithoutCredentials(t *testing.T) {
	a := startAuthNATS(t)
	if nc, err := nats.Connect(a.url); err == nil {
		nc.Close()
		t.Fatal("conexão sem credencial aceita")
	} else if !strings.Contains(strings.ToLower(err.Error()), "authorization violation") {
		t.Errorf("erro sem credencial = %v", err)
	}
	if nc, err := nats.Connect(a.url, nats.UserInfo("capture", a.pw["web"])); err == nil {
		nc.Close()
		t.Fatal("capture com a senha do web aceito")
	}
	if nc, err := nats.Connect(a.url, nats.UserInfo("nobody", a.pw["store"])); err == nil {
		nc.Close()
		t.Fatal("usuário desconhecido aceito")
	}
}

// O capture não grava TXT do DNS-01 nem alcança a API do JetStream (critério de aceite da task 353): a publicação
// é recusada pelo servidor, o dns não recebe nada e o stream continua lá.
func TestNATSAuthCaptureCannotWriteACMEOrJetStream(t *testing.T) {
	a := startAuthNATS(t)
	st := a.connect(t, "store")
	js, err := jetstream.New(st.nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := store.EnsureStream(ctx, js); err != nil {
		t.Fatalf("store.EnsureStream: %v", err)
	}
	dns := a.connect(t, "dns")
	var mu sync.Mutex
	got := 0
	if _, err := dns.nc.Subscribe(event.SubjectDNSACMESet, func(m *nats.Msg) {
		mu.Lock()
		got++
		mu.Unlock()
		_ = m.Respond([]byte(`{"ok":true}`))
	}); err != nil {
		t.Fatal(err)
	}
	dns.noErrors(t, "dns")

	capture := a.connect(t, "capture")
	del := "$JS.API.STREAM.DELETE." + store.StreamName
	purge := "$JS.API.STREAM.PURGE." + store.StreamName
	for _, s := range []string{event.SubjectDNSACMESet, event.SubjectDNSACMEClear, del, purge, event.SubjectStoreConnection} {
		if err := capture.nc.Publish(s, []byte(`{"name":"_acme-challenge.x","value":"forjado"}`)); err != nil {
			t.Fatal(err)
		}
		capture.waitDenied(t, "publish", s)
	}
	if _, err := capture.nc.Subscribe(">", func(*nats.Msg) {}); err != nil {
		t.Fatal(err)
	}
	capture.waitDenied(t, "subscription", ">")

	if err := dns.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if got != 0 {
		t.Errorf("dns recebeu %d fs.v1.dns.acme.set do capture", got)
	}
	mu.Unlock()
	if _, err := js.Stream(ctx, store.StreamName); err != nil {
		t.Errorf("stream %s sumiu: %v", store.StreamName, err)
	}
}

// Cada serviço faz o que o código dele faz com as permissões da tabela (ADR 0075 item 1.1), sem nenhuma recusa:
// produtores publicam no stream, o store cria o stream e o consumidor, faz Fetch e Ack, responde ao conn_id e
// publica fs.v1.store.connection para o bot; o web pede conn_id ao store e TXT ao dns; todos mandam heartbeat.
func TestNATSAuthServiceFlows(t *testing.T) {
	a := startAuthNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clients := map[string]*natsClient{}
	for _, u := range natsUsers {
		clients[u] = a.connect(t, u)
	}

	// store: stream e consumidor (store.EnsureStream), heartbeats e conn_id
	st := clients["store"]
	js, err := jetstream.New(st.nc)
	if err != nil {
		t.Fatal(err)
	}
	cons, err := store.EnsureStream(ctx, js)
	if err != nil {
		t.Fatalf("store.EnsureStream: %v", err)
	}
	hbStore := make(chan string, 16)
	if _, err := st.nc.Subscribe(event.SubjectHeartbeat, func(m *nats.Msg) { hbStore <- string(m.Data) }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.nc.Subscribe(event.SubjectStoreConnID, func(m *nats.Msg) { _ = m.Respond([]byte(`{"conn_id":"c1"}`)) }); err != nil {
		t.Fatal(err)
	}
	// dns: responde ao DNS-01
	if _, err := clients["dns"].nc.Subscribe(event.SubjectDNSACMESet, func(m *nats.Msg) { _ = m.Respond([]byte(`{"ok":true}`)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := clients["dns"].nc.Subscribe(event.SubjectDNSACMEClear, func(m *nats.Msg) { _ = m.Respond([]byte(`{"ok":true}`)) }); err != nil {
		t.Fatal(err)
	}
	// bot: conexões do store e heartbeats
	conns := make(chan string, 4)
	hbBot := make(chan string, 16)
	if _, err := clients["bot"].nc.Subscribe(event.SubjectStoreConnection, func(m *nats.Msg) { conns <- string(m.Data) }); err != nil {
		t.Fatal(err)
	}
	if _, err := clients["bot"].nc.Subscribe(event.SubjectHeartbeat, func(m *nats.Msg) { hbBot <- string(m.Data) }); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"store", "dns", "bot"} {
		if err := clients[u].nc.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	// web: request/reply como requerente
	web := clients["web"]
	if r, err := web.nc.RequestWithContext(ctx, event.SubjectStoreConnID, []byte(`{}`)); err != nil || string(r.Data) != `{"conn_id":"c1"}` {
		t.Errorf("web conn_id: %v %v", r, err)
	}
	for _, s := range []string{event.SubjectDNSACMESet, event.SubjectDNSACMEClear} {
		if r, err := web.nc.RequestWithContext(ctx, s, []byte(`{}`)); err != nil || string(r.Data) != `{"ok":true}` {
			t.Errorf("web %s: %v %v", s, r, err)
		}
	}

	// eventos de cada produtor no stream
	events := map[string][]string{
		"capture": {event.SubjectCapturePacket},
		"web":     {event.SubjectWebHTTP1Request, event.SubjectWebTLSClientHello, event.SubjectWebRawSession},
		"raw":     {event.SubjectRawSession, event.SubjectRawRead, event.SubjectWebTLSClientHello, event.SubjectWebTLSHandshake},
		"dns":     {event.SubjectDNSQuery},
	}
	want := 0
	for u, subs := range events {
		for _, s := range subs {
			if err := clients[u].nc.Publish(s, []byte(u)); err != nil {
				t.Fatal(err)
			}
			want++
		}
	}
	for _, u := range natsUsers {
		if err := clients[u].nc.Publish(event.SubjectHeartbeat, []byte(u)); err != nil {
			t.Fatal(err)
		}
		want++
	}
	for _, u := range natsUsers {
		if err := clients[u].nc.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	// store: Fetch e Ack de tudo
	seen := 0
	for seen < want && ctx.Err() == nil {
		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(500*time.Millisecond))
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		for m := range batch.Messages() {
			if err := m.Ack(); err != nil {
				t.Fatalf("Ack: %v", err)
			}
			seen++
		}
	}
	if seen != want {
		t.Fatalf("store leu %d mensagens do stream, quer %d", seen, want)
	}
	for ctx.Err() == nil {
		info, err := cons.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.NumAckPending == 0 && info.NumPending == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("acks não chegaram ao consumidor")
	}

	// store → bot
	if err := st.nc.Publish(event.SubjectStoreConnection, []byte(`{"stage":"tcp"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conns:
	case <-ctx.Done():
		t.Fatal("bot não recebeu fs.v1.store.connection")
	}
	for range natsUsers {
		select {
		case <-hbStore:
		case <-ctx.Done():
			t.Fatal("store não recebeu os heartbeats")
		}
		select {
		case <-hbBot:
		case <-ctx.Done():
			t.Fatal("bot não recebeu os heartbeats")
		}
	}
	for _, u := range natsUsers {
		clients[u].noErrors(t, u)
	}
}

// As travessias que a tabela nega: só o store publica fs.v1.store.connection e usa o JetStream, só o web pede TXT ao
// dns, ninguém publica em subject de outro serviço nem assina o que não é seu.
func TestNATSAuthDeniedCrossings(t *testing.T) {
	a := startAuthNATS(t)
	pubs := map[string][]string{
		"web":   {event.SubjectStoreConnection, "$JS.API.INFO", event.SubjectCapturePacket, event.SubjectDNSQuery},
		"raw":   {event.SubjectWebHTTP1Request, event.SubjectDNSACMESet, "$JS.API.INFO"},
		"dns":   {event.SubjectDNSACMESet, event.SubjectStoreConnection, event.SubjectWebTLSClientHello},
		"store": {event.SubjectDNSACMESet, event.SubjectCapturePacket, "$JS.ACK.OTHER.x.1"},
		"bot":   {event.SubjectStoreConnection, event.SubjectStoreConnID, "$JS.API.INFO"},
	}
	subs := map[string][]string{
		"web":   {event.SubjectCapturePacket, event.SubjectDNSACMESet},
		"raw":   {"_INBOX.>"},
		"dns":   {"_INBOX.>", event.SubjectStoreConnection},
		"store": {event.SubjectDNSACMESet},
		"bot":   {event.SubjectDNSACMESet, "_INBOX.>", event.SubjectCapturePacket},
	}
	for u, ss := range pubs {
		c := a.connect(t, u)
		for _, s := range ss {
			if err := c.nc.Publish(s, []byte("x")); err != nil {
				t.Fatal(err)
			}
			c.waitDenied(t, "publish", s)
		}
		for _, s := range subs[u] {
			if _, err := c.nc.Subscribe(s, func(*nats.Msg) {}); err != nil {
				t.Fatal(err)
			}
			c.waitDenied(t, "subscription", s)
		}
	}
}

// natsUnitPaths: o que cada unit não alcança em etc/nats (spec 016 RF-06, ADR 0075 item 2.1): o auth.conf e as
// senhas dos outros serviços; a unit do NATS, todas as senhas (o auth.conf já as contém).
func natsUnitPaths(unit string) []string {
	var out []string
	if unit != "nats" {
		out = append(out, "-/finger-sniffer/etc/nats/auth.conf")
	}
	for _, u := range natsUsers {
		if u != unit {
			out = append(out, "-/finger-sniffer/etc/nats/"+u+".password")
		}
	}
	return out
}

// ADR 0075 item 1.3 e 2.1 (task 353): cada unit de serviço tem o próprio usuário e o arquivo da própria senha
// (FS_NATS_USER e FS_NATS_PASSWORD_FILE em Environment=, nunca FS_NATS_PASSWORD) e não alcança o auth.conf nem a
// senha dos outros; a unit do NATS lê o auth.conf e não as senhas.
func TestUnitNATSCredentials(t *testing.T) {
	for _, unit := range append(slices.Clone(natsUsers), "nats") {
		d := unitDirectives(t, "finger-sniffer-"+unit+".service")
		env := envOf(d)
		var inacc []string
		for _, p := range fieldsOf(d, "InaccessiblePaths") {
			if strings.HasPrefix(p, "-/finger-sniffer/etc/") {
				inacc = append(inacc, p)
			}
		}
		if want := natsUnitPaths(unit); !slices.Equal(inacc, want) {
			t.Errorf("%s: InaccessiblePaths de etc/ = %q, quer %q", unit, inacc, want)
		}
		if unit == "nats" {
			if strings.Contains(env, "FS_NATS_") {
				t.Errorf("nats: Environment com credencial de cliente: %s", env)
			}
			continue
		}
		for _, kv := range []string{"FS_NATS_USER=" + unit, "FS_NATS_PASSWORD_FILE=/finger-sniffer/etc/nats/" + unit + ".password"} {
			if !strings.Contains(env, " "+kv+" ") {
				t.Errorf("%s: Environment sem %s (%s)", unit, kv, env)
			}
		}
		if strings.Contains(env, "FS_NATS_PASSWORD=") {
			t.Errorf("%s: senha direta na unit", unit)
		}
	}
	// nenhuma unit de serviço sem usuário: toda unit que não é a de rede nem a do NATS conecta ao NATS (um serviço
	// novo sem entrada em natsUsers falha aqui)
	units, err := filepath.Glob(filepath.Join("systemd", "finger-sniffer-*.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range units {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(u), "finger-sniffer-"), ".service")
		if name == "net" || name == "nats" {
			continue
		}
		if !slices.Contains(natsUsers, name) || !strings.Contains(envOf(unitDirectives(t, filepath.Base(u))), " FS_NATS_USER="+name+" ") {
			t.Errorf("%s: serviço sem usuário do NATS", filepath.Base(u))
		}
	}
}
