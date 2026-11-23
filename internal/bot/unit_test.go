package bot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	for _, k := range []string{"FS_LISTEN_IPV4", "FS_LISTEN_IPV6", "FS_BOT_INTERNAL_LISTEN", "FS_BOT_INTERNAL_ALLOW"} {
		t.Setenv(k, "")
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicPort != 9002 || c.InternalPort != 9003 || c.DBPath != "/finger-sniffer/var/bot/bot.db" ||
		c.MaxBytes != 2<<30 || c.FlushInterval != 5*time.Second || c.AggRetention != MaxAggRetention ||
		c.ConnTTL != 10*time.Minute || c.MaxConns != 100000 || c.ViewWait != 100*time.Millisecond ||
		c.RateHigh != 120 || c.ListRefreshAt != 4*time.Hour || len(c.PublicIPs) != 0 || len(c.InternalAllow) != 0 {
		t.Fatalf("padrões: %+v", c)
	}

	t.Setenv("FS_LISTEN_IPV4", "172.233.24.85")
	t.Setenv("FS_BOT_INTERNAL_LISTEN", "10.249.0.1/16")
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.InternalListen != netip.MustParseAddr("10.249.0.1") || len(c.InternalAllow) != 1 ||
		c.InternalAllow[0] != netip.MustParsePrefix("10.249.0.0/16") || len(c.PublicIPs) != 1 {
		t.Fatalf("listen com prefixo: %+v", c)
	}
	// IP sem prefixo: a sub-rede vem da interface (aqui, falsa).
	old := interfacePrefix
	interfacePrefix = func(netip.Addr) (netip.Prefix, bool) { return netip.MustParsePrefix("10.249.0.0/16"), true }
	t.Cleanup(func() { interfacePrefix = old })
	t.Setenv("FS_BOT_INTERNAL_LISTEN", "10.249.0.1")
	if c, err = LoadConfig(); err != nil || c.InternalAllow[0] != netip.MustParsePrefix("10.249.0.0/16") {
		t.Fatalf("sub-rede da interface: %v %+v", err, c.InternalAllow)
	}
	t.Setenv("FS_BOT_INTERNAL_ALLOW", "10.249.0.0/24, 192.168.5.0/24")
	if c, err = LoadConfig(); err != nil || len(c.InternalAllow) != 2 {
		t.Fatalf("allow explícito: %v %+v", err, c.InternalAllow)
	}

	for k, v := range map[string]string{
		"FS_BOT_AGG_RETENTION": "169h", "FS_BOT_INTERNAL_LISTEN": "0.0.0.0", "FS_LISTEN_IPV4": "::1",
		"FS_BOT_VIEW_WAIT": "2s", "FS_BOT_LIST_REFRESH_AT": "4am", "FS_BOT_PUBLIC_PORT": "70000",
		"FS_BOT_INTERNAL_ALLOW": "x",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Errorf("%s=%s aceito", k, v)
			}
		})
	}
}

func TestDomains(t *testing.T) {
	d, err := NormalizeDomains([]string{" Example.COM. ", "*.example.org", "example.com", ""})
	if err != nil || len(d) != 2 || d[0] != "example.com" || d[1] != "*.example.org" {
		t.Fatalf("%v %v", d, err)
	}
	for _, bad := range [][]string{{}, {"localhost"}, {"exa mple.com"}, {"*.*.example.com"}, {"-a.example.com"}} {
		if _, err := NormalizeDomains(bad); err == nil {
			t.Errorf("%v aceito", bad)
		}
	}
	for _, tc := range []struct {
		site string
		want bool
	}{
		{"example.com", true},
		{"EXAMPLE.com:443", true},
		{"example.com.", true},
		{"www.example.com", false},
		{"a.example.org", true},
		{"a.b.example.org", true},
		{"example.org", false},
		{"badexample.org", false},
		{"", false},
	} {
		if got := MatchDomain(d, tc.site); got != tc.want {
			t.Errorf("%q: %v", tc.site, got)
		}
	}
}

// TestKeyLifecycle: create/list/revoke/rotate; formato fsk_ + 52 base32; só o SHA-256 vai ao banco.
func TestKeyLifecycle(t *testing.T) {
	db, path := testDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	k, secret, wh, err := CreateKey(ctx, db, KeyOptions{
		Name: "site", Domains: []string{"example.com"}, WebhookURL: "https://hooks.example.com/x",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 4+52 || !strings.HasPrefix(secret, "fsk_") || strings.ToLower(secret) != secret || len(wh) != 32 {
		t.Fatalf("chave %q, segredo do webhook %d bytes", secret, len(wh))
	}
	if _, ok := ParseKey(secret); !ok {
		t.Fatal("formato próprio recusado")
	}
	for _, suffix := range []string{"", "-wal"} {
		if raw, _ := os.ReadFile(path + suffix); bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(secret[4:])) {
			t.Fatalf("chave em claro no banco (%s)", path+suffix)
		}
	}
	var stored []byte
	if err := db.QueryRow("SELECT key_sha256 FROM api_keys").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256([]byte(secret)); !bytes.Equal(stored, h[:]) {
		t.Fatal("key_sha256 não é o SHA-256 da chave")
	}
	if k.Prefix != secret[4:12] || k.Mode != ModeObserve || strings.Join(k.WebhookClasses, ",") != "bot,suspect" {
		t.Fatalf("%+v", k)
	}
	ks := NewKeyStore(db)
	if err := ks.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got, ok := ks.Lookup(secret); !ok || got.ID != k.ID || ks.Active() != 1 {
		t.Fatal("lookup")
	}
	// Rotação pelo prefixo: a antiga deixa de valer, a nova vale, id mantido.
	k2, secret2, err := RotateKey(ctx, db, "fsk_"+k.Prefix)
	if err != nil || k2.ID != k.ID || secret2 == secret {
		t.Fatal(err)
	}
	_ = ks.Reload(ctx)
	if _, ok := ks.Lookup(secret); ok {
		t.Error("chave antiga vale depois da rotação")
	}
	if _, ok := ks.Lookup(secret2); !ok {
		t.Error("chave nova não vale")
	}
	if _, err := RevokeKey(ctx, db, k.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := RevokeKey(ctx, db, k.ID, now); err == nil {
		t.Error("revogar duas vezes")
	}
	_ = ks.Reload(ctx)
	if _, ok := ks.Lookup(secret2); ok || ks.Active() != 0 {
		t.Error("revogada vale")
	}
	keys, err := ListKeys(ctx, db)
	if err != nil || len(keys) != 1 || keys[0].RevokedAt == nil {
		t.Fatalf("%v %+v", err, keys)
	}
	for _, o := range []KeyOptions{
		{Domains: []string{"example.com"}},
		{Name: "x"},
		{Name: "x", Domains: []string{"example.com"}, Mode: "deny"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "http://insecure.example.com"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://127.0.0.1/hook"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://[::1]:8443/hook"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://10.249.0.5/hook"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://169.254.169.254/latest"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://100.64.0.1/hook"},
		{Name: "x", Domains: []string{"example.com"}, WebhookURL: "https://h.example.com", WebhookClasses: []string{"evil"}},
	} {
		if _, _, _, err := CreateKey(ctx, db, o, now); err == nil {
			t.Errorf("%+v aceito", o)
		}
	}
	for _, bad := range []string{"", "fsk_", "fsk_" + strings.Repeat("A", 52), "fsk_" + strings.Repeat("1", 52), "xsk_" + strings.Repeat("a", 52)} {
		if _, ok := ParseKey(bad); ok {
			t.Errorf("%q aceito", bad)
		}
	}
}

// TestCLI: key create imprime a chave uma vez; list não a mostra; revoke/rotate/forget pela CLI.
func TestCLI(t *testing.T) {
	shortWaits(t, 50*time.Millisecond, 50*time.Millisecond)
	_, path := testDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	var out, errOut bytes.Buffer
	if err := RunCLI(ctx, []string{"key", "create", "--name", "site", "--domains", "example.com,*.example.org", "--mode", "block"}, path, &out, &errOut, now); err != nil {
		t.Fatalf("%v %s", err, errOut.String())
	}
	var secret, id string
	for _, l := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, "key: "); ok {
			secret = v
		}
		if v, ok := strings.CutPrefix(l, "id: "); ok {
			id = v
		}
	}
	if _, ok := ParseKey(secret); !ok || id == "" {
		t.Fatalf("saída: %s", out.String())
	}
	out.Reset()
	if err := RunCLI(ctx, []string{"key", "list"}, path, &out, &errOut, now); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) || !strings.Contains(out.String(), id) || !strings.Contains(out.String(), "block") {
		t.Fatalf("list: %s", out.String())
	}
	out.Reset()
	if err := RunCLI(ctx, []string{"key", "rotate", id}, path, &out, &errOut, now); err != nil || !strings.Contains(out.String(), "key: fsk_") {
		t.Fatalf("rotate: %v %s", err, out.String())
	}
	if err := RunCLI(ctx, []string{"key", "revoke", id}, path, &out, &errOut, now); err != nil {
		t.Fatal(err)
	}
	if err := RunCLI(ctx, []string{"key", "revoke", "01JC0X3K8V2T7Q9N4M6P1R5S8W"}, path, &out, &errOut, now); err == nil {
		t.Error("revogar chave inexistente")
	}
	out.Reset()
	if err := RunCLI(ctx, []string{"forget", "192.0.2.0/24"}, path, &out, &errOut, now); err != nil || !strings.Contains(out.String(), "0 aggregate rows") {
		t.Fatalf("forget: %v %s", err, out.String())
	}
	for _, args := range [][]string{{"key"}, {"key", "nope"}, {"key", "revoke"}, {"forget"}, {"key", "create", "--bogus"}} {
		if err := RunCLI(ctx, args, path, &out, &errOut, now); err == nil {
			t.Errorf("%v aceito", args)
		}
	}
}

// TestForgetAndPurge: forget apaga o IP ou o prefixo (v4 e v6) e nada além; o expurgo tira o que passa da
// retenção (relógio falso): nada com IP fica além de 7 dias e 1 hora.
func TestForgetAndPurge(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 30, 0, 0, time.UTC)
	hour := now.Unix() / 3600
	ins := func(ip string, h int64) {
		t.Helper()
		if _, err := db.Exec("INSERT INTO ip_hourly (ip, site, hour, requests) VALUES (?, 's', ?, 1)", ipKey(mustAddr(ip)), h); err != nil {
			t.Fatal(err)
		}
	}
	count := func() (n int) {
		t.Helper()
		_ = db.QueryRow("SELECT count(*) FROM ip_hourly").Scan(&n)
		return n
	}
	ins("192.0.2.1", hour)
	ins("192.0.2.200", hour)
	ins("192.0.3.1", hour)
	ins("2001:db8::1", hour)
	ins("2001:db8:1::1", hour)
	for _, tc := range []struct {
		arg  string
		want int64
	}{{"::ffff:192.0.2.1", 1}, {"192.0.2.0/24", 1}, {"2001:db8::/48", 1}, {"10.0.0.1", 0}} {
		p, err := ParseIPOrPrefix(tc.arg)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := Forget(ctx, db, p); err != nil || n != tc.want {
			t.Errorf("forget %s: %d %v", tc.arg, n, err)
		}
	}
	if count() != 2 {
		t.Fatalf("sobraram %d linhas", count())
	}
	if _, err := ParseIPOrPrefix("nope"); err == nil {
		t.Error("prefixo inválido aceito")
	}

	// Expurgo: fica a hora que começou depois do corte (now-7d), sai a que começou antes (inclusive a hora do corte,
	// que começa às 12:00 de 7 dias atrás com o relógio às 12:30).
	db.Exec("DELETE FROM ip_hourly") //nolint:errcheck // limpeza do teste
	cut := now.Unix() - int64(MaxAggRetention/time.Second)
	ins("192.0.2.1", cut/3600+1)
	ins("192.0.2.2", cut/3600)
	day := cut / 86400
	if _, err := db.Exec("INSERT INTO fp_daily (kind, value, day, ua_family) VALUES ('ja4','a',?,'x'), ('ja4','b',?,'x')",
		day+1, day); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO key_usage_daily (key_id, day) VALUES ('k', ?), ('k', ?)", now.Unix()/86400-89, now.Unix()/86400-91); err != nil {
		t.Fatal(err)
	}
	n, err := Purge(ctx, db, now, MaxAggRetention)
	if err != nil || n != 2 {
		t.Fatalf("purge: %d %v", n, err)
	}
	var fp, usage int
	_ = db.QueryRow("SELECT count(*) FROM fp_daily").Scan(&fp)
	_ = db.QueryRow("SELECT count(*) FROM key_usage_daily").Scan(&usage)
	if count() != 1 || fp != 1 || usage != 1 {
		t.Fatalf("ip %d fp %d uso %d", count(), fp, usage)
	}
}

// TestPurgeMaxAge: relógio falso fora de fase com a hora e o dia (expurgo a cada purgeInterval começando em minutos
// e segundos quaisquer), uma linha por hora e por dia escrita como o flush escreve (período do instante); a idade do
// dado mais velho de cada linha, medida logo antes de cada expurgo, nunca passa de 7 dias e 1 hora (spec 018 RF-08,
// ADR 0052 item 1).
func TestPurgeMaxAge(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	limit := MaxAggRetention + time.Hour
	for _, start := range []time.Time{
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 1, 0, 59, 59, 0, time.UTC),
		time.Date(2026, 11, 1, 23, 17, 43, 0, time.UTC),
		time.Date(2026, 11, 1, 12, 30, 1, 0, time.UTC),
	} {
		db.Exec("DELETE FROM ip_hourly") //nolint:errcheck // limpeza do teste
		db.Exec("DELETE FROM fp_daily")  //nolint:errcheck // limpeza do teste
		var maxIP, maxFP time.Duration
		// 10 dias de expurgos; antes de cada um, o flush grava a hora e o dia correntes
		for now := start; now.Before(start.Add(10 * 24 * time.Hour)); now = now.Add(purgeInterval) {
			h, d := now.Unix()/3600, now.Unix()/86400
			if _, err := db.Exec("INSERT OR IGNORE INTO ip_hourly (ip, site, hour, requests) VALUES (?, 's', ?, 1)",
				ipKey(mustAddr("192.0.2.1")), h); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT OR IGNORE INTO fp_daily (kind, value, day, ua_family) VALUES ('ja4','a',?,'x')", d); err != nil {
				t.Fatal(err)
			}
			// idade do dado mais velho possível de cada linha: o início do período
			var oh, od int64
			_ = db.QueryRow("SELECT min(hour) FROM ip_hourly").Scan(&oh)
			_ = db.QueryRow("SELECT min(day) FROM fp_daily").Scan(&od)
			maxIP = max(maxIP, now.Sub(time.Unix(oh*3600, 0)))
			maxFP = max(maxFP, now.Sub(time.Unix(od*86400, 0)))
			if _, err := Purge(ctx, db, now, MaxAggRetention); err != nil {
				t.Fatal(err)
			}
		}
		if maxIP > limit || maxFP > limit {
			t.Errorf("início %s: idade máxima ip_hourly %s fp_daily %s (limite %s)", start, maxIP, maxFP, limit)
		}
		// a janela de 7 dias continua lá: depois de 10 dias, há linhas de quase 7 dias
		if maxIP < MaxAggRetention-time.Hour {
			t.Errorf("início %s: ip_hourly expurgado cedo demais (%s)", start, maxIP)
		}
	}
}

// TestDailyQuota: a cota diária responde 429 com Retry-After até a meia-noite UTC e sobrevive ao reinício
// (o uso gravado no Flush é lido de volta).
func TestDailyQuota(t *testing.T) {
	db, _ := testDB(t)
	ctx := context.Background()
	clock := newFakeClock(time.Date(2026, 11, 16, 23, 59, 0, 0, time.UTC))
	k := &Key{ID: "k1", RatePerS: 1000, Burst: 1000, DailyQuota: 3}
	l := NewLimiter(db, clock.Now)
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow(ctx, k); !ok {
			t.Fatal("dentro da cota")
		}
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// "Reinício": limitador novo lê as 2 já gravadas.
	l = NewLimiter(db, clock.Now)
	if ok, _ := l.Allow(ctx, k); !ok {
		t.Fatal("terceira")
	}
	ok, retry := l.Allow(ctx, k)
	if ok || retry != 60 {
		t.Fatalf("acima da cota: %v %d", ok, retry)
	}
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var req, lim int
	if err := db.QueryRow("SELECT requests, limited FROM key_usage_daily WHERE key_id = 'k1'").Scan(&req, &lim); err != nil || req != 3 || lim != 1 {
		t.Fatalf("uso gravado: %d %d %v", req, lim, err)
	}
	clock.Advance(time.Minute)
	if ok, _ := l.Allow(ctx, k); !ok {
		t.Fatal("dia novo")
	}
}

// TestMatchStoreClosedWithoutFirst: task 364 — sem o início do fork (forwardAuth antes do registro de conexão), a
// entrada fechada da mesma origem não casa (é a conexão anterior da mesma 4-tupla); a aberta casa. Com o início,
// vale só a janela de 5 s.
func TestMatchStoreClosedWithoutFirst(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	ix := NewIndex(10*time.Minute, 100, 0, nil)
	put := func(id, stage string, started time.Time) {
		ix.PutStore(&StoreConn{
			ConnID: id, Stage: stage, L4: "tcp", SrcIP: mustAddr("198.51.100.7"), SrcPort: 51234, DstPort: 443, Started: started,
		}, now)
	}
	put("OLD", StageClosed, now.Add(-5*time.Minute))
	if c, ok := ix.MatchStore(mustAddr("198.51.100.7"), 51234, 443, "", time.Time{}, now); ok {
		t.Fatalf("casou a conexão fechada sem o início: %+v", c)
	}
	if _, ok := ix.MatchStore(mustAddr("198.51.100.7"), 51234, 443, "", now.Add(-5*time.Minute), now); !ok {
		t.Error("com o início, a fechada dentro da janela devia casar (consulta depois do fim)")
	}
	put("NEW", StageOpened, now)
	if c, ok := ix.MatchStore(mustAddr("198.51.100.7"), 51234, 443, "", time.Time{}, now); !ok || c.ConnID != "NEW" {
		t.Fatalf("a aberta não casou: %+v %v", c, ok)
	}
	put("NEW", StageUpdated, now)
	if c, ok := ix.MatchStore(mustAddr("198.51.100.7"), 51234, 443, "", time.Time{}, now); !ok || c.ConnID != "NEW" {
		t.Fatalf("a atualizada não casou: %+v %v", c, ok)
	}
}

// TestMatchStoreL4: task 402 — o casamento confere o L4 esperado (h3 → udp, h1/h2 → tcp) sem mudar a chave do
// índice; "" não filtra. ForkConn.L4 deduz o transporte da conexão do fork.
func TestMatchStoreL4(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	ix := NewIndex(10*time.Minute, 100, 0, nil)
	ix.PutStore(&StoreConn{ConnID: "U", Stage: StageOpened, L4: "udp", SrcIP: mustAddr("198.51.100.7"), SrcPort: 50000, DstPort: 443, Started: now}, now)
	for l4, want := range map[string]bool{"udp": true, "tcp": false, "": true} {
		if _, ok := ix.MatchStore(mustAddr("198.51.100.7"), 50000, 443, l4, now, now); ok != want {
			t.Errorf("l4 %q: casou %v", l4, ok)
		}
	}
	for proto, want := range map[string]string{"h1": "tcp", "h2": "tcp", "h3": "udp", "": ""} {
		if got := l4OfProto(proto); got != want {
			t.Errorf("l4OfProto(%q) = %q", proto, got)
		}
	}
	for name, c := range map[string]struct {
		f    ForkConn
		want string
	}{
		"empty":       {ForkConn{}, ""},
		"udp view":    {ForkConn{TCP: &ForkTCP{UDP: true}}, "udp"},
		"tcp view":    {ForkConn{TCP: &ForkTCP{}}, "tcp"},
		"quic timing": {ForkConn{Timing: &ForkTiming{QUIC: true}}, "udp"},
		"ja4 q":       {ForkConn{TLS: &ForkTLS{JA4: "q13d0310h3_x_y"}}, "udp"},
		"ja4 t":       {ForkConn{TLS: &ForkTLS{JA4: "t13d1516h2_x_y"}}, "tcp"},
		"alpn h3":     {ForkConn{ALPN: "h3"}, "udp"},
		"request h2":  {ForkConn{Requests: []ForkRequest{{Proto: "h2"}}}, "tcp"},
		"request h3":  {ForkConn{Requests: []ForkRequest{{Proto: "h3"}}}, "udp"},
	} {
		if got := c.f.L4(); got != c.want {
			t.Errorf("%s: L4 = %q, esperado %q", name, got, c.want)
		}
	}
}

// TestAuthIgnoresClosedSameOrigin: task 364 — com a conexão anterior da mesma origem fechada no índice, o
// forwardAuth da primeira requisição da conexão nova espera o opened dela (que chega 50 ms depois) e o veredito leva
// o conn_id da nova, não o da velha.
func TestAuthIgnoresClosedSameOrigin(t *testing.T) {
	f := newFixture(t)
	f.srv.api.ViewWait = 300 * time.Millisecond
	ix := f.srv.Index()
	ix.PutStore(&StoreConn{
		ConnID: "01JC0X3K8V2T7Q9N4M6P1R5OLD", Stage: StageClosed, L4: "tcp", SrcIP: mustAddr("198.51.100.7"), SrcPort: 51234,
		DstIP: mustAddr("203.0.113.10"), DstPort: 443, Started: f.clock.Now().Add(-5 * time.Minute),
	}, f.clock.Now())
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.putStore()
	}()
	c, _, v, b := f.authVerdict("internal", "", forkHeadersFor())
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	if v.Subject.ConnID == nil || *v.Subject.ConnID != testStoreConnID || !v.View.TCP {
		t.Fatalf("veredito sem a conexão nova: %s", b)
	}
	if n := f.metrics.Get(viewWaitMetric("tcp")); n != 0 {
		t.Errorf("view_wait{missing=tcp} = %v com o opened chegando na espera", n)
	}
	// Sem o opened da nova, a velha não casa: o veredito sai sem visão TCP e a espera conta missing="tcp".
	hdr := forkHeadersFor()
	hdr["X-Fs-Src-Port"], hdr["X-Fs-Conn-Id"] = "51235", "01JC0X3K8V2T7Q9F4M6P1R5T70"
	ix.PutStore(&StoreConn{
		ConnID: "01JC0X3K8V2T7Q9N4M6P1R5OL2", Stage: StageClosed, L4: "tcp", SrcIP: mustAddr("198.51.100.7"), SrcPort: 51235,
		DstIP: mustAddr("203.0.113.10"), DstPort: 443, Started: f.clock.Now().Add(-5 * time.Minute),
	}, f.clock.Now())
	if _, _, v, b := f.authVerdict("internal", "", hdr); v.View.TCP || v.Subject.ConnID != nil {
		t.Errorf("casou a conexão fechada: %s", b)
	}
	if n := f.metrics.Get(viewWaitMetric("tcp")); n != 1 {
		t.Errorf("view_wait{missing=tcp} = %v, esperado 1", n)
	}
}

// TestIndex: TTL, teto com despejo da mais antiga, casamento pela origem (IPv4 mapeado) com janela de 5 s e
// espera pela visão.
func TestIndex(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	evicted := 0
	ix := NewIndex(10*time.Minute, 2, 0, func(_ string, n int) { evicted += n })
	conn := func(id string, port int) *StoreConn {
		return &StoreConn{ConnID: id, SrcIP: mustAddr("::ffff:198.51.100.7"), SrcPort: port, DstPort: 443, Started: now}
	}
	ix.PutStore(conn("A", 1), now)
	ix.PutStore(conn("B", 2), now)
	ix.PutStore(conn("A", 1), now.Add(time.Second)) // atualização move A para o fim
	ix.PutStore(conn("C", 3), now.Add(2*time.Second))
	if evicted != 1 {
		t.Fatalf("despejos %d", evicted)
	}
	if _, ok := ix.StoreByID("B", now); ok {
		t.Error("B devia ter sido despejada (a mais antiga)")
	}
	if _, ok := ix.MatchStore(mustAddr("198.51.100.7"), 1, 443, "", now.Add(4*time.Second), now); !ok {
		t.Error("casamento com IPv4 mapeado")
	}
	if _, ok := ix.MatchStore(mustAddr("198.51.100.7"), 1, 443, "", now.Add(6*time.Second), now); ok {
		t.Error("casou fora da janela de 5 s")
	}
	if _, ok := ix.MatchStore(mustAddr("198.51.100.7"), 1, 8443, "", time.Time{}, now); ok {
		t.Error("casou com outra porta de destino")
	}
	if _, ok := ix.StoreByID("A", now.Add(11*time.Minute)); ok {
		t.Error("A passou do TTL")
	}
	if n := ix.Forget(netip.MustParsePrefix("198.51.100.0/24")); n != 2 {
		t.Errorf("forget no índice: %d", n)
	}

	// Wait acorda quando a visão chega.
	go func() {
		time.Sleep(10 * time.Millisecond)
		ix.UpdateFork("F", now, func(c *ForkConn) { c.SNI = "x.example.com" })
	}()
	ok := ix.Wait(context.Background(), time.Second, func() bool { _, ok := ix.Fork("F", now); return ok })
	if !ok {
		t.Fatal("Wait não viu a visão")
	}
	if ix.Wait(context.Background(), 5*time.Millisecond, func() bool { return false }) {
		t.Error("Wait sem visão")
	}
}

// TestParseStoreConnection: o payload do asyncapi (envelope + stage + Connection) vira a visão do store, sem as
// listas grandes; fora do contrato é recusado.
func TestParseStoreConnection(t *testing.T) {
	msg := storeMessage("opened", testStoreConnID, "203.0.113.9", 40000)
	c, err := ParseStoreConnection(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnID != testStoreConnID || c.Stage != "opened" || c.SrcIP != mustAddr("203.0.113.9") || c.SrcPort != 40000 ||
		c.DstPort != 443 || c.Started.IsZero() || c.ProbeID != "" {
		t.Fatalf("%+v", c)
	}
	if bytes.Contains(c.Record, []byte(`"http"`)) || !bytes.Contains(c.Record, []byte(`"tcp"`)) {
		t.Errorf("record: %s", c.Record)
	}
	for _, bad := range [][]byte{
		[]byte(`{}`),
		storeMessage("deleted", testStoreConnID, "203.0.113.9", 1),
		storeMessage("opened", "x", "203.0.113.9", 1),
		storeMessage("opened", testStoreConnID, "nope", 1),
		storeMessage("opened", testStoreConnID, "203.0.113.9", 70000),
	} {
		if _, err := ParseStoreConnection(bad); err == nil {
			t.Errorf("aceito: %s", bad)
		}
	}
}

// storeMessage monta uma mensagem de fs.v1.store.connection como o store publica (task 268).
func storeMessage(stage, connID, srcIP string, srcPort int) []byte {
	return []byte(`{"schema_version":1,"service":"store","service_version":"v0.4.0","ts":"2026-11-16T12:00:00.000000000Z",` +
		`"payload":{"stage":"` + stage + `","connection":{"conn_id":"` + connID + `","probe_id":null,"proto":"tcp","l4":"tcp",` +
		`"family":4,"src":{"ip":"` + srcIP + `","port":` + strconv.Itoa(srcPort) + `},"dst":{"ip":"172.233.24.85","port":443},` +
		`"started":"2026-11-16T12:00:00.000000000Z","ended":null,"tcp":{"syn":{"ttl":64}},"http":[{"method":"GET"}]}}}`)
}
