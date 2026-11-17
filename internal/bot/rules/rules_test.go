package rules

import (
	"go/build"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestInputHasNoPersonalContent garante que a entrada não tem campo de corpo, query, caminho, cookie nem
// Authorization (ADR 0049 item 5, ADR 0052): nenhum sinal pode lê-los porque eles não chegam às regras.
func TestInputHasNoPersonalContent(t *testing.T) {
	forbidden := []string{"body", "query", "path", "cookie", "authorization", "auth", "password", "token"}
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || rt.PkgPath() != reflect.TypeFor[Input]().PkgPath() {
			return
		}
		for f := range rt.Fields() {
			// contagens de caminhos distintos (por hash, ADR 0052 item 2) não são caminhos
			if f.Name == "PathsHour" {
				continue
			}
			name := strings.ToLower(f.Name)
			for _, w := range forbidden {
				if strings.Contains(name, w) {
					t.Errorf("campo %s%s lembra %q: dado fora da spec 018", prefix, f.Name, w)
				}
			}
			walk(f.Type, prefix+f.Name+".")
		}
	}
	walk(reflect.TypeFor[Input](), "Input.")
}

// TestDetailsHaveNoIPOrUA confere que nenhum `detail` dos goldens leva o IP ou o User-Agent inteiro.
func TestDetailsHaveNoIPOrUA(t *testing.T) {
	for _, c := range goldenCases(t) {
		got := goldenEngine(t, c.ja4db).Evaluate(c.in)
		for _, s := range got.Signals {
			if c.in.IP.IsValid() && strings.Contains(s.Detail, c.in.IP.Unmap().String()) {
				t.Errorf("%s/%s: detail com IP: %q", c.name, s.ID, s.Detail)
			}
			if c.in.HTTP != nil && len(c.in.HTTP.UserAgent) > 20 && strings.Contains(s.Detail, c.in.HTTP.UserAgent) {
				t.Errorf("%s/%s: detail com o User-Agent: %q", c.name, s.ID, s.Detail)
			}
			if len(s.Detail) > detailMaxLen {
				t.Errorf("%s/%s: detail com %d bytes", c.name, s.ID, len(s.Detail))
			}
		}
	}
}

// TestNoImportOfBot: o pacote não importa internal/bot (sem ciclo) nem nada fora da stdlib.
func TestNoImportOfBot(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, ".") {
			t.Errorf("import fora da stdlib: %s", imp)
		}
	}
}

func TestZeroEngineAndEmptyInput(t *testing.T) {
	got := Engine{}.Evaluate(Input{})
	if got.Class != ClassUnknown || got.Score != 0 || got.Signals == nil || len(got.Signals) != 0 {
		t.Fatalf("%+v", got)
	}
	// sem fontes, um Chrome completo não tem base para comparar: human sem sinais
	base := loadKnownClients(t)
	in := inputFrom(base.entry(t, "chrome", "h2"), goldenUA["chrome"], ipResidential)
	if got := (Engine{}).Evaluate(in); got.Class != ClassHuman || len(got.Signals) != 0 || got.UAFamily != "chrome" ||
		got.UAOS != "macos" {
		t.Fatalf("%+v", got)
	}
}

func TestScoreClampedAndClasses(t *testing.T) {
	cases := []struct {
		sum  int
		view View
		want string
	}{
		{100, View{}, ClassBot},
		{70, View{}, ClassBot},
		{69, View{TLS: true, HTTP: true}, ClassSuspect},
		{40, View{}, ClassSuspect},
		{39, View{TLS: true, HTTP: true}, ClassHuman},
		{39, View{TLS: true}, ClassUnknown},
		{0, View{HTTP: true}, ClassUnknown},
	}
	for _, c := range cases {
		if got := classify(c.sum, false, c.view); got != c.want {
			t.Errorf("score %d view %+v: %q; quer %q", c.sum, c.view, got, c.want)
		}
	}
	if got := classify(0, true, View{}); got != ClassGoodBot {
		t.Errorf("good_bot: %q", got)
	}
	// soma acima de 100 fica em 100
	in := withView(Input{IP: ipCloud, Behavior: &Behavior{
		RequestsPerMin: 1000, RequestsHour: 1000, ConnsHour: 1000, IntervalN: 100, IntervalSum: 100, IntervalSqSum: 100,
		PathsHour: 900,
	}, HTTP: &HTTP{UserAgent: uaGooglebot}})
	en := Engine{Sources: Sources{IPs: testIPs()}}
	if got := en.Evaluate(in); got.Score != 100 || got.Class != ClassBot {
		t.Fatalf("%+v", got)
	}
}

func TestRateHighThreshold(t *testing.T) {
	in := withView(Input{Behavior: &Behavior{RequestsPerMin: 121}})
	if got := (Engine{}).Evaluate(in); len(got.Signals) != 1 || got.Signals[0].ID != SignalRateHigh {
		t.Fatalf("padrão 120: %+v", got)
	}
	if got := (Engine{RateHigh: 200}).Evaluate(in); len(got.Signals) != 0 {
		t.Fatalf("limiar 200: %+v", got)
	}
	in.Behavior.RequestsPerMin = 120
	if got := (Engine{}).Evaluate(in); len(got.Signals) != 0 {
		t.Fatalf("120 não passa de 120: %+v", got)
	}
}

func TestBehaviorBorders(t *testing.T) {
	cases := []struct {
		name string
		b    Behavior
		want string
	}{
		{"no_reuse below 10", Behavior{RequestsHour: 9, ConnsHour: 9}, ""},
		{"no_reuse reused", Behavior{RequestsHour: 20, ConnsHour: 5}, ""},
		{"no_reuse", Behavior{RequestsHour: 10, ConnsHour: 10}, SignalNoReuse},
		{"interval 19", Behavior{IntervalN: 19, IntervalSum: 19, IntervalSqSum: 19}, ""},
		{"interval irregular", Behavior{IntervalN: 20, IntervalSum: 20, IntervalSqSum: 40}, ""},
		{"interval regular", Behavior{IntervalN: 20, IntervalSum: 20, IntervalSqSum: 20}, SignalIntervalRegular},
		{"interval zero sum", Behavior{IntervalN: 20}, ""},
		{"route 49", Behavior{PathsHour: 49}, ""},
		{"route statics 5%", Behavior{PathsHour: 100, StaticsHour: 5}, ""},
		{"route", Behavior{PathsHour: 100, StaticsHour: 4}, SignalRouteBreadth},
	}
	for _, c := range cases {
		b := c.b
		got := Engine{}.Evaluate(withView(Input{Behavior: &b}))
		ids := signalIDs(got)
		if (c.want == "" && len(ids) != 0) || (c.want != "" && (len(ids) != 1 || ids[0] != c.want)) {
			t.Errorf("%s: %v; quer %q", c.name, ids, c.want)
		}
	}
}

func TestCrawlerVerification(t *testing.T) {
	go1 := loadKnownClients(t).entry(t, "go", "h2")
	en := goldenEngine(t, false)
	// no IP da lista com a verificação ainda desconhecida: sem good_bot e sem ua_claims_crawler (ainda pendente)
	pending := netip.MustParseAddr("66.249.66.200")
	got := en.Evaluate(inputFrom(go1, uaGooglebot, pending))
	if got.Class == ClassGoodBot || hasSignal(got, SignalUAClaimsCrawler) || !hasSignal(got, SignalIPCrawlerListUnverified) {
		t.Fatalf("verificação desconhecida: %+v", got)
	}
	// UA de Googlebot num IP da lista do Bing: não é o robô declarado
	got = en.Evaluate(inputFrom(go1, uaGooglebot, ipBingbot))
	if !hasSignal(got, SignalUAClaimsCrawler) || !hasSignal(got, SignalIPCrawlerListUnverified) {
		t.Fatalf("lista de outro operador: %+v", got)
	}
	// sem IP não há como verificar
	got = en.Evaluate(inputFrom(go1, uaGooglebot, netip.Addr{}))
	if !hasSignal(got, SignalUAClaimsCrawler) || got.Class == ClassGoodBot {
		t.Fatalf("sem IP: %+v", got)
	}
	// robô sem lista no catálogo (Yandex) não é conferido
	got = en.Evaluate(inputFrom(go1, "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", ipResidential))
	if hasSignal(got, SignalUAClaimsCrawler) {
		t.Fatalf("robô sem lista: %+v", got)
	}
	// good_bot prevalece sobre o score
	in := inputFrom(go1, uaGooglebot, ipGooglebot)
	in.Behavior = &Behavior{RequestsPerMin: 1000, RequestsHour: 100, ConnsHour: 100, PathsHour: 500}
	got = en.Evaluate(withView(in))
	if got.Class != ClassGoodBot || got.Score < scoreBot || got.Crawler != "googlebot" {
		t.Fatalf("good_bot com score alto: %+v", got)
	}
}

// spyVerifier conta as consultas (a prova por lista não deve consultar o DNS).
type spyVerifier struct {
	calls *int
	res   Verification
}

func (s spyVerifier) Verified(netip.Addr, string) Verification {
	*s.calls++
	return s.res
}

func TestCrawlerVerifiedByList(t *testing.T) {
	go1 := loadKnownClients(t).entry(t, "go", "h2")
	calls := 0
	en := goldenEngine(t, false)
	// mesmo um verificador que reprova não muda a prova por lista: ele nem é consultado
	en.Sources.Verifier = spyVerifier{calls: &calls, res: VerifyFailed}
	cases := []struct {
		name, ua string
		ip       netip.Addr
		good     bool
		crawler  string
	}{
		{"gptbot na lista", uaGPTBot, ipGPTBot, true, "gptbot"},
		{"oai-searchbot na lista da openai", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot", ipGPTBot, true, "oai-searchbot"},
		{"duckduckbot na lista", uaDuckDuckBot, ipDuckDuckBot, true, "duckduckbot"},
		{"gptbot fora da lista", uaGPTBot, ipResidential, false, ""},
		{"gptbot na lista do duckduckgo", uaGPTBot, ipDuckDuckBot, false, ""},
		{"duckduckbot na lista da openai", uaDuckDuckBot, ipGPTBot, false, ""},
	}
	for _, c := range cases {
		got := en.Evaluate(inputFrom(go1, c.ua, c.ip))
		if (got.Class == ClassGoodBot) != c.good || got.Crawler != c.crawler {
			t.Errorf("%s: %+v", c.name, got)
		}
		if c.good && (!hasSignal(got, SignalIPVerifiedCrawler) || hasSignal(got, SignalUAClaimsCrawler)) {
			t.Errorf("%s: sinais %v", c.name, signalIDs(got))
		}
		if !c.good && !hasSignal(got, SignalUAClaimsCrawler) {
			t.Errorf("%s: sem ua_claims_crawler: %v", c.name, signalIDs(got))
		}
	}
	if calls != 0 {
		t.Fatalf("CrawlerVerifier consultado %d vezes para operadores provados por lista", calls)
	}
	// Google continua exigindo o DNS: o verificador é consultado e a reprovação vale
	got := en.Evaluate(inputFrom(go1, uaGooglebot, ipGooglebot))
	if calls != 1 || got.Class == ClassGoodBot || !hasSignal(got, SignalUAClaimsCrawler) {
		t.Fatalf("googlebot sem DNS: chamadas %d, %+v", calls, got)
	}
	for op, byList := range map[string]bool{
		OperatorGoogle: false, OperatorBing: false, OperatorApple: false, OperatorOpenAI: true, OperatorDuckDuckGo: true,
		"": false,
	} {
		if VerifiedByList(op) != byList {
			t.Errorf("VerifiedByList(%q) != %v", op, byList)
		}
	}
}

func TestLibraryClient(t *testing.T) {
	base := loadKnownClients(t)
	en := goldenEngine(t, false)
	cases := []struct {
		name, client, proto, ua string
		want                    bool
	}{
		{"curl declara", "curl", "h2", "curl/8.23.0", true},
		{"java declara", "chrome", "h2", "okhttp/4.12.0", true},
		{"node declara", "chrome", "h2", "axios/1.7.7", true},
		{"ua vazio com ja4 de python", "python", "h1", "", true},
		{"ua other com ja4 de go", "go", "h2", "custom-agent/1.0", true},
		{"ua other com ja4 de chrome", "chrome", "h2", "custom-agent/1.0", false},
		{"chrome com ja4 de curl", "curl", "h2", goldenUA["chrome"], false},
		{"firefox com ja4 de go", "go", "h2", goldenUA["firefox"], false},
		{"headless com ja4 de curl", "curl", "h2", goldenUA["headless"], false},
		{"robô com ja4 de go", "go", "h2", uaGooglebot, false},
		{"robô genérico com ja4 de go", "go", "h2", "Mozilla/5.0 (compatible; FooBar-Bot/1.0)", false},
	}
	for _, c := range cases {
		got := en.Evaluate(inputFrom(base.entry(t, c.client, c.proto), c.ua, ipResidential))
		if hasSignal(got, SignalLibraryClient) != c.want {
			t.Errorf("%s: %v; quer library_client=%v", c.name, signalIDs(got), c.want)
		}
	}
	// JA4 que a base não conhece e base desligada: nada conclui
	in := inputFrom(base.entry(t, "go", "h2"), "", ipResidential)
	in.TLS.JA4 = "t13d0000h2_000000000000_000000000000"
	if got := en.Evaluate(in); hasSignal(got, SignalLibraryClient) {
		t.Errorf("ja4 desconhecido: %v", signalIDs(got))
	}
	if got := (Engine{}).Evaluate(inputFrom(base.entry(t, "go", "h2"), "", ipResidential)); hasSignal(got, SignalLibraryClient) {
		t.Errorf("sem base própria: %v", signalIDs(got))
	}
	// sem visão HTTP não há UA a julgar
	in = inputFrom(base.entry(t, "go", "h2"), "", ipResidential)
	in.HTTP = nil
	if got := en.Evaluate(withView(in)); hasSignal(got, SignalLibraryClient) {
		t.Errorf("sem HTTP: %v", signalIDs(got))
	}
}

func TestOSTCPMismatch(t *testing.T) {
	cases := []struct {
		ua   string
		p0f  string
		ttl  int
		want bool
	}{
		{uaChromeWin, "", 64, true},
		{uaChromeWin, "", 128, false},
		{uaChromeWin, "Windows 7 or 8", 64, false}, // o p0f decide antes do TTL
		{goldenUA["chrome"], "", 128, true},
		{goldenUA["chrome"], "", 255, false},
		{goldenUA["chrome"], "Windows NT kernel", 64, true},
		{goldenUA["chrome"], "iOS iPhone or iPad", 64, false},
		{goldenUA["chrome"], "???", 0, false},
		{"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", "Linux 3.11 and newer", 64, false},
		{"curl/8.0", "Windows 7 or 8", 128, false}, // UA sem SO
	}
	for _, c := range cases {
		in := withView(Input{HTTP: &HTTP{UserAgent: c.ua}, TCP: &TCP{P0fOS: c.p0f, TTLInitial: c.ttl}})
		if got := hasSignal(Engine{}.Evaluate(in), SignalUAOSTCPMismatch); got != c.want {
			t.Errorf("ua %.30q p0f %q ttl %d: %v; quer %v", c.ua, c.p0f, c.ttl, got, c.want)
		}
	}
}

func TestSignalTable(t *testing.T) {
	if len(signalTable) != 19 {
		t.Fatalf("%d sinais; a spec 018 (rules v1.2) tem 19", len(signalTable))
	}
	// os dois sinais da v1.1 entram logo antes de ja4db_match, com o tipo e o peso da ADR 0057 item 1
	pos := slices.IndexFunc(signalTable, func(d signalDef) bool { return d.id == SignalJA4DBMatch })
	if want := []signalDef{{SignalUAAutomation, KindList, 70}, {SignalLibraryClient, KindList, 50}}; pos < 2 ||
		!slices.Equal(signalTable[pos-2:pos], want) {
		t.Fatalf("ordem/pesos dos sinais da v1.1: %+v", signalTable[max(pos-2, 0):pos])
	}
	seen := map[string]bool{}
	for _, d := range signalTable {
		if seen[d.id] {
			t.Fatalf("id repetido %s", d.id)
		}
		seen[d.id] = true
		if w, ok := SignalWeight(d.id); !ok || w != d.weight {
			t.Fatalf("SignalWeight(%s)", d.id)
		}
	}
	if _, ok := SignalWeight("nope"); ok {
		t.Fatal("id desconhecido com peso")
	}
	if RulesVersion != "v1.3" {
		t.Fatalf("RulesVersion %q", RulesVersion)
	}
}

// TestAutomationNeverKnownClient: ADR 0058 item 5 (task 292) — UA de navegador com qualquer marcador de
// ua_automation nunca recebe known_client, mesmo com a pilha medida do Chrome/Firefox (e o JA4T com outro MSS, que
// na v1.2 casa a base); fica `bot` pelo ua_automation. O mesmo UA sem marcador recebe.
func TestAutomationNeverKnownClient(t *testing.T) {
	base := loadKnownClients(t)
	en := goldenEngine(t, false)
	for _, client := range []string{"chrome", "firefox"} {
		for _, proto := range []string{"h1", "h2", "h3"} {
			in := inputFrom(base.entry(t, client, proto), goldenUA[client], ipResidential)
			if in.TCP != nil {
				p := strings.Split(in.TCP.JA4T, "_")
				in.TCP.JA4T = p[0] + "_" + p[1] + "_1380_" + p[3]
			}
			if got := en.Evaluate(in); !hasSignal(got, SignalKnownClient) {
				t.Fatalf("%s %s sem marcador: sem known_client (%v)", client, proto, signalIDs(got))
			}
			for _, m := range automationMarkers {
				in.HTTP.UserAgent = goldenUA[client] + " " + m + "/1.0"
				got := en.Evaluate(in)
				if hasSignal(got, SignalKnownClient) || !hasSignal(got, SignalUAAutomation) || got.Class != ClassBot {
					t.Errorf("%s %s com %q: %s %v", client, proto, m, got.Class, signalIDs(got))
				}
			}
		}
	}
}

func hasSignal(r Result, id string) bool {
	for _, s := range r.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}
