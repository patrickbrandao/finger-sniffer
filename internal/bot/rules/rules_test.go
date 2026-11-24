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

// TestNoImportOfBot: o pacote não importa internal/bot (sem ciclo) nem nada fora da stdlib, salvo o
// pkg/fingerprint/ja4 do espelho (derivação do JA4 stable, ADR 0072 item 1.2) e o pkg/fingerprint/ja4plus (JA4H do
// `ja4h_library` no pacote isolado da FoxIO License, ADR 0010, task 403).
func TestNoImportOfBot(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4":     true,
		"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus": true,
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, ".") && !allowed[imp] {
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
	// robô sem lista no catálogo (Yandex) não é conferido, mas se declara robô: com o JA4 de Go e o JA4H de
	// biblioteca sai `bot` (ADR 0072 item 2)
	got = en.Evaluate(inputFrom(go1, "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", ipResidential))
	if hasSignal(got, SignalUAClaimsCrawler) || got.Class != ClassBot || got.Score != 100 ||
		!hasSignal(got, SignalUADeclaresCrawler) || !hasSignal(got, SignalLibraryClient) {
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
		{"robô com operador e ja4 de go", "go", "h2", uaGooglebot, false},
		// robô sem operador: o JA4 que a base só viu em bibliotecas decide (ADR 0072 item 2.3)
		{"robô genérico com ja4 de go", "go", "h2", "Mozilla/5.0 (compatible; FooBar-Bot/1.0)", true},
		{"robô genérico com ja4 de chrome", "chrome", "h2", "Mozilla/5.0 (compatible; FooBar-Bot/1.0)", false},
		{"yandex com ja4 de go", "go", "h2", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", true},
		{"biblioteca com marcador de robô", "curl", "h2", "curl/8.23.0 mybot/1.0", true},
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
	if len(signalTable) != 23 {
		t.Fatalf("%d sinais; a spec 018 (rules v1.6) tem 23", len(signalTable))
	}
	// os dois sinais da v1.6 (ADR 0078) fecham a tabela, depois de route_breadth, comportamento de peso 10
	if want := []signalDef{{SignalRouteBreadth, KindBehavior, 15}, {SignalTTLTCPH3Mismatch, KindBehavior, 10}, {SignalRelayRTTGapAgg, KindBehavior, 10}}; !slices.Equal(signalTable[len(signalTable)-3:], want) {
		t.Fatalf("fim da tabela: %+v", signalTable[len(signalTable)-3:])
	}
	// relay_rtt_gap (v1.4, ADR 0065 item 3) entra logo depois de tunnel_mss, incoerência de peso 15
	if pos := slices.IndexFunc(signalTable, func(d signalDef) bool { return d.id == SignalTunnelMSS }); pos < 0 ||
		signalTable[pos+1] != (signalDef{SignalRelayRTTGap, KindIncoherence, 15}) {
		t.Fatalf("posição/peso de relay_rtt_gap: %+v", signalTable)
	}
	// os dois sinais da v1.1 (ADR 0057 item 1) e o ua_declares_crawler da v1.5 (ADR 0072 item 2.4, logo depois de
	// library_client) entram antes de ja4db_match
	pos := slices.IndexFunc(signalTable, func(d signalDef) bool { return d.id == SignalJA4DBMatch })
	if want := []signalDef{{SignalUAAutomation, KindList, 70}, {SignalLibraryClient, KindList, 50}, {SignalUADeclaresCrawler, KindList, 50}}; pos < 3 ||
		!slices.Equal(signalTable[pos-3:pos], want) {
		t.Fatalf("ordem/pesos dos sinais da v1.1 e v1.5: %+v", signalTable[max(pos-3, 0):pos])
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
	if RulesVersion != "v1.6" {
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

// TestRelayRTTGap: os limiares da ADR 0065 item 3 — gap > 20 ms e > 30% da volta TCP e primeiro byte depois de
// 10 ms; só em TCP (não em h3) e com as duas voltas e a espera conhecidas.
func TestRelayRTTGap(t *testing.T) {
	us := func(v int64) *int64 { return &v }
	cases := []struct {
		name string
		tm   *Timing
		h3   bool
		want bool
	}{
		{"relay", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(80_000)}, false, true},
		{"direct", &Timing{TCPRTTMicros: us(12_000), TLSRTTMicros: us(12_400), RTTGapMicros: us(400), EstToFirstMicros: us(1_000)}, false, false},
		{"gap at 15 ms", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(17_000), RTTGapMicros: us(15_000), EstToFirstMicros: us(30_000)}, false, false},
		{"gap at 16 ms", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(18_000), RTTGapMicros: us(16_000), EstToFirstMicros: us(30_000)}, false, true},
		{"gap below 30% of tcp", &Timing{TCPRTTMicros: us(100_000), TLSRTTMicros: us(125_000), RTTGapMicros: us(25_000), EstToFirstMicros: us(30_000)}, false, false},
		{"gap above 30% of tcp", &Timing{TCPRTTMicros: us(100_000), TLSRTTMicros: us(131_000), RTTGapMicros: us(31_000), EstToFirstMicros: us(30_000)}, false, true},
		{"first byte at 5 ms", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(5_000)}, false, false},
		{"first byte at 6 ms", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(6_000)}, false, true},
		{"negative first byte", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(-50)}, false, false},
		{"gap computed", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), EstToFirstMicros: us(80_000)}, false, true},
		{"no tcp rtt", &Timing{TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(80_000)}, false, false},
		{"no tls rtt", &Timing{TCPRTTMicros: us(2_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(80_000)}, false, false},
		{"no first byte", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000)}, false, false},
		{"huge values", &Timing{TCPRTTMicros: us(-1 << 62), TLSRTTMicros: us(1 << 62), EstToFirstMicros: us(80_000)}, false, false},
		{"h3", &Timing{TCPRTTMicros: us(2_000), TLSRTTMicros: us(82_000), RTTGapMicros: us(80_000), EstToFirstMicros: us(80_000)}, true, false},
		{"nil", nil, false, false},
	}
	for _, c := range cases {
		in := withView(Input{HTTP: &HTTP{UserAgent: goldenUA["chrome"]}, Timing: c.tm})
		in.View.H3 = c.h3
		res := Engine{}.Evaluate(in)
		if got := hasSignal(res, SignalRelayRTTGap); got != c.want {
			t.Errorf("%s: %v; quer %v (%+v)", c.name, got, c.want, res.Signals)
		}
	}
}

// TestTLSIdentity: o stable vem da entrada ou do JA4_r que reproduz o JA4 visto (ADR 0072 item 1.1); a parte b só
// em TCP.
func TestTLSIdentity(t *testing.T) {
	base := loadKnownClients(t)
	ch := base.entry(t, "chrome", "h2")
	id := tlsIdentity(&TLS{JA4: *ch.JA4, JA4R: *ch.JA4R})
	if id.stable == "" || id.stable == *ch.JA4 || id.ciphers != "8daaf6152771" || id.quic {
		t.Fatalf("chrome h2: %+v", id)
	}
	// o stable da entrada prevalece
	if id := tlsIdentity(&TLS{JA4: *ch.JA4, JA4R: *ch.JA4R, JA4Stable: "x"}); id.stable != "x" {
		t.Fatalf("stable da entrada: %+v", id)
	}
	// JA4_r de outro ClientHello (não reproduz o JA4 visto): sem stable
	other := base.entry(t, "curl", "h2")
	if id := tlsIdentity(&TLS{JA4: *ch.JA4, JA4R: *other.JA4R}); id.stable != "" {
		t.Fatalf("ja4_r de outro ClientHello: %+v", id)
	}
	// QUIC: sem a parte b
	q := base.entry(t, "chrome", "h3")
	if id := tlsIdentity(&TLS{JA4: *q.JA4}); id.ciphers != "" || !id.quic || id.stable != "" {
		t.Fatalf("chrome h3 sem ja4_r: %+v", id)
	}
	// QUIC sem stable não avalia o conjunto da família: JA4 `q` fora da base, só com o JA4 e UA de Chrome
	g := base.entry(t, "go", "h3")
	in := inputFrom(g, goldenUA["chrome"], ipResidential)
	in.TLS.JA4, in.TLS.JA4R = "q13d0313h3_55b375c5d22e_000000000000", ""
	if got := goldenEngine(t, false).Evaluate(in); slices.Contains(signalIDs(got), SignalUATLSMismatch) {
		t.Fatalf("QUIC sem stable: %v", signalIDs(got))
	}
	// a pilha só de biblioteca vale também sem stable, pelo JA4 completo (ADR 0072 item 3.1)
	in.TLS.JA4 = *g.JA4
	got := goldenEngine(t, false).Evaluate(in)
	if i := slices.IndexFunc(got.Signals, func(s Signal) bool { return s.ID == SignalUATLSMismatch }); i < 0 ||
		got.Signals[i].Detail != "ua chrome, ja4 of measured go" {
		t.Fatalf("QUIC de biblioteca sem stable: %+v", got.Signals)
	}
}

// TestOSClass: classe de SO do ttl_tcp_h3_mismatch (ADR 0078 item 1).
func TestOSClass(t *testing.T) {
	for os, want := range map[string]string{
		OSWindows: "windows", OSLinux: "unix", OSMacOS: "unix", OSAndroid: "unix", OSIOS: "unix", OSOther: "other", "": "other", "bsd": "other",
	} {
		if got := OSClass(os); got != want {
			t.Errorf("OSClass(%q) = %q; quer %q", os, got, want)
		}
	}
}

// TestRelayShape: a forma do relay de uma conexão para o agregado (ADR 0078 item 2), com a validação do relay_rtt_gap.
func TestRelayShape(t *testing.T) {
	p := ptr[int64]
	cases := []struct {
		name                    string
		t                       *Timing
		timed, gap, frac, first bool
	}{
		{"nil", nil, false, false, false, false},
		{"no tcp", &Timing{TLSRTTMicros: p(80_000), EstToFirstMicros: p(9_000)}, false, false, false, false},
		{"no est", &Timing{TCPRTTMicros: p(2_000), RTTGapMicros: p(80_000)}, false, false, false, false},
		{"no gap nor tls", &Timing{TCPRTTMicros: p(2_000), EstToFirstMicros: p(9_000)}, false, false, false, false},
		{"tls out of range", &Timing{TCPRTTMicros: p(2_000), TLSRTTMicros: p(1 << 41), EstToFirstMicros: p(9_000)}, false, false, false, false},
		{"relay", &Timing{TCPRTTMicros: p(2_000), TLSRTTMicros: p(82_000), RTTGapMicros: p(80_000), EstToFirstMicros: p(80_000)}, true, true, true, true},
		{"gap from tls", &Timing{TCPRTTMicros: p(20_000), TLSRTTMicros: p(31_000), EstToFirstMicros: p(5_000)}, true, true, true, false},
		{"gap at limit", &Timing{TCPRTTMicros: p(50_000), RTTGapMicros: p(10_000), EstToFirstMicros: p(5_001)}, true, false, false, true},
		{"direct", &Timing{TCPRTTMicros: p(12_000), TLSRTTMicros: p(12_400), RTTGapMicros: p(400), EstToFirstMicros: p(1_000)}, true, false, false, false},
	}
	for _, c := range cases {
		timed, gap, frac, first := RelayShape(c.t)
		if timed != c.timed || gap != c.gap || frac != c.frac || first != c.first {
			t.Errorf("%s: %v %v %v %v", c.name, timed, gap, frac, first)
		}
	}
}

// TestAggregateBehaviorSignals: limiares dos dois sinais da v1.6 (ADR 0078).
func TestAggregateBehaviorSignals(t *testing.T) {
	ev := func(b Behavior, ua string) Result {
		return Engine{}.Evaluate(withView(Input{HTTP: &HTTP{UserAgent: ua}, Behavior: &b}))
	}
	win := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	relay := func(n, g, f, s int) Behavior {
		return Behavior{TimedConnsHour: n, RelayGapConnsHour: g, RelayFracConnsHour: f, RelayFirstConnsHour: s}
	}
	for _, c := range []struct {
		b    Behavior
		want bool
	}{
		{relay(5, 3, 3, 3), true},
		{relay(4, 4, 4, 4), false},
		{relay(6, 3, 6, 6), false},
		{relay(6, 6, 3, 6), false},
		{relay(6, 6, 6, 3), false},
		{relay(65535, 65535, 65535, 65535), true},
	} {
		if got := hasSignal(ev(c.b, win), SignalRelayRTTGapAgg); got != c.want {
			t.Errorf("relay %+v: %v", c.b, got)
		}
	}
	ttl := func(seen ...TTLSeen) Behavior { return Behavior{TTLSeen: seen} }
	for _, c := range []struct {
		name string
		b    Behavior
		ua   string
		want bool
	}{
		{"disjoint", ttl(TTLSeen{OS: "windows", TCP: []int{64}, H3: []int{128}}), win, true},
		{"no h3", ttl(TTLSeen{OS: "windows", TCP: []int{64, 128}}), win, false},
		{"no tcp", ttl(TTLSeen{OS: "windows", H3: []int{128}}), win, false},
		{"overlap", ttl(TTLSeen{OS: "windows", TCP: []int{64, 128}, H3: []int{128}}), win, false},
		{"other class", ttl(TTLSeen{OS: "unix", TCP: []int{64}, H3: []int{128}}), win, false},
		{"no ua os", ttl(TTLSeen{OS: "other", TCP: []int{64}, H3: []int{128}}), "curl/8.0", true},
	} {
		if got := hasSignal(ev(c.b, c.ua), SignalTTLTCPH3Mismatch); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	// sem visão HTTP a classe é other
	r := Engine{}.Evaluate(withView(Input{Behavior: &Behavior{TTLSeen: []TTLSeen{{OS: "other", TCP: []int{128}, H3: []int{64}}}}}))
	if !hasSignal(r, SignalTTLTCPH3Mismatch) || r.Signals[0].Detail != "ua os other: initial ttl tcp [128], h3 [64] in the hour" {
		t.Errorf("sem http: %+v", r.Signals)
	}
}
