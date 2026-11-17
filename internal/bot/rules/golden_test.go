package rules

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

var update = flag.Bool("update", false, "regrava os goldens de veredito em testdata/golden")

// goldenUA é o User-Agent de cada cliente medido em known_clients.json.
var goldenUA = map[string]string{
	"chrome":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
	"firefox":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0",
	"curl":     "curl/8.23.0",
	"go":       "Go-http-client/2.0",
	"python":   "python-requests/2.32.3",
	"headless": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/157.0.0.0 Safari/537.36",
}

const (
	uaGooglebot   = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	uaBingbot     = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
	uaGPTBot      = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"
	uaDuckDuckBot = "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
	// Selenium conduzindo um Chrome de verdade, com o marcador no UA
	uaSelenium  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Selenium/4.27.0"
	uaChromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
)

func deref[T any](p *T) T {
	var z T
	if p == nil {
		return z
	}
	return *p
}

var protoVersion = map[string]string{"h1": "1.1", "h2": "2", "h3": "3"}

// inputFrom monta a entrada a partir de uma medida da base própria, como o bot montaria com as duas visões.
func inputFrom(e knownEntry, ua string, ip netip.Addr) Input {
	in := Input{IP: ip}
	if e.JA4T != nil {
		in.TCP = &TCP{P0fOS: deref(e.P0fOS), TTLInitial: deref(e.TTLInitial), JA4T: *e.JA4T}
	}
	in.TLS = &TLS{JA4: deref(e.JA4), JA4R: deref(e.JA4R), ALPN: e.ALPN}
	if e.Akamai != nil {
		in.H2 = &H2{Akamai: *e.Akamai}
	}
	ab := deref(e.JA4HAB)
	// sem cookies: partes c e d do JA4H zeradas
	in.HTTP = &HTTP{
		UserAgent: ua, Version: protoVersion[e.Proto], JA4H: ab + "_000000000000_000000000000",
		HasAcceptLanguage: len(ab) >= 12 && ab[8:12] != "0000",
	}
	in.View.H3 = e.Proto == "h3"
	return withView(in)
}

// probeFrom é a medida da base aberta pelo probe (caso (a) da spec 020, ADR 0060): a ordem real dos campos do
// cliente com o Origin (ou o Referer, nos navegadores) de um domínio da chave, e o JA4H medido dessa ordem.
func probeFrom(e knownEntry, ua string, ip netip.Addr, fields []string) Input {
	in := inputFrom(e, ua, ip)
	in.HTTP.JA4H = measuredJA4H("GET", e.Proto, fields)
	in.HTTP.FieldOrder = fields
	return in
}

// withView preenche a visão pelo que há na entrada (o H3 vem de quem monta).
func withView(in Input) Input {
	in.View.TCP, in.View.TLS, in.View.HTTP = in.TCP != nil, in.TLS != nil, in.HTTP != nil
	in.View.H2, in.View.Behavior = in.H2 != nil, in.Behavior != nil
	return in
}

type goldenCase struct {
	name    string
	in      Input
	ja4db   bool
	class   string
	signals []string
}

func goldenCases(t testing.TB) []goldenCase {
	base := loadKnownClients(t)
	e := func(client, proto string) knownEntry { return base.entry(t, client, proto) }
	ua := goldenUA

	curlLoop := inputFrom(e("curl", "h2"), ua["curl"], ipCloud)
	// 500 requisições numa hora, cada uma numa conexão, a cada 0,5 s ± 1 ms, 400 caminhos sem estáticos
	curlLoop.Behavior = &Behavior{
		RequestsPerMin: 300, RequestsHour: 500, ConnsHour: 500,
		IntervalN: 499, IntervalSum: 499 * 0.5, IntervalSqSum: 499 * (0.25 + 0.000001), PathsHour: 400,
	}
	curlLoop = withView(curlLoop)

	chromeUACurlTLS := inputFrom(e("curl", "h2"), ua["chrome"], ipResidential)

	winTTL := inputFrom(e("chrome", "h2"), uaChromeWin, ipResidential)
	winTTL.TCP.P0fOS = "Linux 3.11 and newer"

	tunnel := inputFrom(e("firefox", "h2"), ua["firefox"], ipResidential)
	tunnel.TCP.MSSReduction, tunnel.TCP.MTUImplied = ptr(40), ptr(1460)

	noUA := inputFrom(e("python", "h1"), "", ipResidential)

	tcpOnly := withView(Input{IP: ipResidential, TCP: inputFrom(e("curl", "h1"), "", ipResidential).TCP})

	forkOnly := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	forkOnly.TCP = nil
	forkOnly = withView(forkOnly)

	googleUAChrome := inputFrom(e("chrome", "h2"), ua["chrome"], ipGooglebot)

	// v1.2 (ADR 0058 item 4): o MSS do SYN muda com o caminho (grampo), a janela, as opções e a escala não
	chromeMSS := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	chromeMSS.TCP.JA4T = "65535_2-1-3-1-1-8-4-0-0_1460_6"
	firefoxWindow := inputFrom(e("firefox", "h2"), ua["firefox"], ipResidential)
	firefoxWindow.TCP.JA4T = "64240_2-1-3-1-1-8-4-0-0_1430_6"

	return []goldenCase{
		// as classes da ADR 0057 item 1 (rules v1.1; ja4db desligada, ADR 0056 item 1)
		{"curl", inputFrom(e("curl", "h2"), ua["curl"], ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"curl_h1", inputFrom(e("curl", "h1"), ua["curl"], ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"curl_h3", inputFrom(e("curl", "h3"), ua["curl"], ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"go", inputFrom(e("go", "h2"), ua["go"], ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"python_requests", inputFrom(e("python", "h1"), ua["python"], ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"chrome", inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential), false, ClassHuman, []string{SignalKnownClient}},
		{"firefox", inputFrom(e("firefox", "h2"), ua["firefox"], ipResidential), false, ClassHuman, []string{SignalKnownClient}},
		{"chrome_headless", inputFrom(e("headless", "h2"), ua["headless"], ipResidential), false, ClassBot, []string{SignalUAAutomation}},
		{"googlebot_fake", inputFrom(e("curl", "h2"), uaGooglebot, ipFakeGoogle), false, ClassBot, []string{SignalJA4HLibrary, SignalUAClaimsCrawler}},
		{"gptbot_list", inputFrom(e("go", "h2"), uaGPTBot, ipGPTBot), false, ClassGoodBot, []string{SignalJA4HLibrary, SignalIPVerifiedCrawler}},
		{"gptbot_off_list", inputFrom(e("go", "h2"), uaGPTBot, ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalUAClaimsCrawler}},
		{"ua_missing", noUA, false, ClassBot, []string{SignalUAMissing, SignalJA4HLibrary, SignalLibraryClient}},
		// casos novos da v1.1
		{"ua_other_go_ja4", inputFrom(e("go", "h2"), "custom-agent/1.0", ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"selenium_chrome_ua", inputFrom(e("chrome", "h2"), uaSelenium, ipResidential), false, ClassBot, []string{SignalUAAutomation}},
		{"duckduckbot_list", inputFrom(e("go", "h2"), uaDuckDuckBot, ipDuckDuckBot), false, ClassGoodBot, []string{SignalJA4HLibrary, SignalIPVerifiedCrawler}},
		// mais casos para cobrir os 19 sinais e as bordas
		{"chrome_h3", inputFrom(e("chrome", "h3"), ua["chrome"], ipResidential), false, ClassHuman, []string{SignalKnownClient}},
		{"chrome_h1_alpn", inputFrom(e("chrome", "h1"), ua["chrome"], ipResidential), false, ClassHuman, []string{SignalUAH2Mismatch, SignalUAALPNMismatch, SignalKnownClient}},
		{"chrome_ua_curl_tls", chromeUACurlTLS, false, ClassBot, []string{SignalUATLSMismatch, SignalUAH2Mismatch, SignalJA4HLibrary}},
		{"chrome_windows_ttl64", winTTL, false, ClassHuman, []string{SignalUAOSTCPMismatch, SignalKnownClient}},
		{"firefox_tunnel", tunnel, false, ClassHuman, []string{SignalTunnelMSS, SignalKnownClient}},
		{"python_ja4db", inputFrom(e("python", "h1"), ua["python"], ipResidential), true, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient, SignalJA4DBMatch}},
		{"chrome_ja4db", inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential), true, ClassHuman, []string{SignalKnownClient}},
		{"googlebot_verified", inputFrom(e("go", "h2"), uaGooglebot, ipGooglebot), false, ClassGoodBot, []string{SignalJA4HLibrary, SignalIPVerifiedCrawler}},
		{"googlebot_ipv4_mapped", inputFrom(e("go", "h2"), uaGooglebot, netip.AddrFrom16(ipGooglebot.As16())), false, ClassGoodBot, []string{SignalJA4HLibrary, SignalIPVerifiedCrawler}},
		{"bingbot_dns_failed", inputFrom(e("go", "h2"), uaBingbot, ipBingbot), false, ClassBot, []string{SignalJA4HLibrary, SignalUAClaimsCrawler, SignalIPCrawlerListUnverified}},
		{"google_ip_chrome_ua", googleUAChrome, false, ClassHuman, []string{SignalKnownClient, SignalIPCrawlerListUnverified}},
		{"curl_cloud_loop", curlLoop, false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient, SignalIPCloud, SignalRateHigh, SignalNoReuse, SignalIntervalRegular, SignalRouteBreadth}},
		{"tcp_only", tcpOnly, false, ClassUnknown, nil},
		{"fork_only_no_tcp", forkOnly, false, ClassHuman, []string{SignalKnownClient}},
		// casos novos da v1.2
		{"chrome_other_mss", chromeMSS, false, ClassHuman, []string{SignalKnownClient}},
		{"firefox_other_window", firefoxWindow, false, ClassHuman, nil},
		// casos novos da v1.3 (ADR 0060 item 1): o caminho do probe, com Origin nas bibliotecas e Referer nos navegadores
		{"curl_probe", probeFrom(e("curl", "h2"), ua["curl"], ipResidential, curlProbeFields), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"go_probe", probeFrom(e("go", "h2"), ua["go"], ipResidential, goProbeFields), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"python_requests_probe", probeFrom(e("python", "h1"), ua["python"], ipResidential, pythonProbeFields), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient}},
		{"googlebot_fake_probe", probeFrom(e("curl", "h2"), uaGooglebot, ipFakeGoogle, curlProbeFields), false, ClassBot, []string{SignalJA4HLibrary, SignalUAClaimsCrawler}},
		{"ua_missing_probe", probeFrom(e("python", "h1"), "", ipResidential, pythonProbeFields), false, ClassBot, []string{SignalUAMissing, SignalJA4HLibrary, SignalLibraryClient}},
		{"chrome_probe", probeFrom(e("chrome", "h2"), ua["chrome"], ipResidential, chromeProbeFields), false, ClassHuman, []string{SignalKnownClient}},
		{"firefox_probe", probeFrom(e("firefox", "h2"), ua["firefox"], ipResidential, firefoxProbeFields), false, ClassHuman, []string{SignalKnownClient}},
	}
}

func goldenEngine(t testing.TB, ja4db bool) Engine {
	base := loadKnownClients(t)
	en := Engine{Sources: Sources{Known: fakeKnown{base.Measured}, IPs: testIPs(), Verifier: testVerifier()}}
	if ja4db {
		en.Sources.JA4DB = loadJA4DBSample(t)
	}
	return en
}

func signalIDs(r Result) []string {
	ids := []string{}
	for _, s := range r.Signals {
		ids = append(ids, s.ID)
	}
	return ids
}

// sortedByTable ordena ids pela ordem da tabela (a ordem estável da saída).
func sortedByTable(ids []string) []string {
	out := slices.Clone(ids)
	pos := func(id string) int {
		return slices.IndexFunc(signalTable, func(d signalDef) bool { return d.id == id })
	}
	slices.SortFunc(out, func(a, b string) int { return pos(a) - pos(b) })
	if out == nil {
		out = []string{}
	}
	return out
}

func TestGoldenVerdicts(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range goldenCases(t) {
		t.Run(c.name, func(t *testing.T) {
			en := goldenEngine(t, c.ja4db)
			got := en.Evaluate(c.in)
			if got.Class != c.class {
				t.Errorf("classe %q (score %d, sinais %v); quer %q", got.Class, got.Score, signalIDs(got), c.class)
			}
			if want := sortedByTable(c.signals); !slices.Equal(signalIDs(got), want) {
				t.Errorf("sinais %v; quer %v", signalIDs(got), want)
			}
			for _, s := range got.Signals {
				seen[s.ID] = true
			}
			// RF-05: mesma entrada e versões, mesmo veredito
			if again := en.Evaluate(c.in); !reflect.DeepEqual(again, got) {
				t.Fatalf("veredito não determinístico: %+v × %+v", got, again)
			}
			compareGolden(t, c, got)
		})
	}
	for _, d := range signalTable {
		if !seen[d.id] {
			t.Errorf("sinal %s sem golden", d.id)
		}
	}
}

type goldenFile struct {
	RulesVersion string `json:"rules_version"`
	JA4DB        bool   `json:"ja4db"`
	Input        Input  `json:"input"`
	Result       Result `json:"result"`
}

func compareGolden(t *testing.T, c goldenCase, got Result) {
	t.Helper()
	path := filepath.Join("testdata", "golden", c.name+".json")
	b, err := json.MarshalIndent(goldenFile{RulesVersion: RulesVersion, JA4DB: c.ja4db, Input: c.in, Result: got}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (rode com -update)", err)
	}
	if !bytes.Equal(want, b) {
		t.Fatalf("golden %s difere (regrave com -update e revise):\n%s", path, b)
	}
}

func ptr[T any](v T) *T { return &v }
