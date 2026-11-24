package rules

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
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
	uaChatGPTUser = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
	// Selenium conduzindo um Chrome de verdade, com o marcador no UA
	uaSelenium  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Selenium/4.27.0"
	uaChromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
	// UAs de Safari e do iOS: a pilha declarada é a do Safari, que a base própria não mede (ADR 0072 item 3)
	uaSafariMac    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
	uaCriOS        = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1"
	uaSafariIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
	// robôs sem operador (ADR 0072 item 2)
	uaYandexBot  = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
	uaExampleBot = "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://example.com/bot)"
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

	// v1.4 (ADR 0065 item 3): tempos do traefix em TCP; direto, gap ~0 e primeiro byte em 1 ms; por relay, gap e
	// espera de 80 ms (a volta cliente ↔ relay) com a volta TCP de 2 ms (traefix ↔ relay)
	direct := &Timing{TCPRTTMicros: ptr[int64](12_000), TLSRTTMicros: ptr[int64](12_400), RTTGapMicros: ptr[int64](400), EstToFirstMicros: ptr[int64](1_000)}
	relay := &Timing{TCPRTTMicros: ptr[int64](2_000), TLSRTTMicros: ptr[int64](82_000), RTTGapMicros: ptr[int64](80_000), EstToFirstMicros: ptr[int64](80_000)}
	chromeDirect := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	chromeDirect.Timing = direct
	chromeRelay := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	chromeRelay.Timing = relay
	curlRelay := inputFrom(e("curl", "h2"), ua["curl"], ipResidential)
	curlRelay.Timing = relay

	// v1.6 (ADR 0078 item 2): relay agregado na hora pelas contagens de conexões cronometradas que passam cada limiar
	relayAgg := func(timed, gap, frac, first int) Input {
		in := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
		in.Behavior = &Behavior{
			RequestsPerMin: 2, RequestsHour: 2 * timed, ConnsHour: timed, PathsHour: 3, StaticsHour: 1,
			TimedConnsHour: timed, RelayGapConnsHour: gap, RelayFracConnsHour: frac, RelayFirstConnsHour: first,
		}
		return withView(in)
	}
	// v1.6 (ADR 0078 item 1): TTLs iniciais de TCP e h3 da hora, por classe de SO do UA
	ttlSeen := func(client, proto, uaStr string, seen ...TTLSeen) Input {
		in := inputFrom(e(client, proto), uaStr, ipResidential)
		in.Behavior = &Behavior{RequestsPerMin: 2, RequestsHour: 12, ConnsHour: 4, PathsHour: 3, StaticsHour: 1, TTLSeen: seen}
		return withView(in)
	}

	// v1.5 (ADR 0072 item 1): a retomada TLS 1.3 acrescenta pre_shared_key (0029) ao ClientHello; o JA4 muda, o
	// stable não
	chromeResumed := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	chromeResumed.TLS.JA4R = withExtension(t, chromeResumed.TLS.JA4R, "0029")
	chromeResumed.TLS.JA4 = fromRaw(t, chromeResumed.TLS.JA4R)
	chromeResumedHeader := inputFrom(e("chrome", "h2"), ua["chrome"], ipResidential)
	chromeResumedHeader.TLS.JA4, chromeResumedHeader.TLS.JA4R = chromeResumed.TLS.JA4, ""
	// Chrome no Windows do golden FoxIO (test/golden/pcaps/windows-foxio.ja4.jsonl): mesmas cifras do Chrome medido no
	// macOS, outras extensões, sem o ja4_r
	chromeWin := inputFrom(e("chrome", "h2"), uaChromeWin, ipResidential)
	chromeWin.TLS.JA4, chromeWin.TLS.JA4R = ja4ChromeWindowsFoxIO, ""
	chromeWin.TCP.P0fOS, chromeWin.TCP.TTLInitial = "", windowsTTL
	chromeWinVPN := inputFrom(e("chrome", "h2"), uaChromeWin, ipCloud)
	chromeWinVPN.TLS.JA4, chromeWinVPN.TLS.JA4R = ja4ChromeWindowsFoxIO, ""
	chromeWinVPN.TCP.P0fOS, chromeWinVPN.TCP.TTLInitial = "", windowsTTL
	chromeWinVPN.TCP.JA4T = "65535_2-1-3-1-1-8-4-0-0_1360_6"
	chromeWinVPN.TCP.MSSReduction, chromeWinVPN.TCP.MTUImplied = ptr(100), ptr(1400)
	curlUAChromeHeader := inputFrom(e("curl", "h2"), ua["chrome"], ipResidential)
	curlUAChromeHeader.TLS.JA4R = ""

	// v1.5 (ADR 0072 item 3): biblioteca com UA de iPhone e Accept-Language, de IP de nuvem
	goIPhoneAL := inputFrom(e("go", "h2"), uaSafariIPhone, ipCloud)
	goIPhoneAL.HTTP.HasAcceptLanguage = true

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
		// casos novos da v1.4 (ADR 0065 item 3): relay pelos tempos do traefix; o peso baixo não muda a classe do Chrome
		{"chrome_direct_timing", chromeDirect, false, ClassHuman, []string{SignalKnownClient}},
		{"chrome_relay", chromeRelay, false, ClassHuman, []string{SignalRelayRTTGap, SignalKnownClient}},
		// task 365: o ChatGPT-User da faixa própria (na Azure) é provado pela lista do marcador, não sai ua_claims_crawler
		{"chatgpt_user_list", inputFrom(e("go", "h2"), uaChatGPTUser, ipChatGPTUser), false, ClassGoodBot, []string{SignalJA4HLibrary, SignalIPCloud, SignalIPVerifiedCrawler}},
		{"curl_relay", curlRelay, false, ClassBot, []string{SignalJA4HLibrary, SignalRelayRTTGap, SignalLibraryClient}},
		// casos novos da v1.5 (ADR 0072 item 5): identidade TLS pelo JA4 stable e, em TCP, pela parte b
		{"chrome_resumed", chromeResumed, false, ClassHuman, []string{SignalKnownClient}},
		{"chrome_resumed_header_only", chromeResumedHeader, false, ClassHuman, nil},
		{"chrome_windows_foxio", chromeWin, false, ClassHuman, nil},
		{"chrome_windows_foxio_vpn", chromeWinVPN, false, ClassHuman, []string{SignalTunnelMSS, SignalIPCloud}},
		{"curl_ua_chrome_header_only", curlUAChromeHeader, false, ClassBot, []string{SignalUATLSMismatch, SignalUAH2Mismatch, SignalJA4HLibrary}},
		{"go_h3_ua_chrome", inputFrom(e("go", "h3"), ua["chrome"], ipResidential), false, ClassSuspect, []string{SignalUATLSMismatch, SignalJA4HLibrary}},
		{"firefox_ua_chrome_stack", inputFrom(e("chrome", "h2"), ua["firefox"], ipResidential), false, ClassHuman, []string{SignalUAH2Mismatch}},
		// casos novos da v1.5 (ADR 0072 item 3): pilha de biblioteca com UA de Safari ou do iOS, sem medida do Safari
		{"curl_ua_safari", inputFrom(e("curl", "h2"), uaSafariMac, ipResidential), false, ClassBot, []string{SignalUATLSMismatch, SignalUAH2Mismatch, SignalJA4HLibrary}},
		{"go_ua_crios", inputFrom(e("go", "h2"), uaCriOS, ipResidential), false, ClassBot, []string{SignalUATLSMismatch, SignalUAH2Mismatch, SignalJA4HLibrary}},
		{"go_ua_iphone_accept_language", goIPhoneAL, false, ClassBot, []string{SignalUATLSMismatch, SignalUAH2Mismatch, SignalIPCloud}},
		// casos novos da v1.5 (ADR 0072 item 2): robô declarado sem operador
		{"yandexbot_unverifiable", inputFrom(e("go", "h2"), uaYandexBot, ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient, SignalUADeclaresCrawler}},
		{"curl_ua_bot_token", inputFrom(e("curl", "h2"), "curl/8.23.0 mybot/1.0", ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient, SignalUADeclaresCrawler}},
		{"python_ua_crawler_token", inputFrom(e("python", "h1"), "python-requests/2.32.3 (+crawler)", ipResidential), false, ClassBot, []string{SignalJA4HLibrary, SignalLibraryClient, SignalUADeclaresCrawler}},
		{"crawler_other_chrome_stack", inputFrom(e("chrome", "h2"), uaExampleBot, ipResidential), false, ClassSuspect, []string{SignalUADeclaresCrawler}},
		// casos novos da v1.6 (ADR 0078): relay agregado e TTL de TCP × h3 na hora
		{"relay_agg_fires", relayAgg(10, 7, 7, 8), false, ClassHuman, []string{SignalKnownClient, SignalRelayRTTGapAgg}},
		{"relay_agg_below_min", relayAgg(4, 4, 4, 4), false, ClassHuman, []string{SignalKnownClient}},
		{"relay_agg_minority", relayAgg(10, 5, 9, 9), false, ClassHuman, []string{SignalKnownClient}},
		{"ttl_tcp_h3_disjoint", ttlSeen("chrome", "h3", uaChromeWin, TTLSeen{OS: OSClassWindows, TCP: []int{64}, H3: []int{128}}), false, ClassHuman, []string{SignalKnownClient, SignalTTLTCPH3Mismatch}},
		{"ttl_tcp_h3_overlap", ttlSeen("chrome", "h3", ua["chrome"], TTLSeen{OS: OSClassUnix, TCP: []int{64, 128}, H3: []int{64}}), false, ClassHuman, []string{SignalKnownClient}},
		{"ttl_tcp_h3_other_class", ttlSeen("chrome", "h3", ua["chrome"], TTLSeen{OS: OSClassWindows, TCP: []int{64}, H3: []int{128}}), false, ClassHuman, []string{SignalKnownClient}},
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

// ja4ChromeWindowsFoxIO é o JA4 do Chrome no Windows do golden FoxIO (test/golden/pcaps/windows-foxio.ja4.jsonl).
const ja4ChromeWindowsFoxIO = "t13d1516h2_8daaf6152771_e5627efa2ab1"

// withExtension acrescenta uma extensão ao JA4_r (na ordem, como o JA4_r guarda) e soma um na contagem da parte a.
func withExtension(t testing.TB, raw, ext string) string {
	t.Helper()
	p := strings.Split(raw, "_")
	if len(p) < 3 || len(p[0]) != 10 {
		t.Fatalf("ja4_r %q", raw)
	}
	n, err := strconv.Atoi(p[0][6:8])
	if err != nil {
		t.Fatal(err)
	}
	p[0] = fmt.Sprintf("%s%02d%s", p[0][:6], n+1, p[0][8:])
	exts := append(strings.Split(p[2], ","), ext)
	slices.Sort(exts)
	p[2] = strings.Join(exts, ",")
	return strings.Join(p, "_")
}

// fromRaw devolve o JA4 recalculado do JA4_r (ja4.FromRaw).
func fromRaw(t testing.TB, raw string) string {
	t.Helper()
	j, _, ok := ja4.FromRaw(raw)
	if !ok {
		t.Fatalf("ja4.FromRaw(%q)", raw)
	}
	return j
}
