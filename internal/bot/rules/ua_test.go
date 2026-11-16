package rules

import (
	"strings"
	"testing"
)

// UAs reais (ou no formato publicado pelo fabricante) das famílias da RF-06.
var uaCases = []struct {
	name, ua                    string
	family, major, os, operator string
	stack                       string
}{
	{"chrome macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36", "chrome", "157", "macos", "", "chrome"},
	{"chrome windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "chrome", "131", "windows", "", "chrome"},
	{"chrome android", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", "chrome", "131", "android", "", "chrome"},
	{"chrome ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1", "chrome", "131", "ios", "", "safari"},
	{"chrome linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", "chrome", "130", "linux", "", "chrome"},
	{"chromeos", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", "chrome", "130", "linux", "", "chrome"},
	{"opera is chromium", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0", "chrome", "130", "windows", "", "chrome"},
	{"firefox macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0", "firefox", "159", "macos", "", "firefox"},
	{"firefox linux", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0", "firefox", "133", "linux", "", "firefox"},
	{"firefox ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15", "firefox", "133", "ios", "", "safari"},
	{"safari macos", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", "safari", "18", "macos", "", "safari"},
	{"safari iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1", "safari", "18", "ios", "", "safari"},
	{"ios webview", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", "safari", "", "ios", "", "safari"},
	{"edge windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70", "edge", "131", "windows", "", "chrome"},
	{"edge android", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0", "edge", "131", "android", "", "chrome"},
	{"headless chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/157.0.0.0 Safari/537.36", "headless", "157", "macos", "", "headless"},
	{"curl", "curl/8.23.0", "curl", "8", "other", "", "curl"},
	{"curl old", "curl/7.88.1", "curl", "7", "other", "", "curl"},
	{"go h1", "Go-http-client/1.1", "go", "", "other", "", "go"},
	{"go h2", "Go-http-client/2.0", "go", "", "other", "", "go"},
	{"python-requests", "python-requests/2.32.3", "python", "2", "other", "", "python"},
	{"python urllib", "Python-urllib/3.12", "python", "3", "other", "", "python"},
	{"httpx", "python-httpx/0.27.2", "python", "0", "other", "", "python"},
	{"aiohttp", "Python/3.12 aiohttp/3.10.10", "python", "3", "other", "", "python"},
	{"java", "Java/17.0.12", "java", "17", "other", "", "java"},
	{"java httpclient", "Java-http-client/21.0.5", "java", "21", "other", "", "java"},
	{"apache httpclient", "Apache-HttpClient/4.5.14 (Java/17.0.12)", "java", "4", "other", "", "java"},
	{"okhttp", "okhttp/4.12.0", "java", "4", "other", "", "java"},
	{"node fetch", "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)", "node", "1", "other", "", "node"},
	{"axios", "axios/1.7.7", "node", "1", "other", "", "node"},
	{"undici", "undici", "node", "", "other", "", "node"},
	{"node", "node", "other", "", "other", "", "other"},
	{"googlebot desktop", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "crawler:googlebot", "", "other", "google", "crawler:googlebot"},
	{"googlebot smartphone", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "crawler:googlebot", "", "android", "google", "crawler:googlebot"},
	{"googlebot image", "Googlebot-Image/1.0", "crawler:googlebot", "", "other", "google", "crawler:googlebot"},
	{"google inspection", "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)", "crawler:google-inspectiontool", "", "other", "google", "crawler:google-inspectiontool"},
	{"googleother", "GoogleOther", "crawler:googleother", "", "other", "google", "crawler:googleother"},
	{"adsbot", "AdsBot-Google (+http://www.google.com/adsbot.html)", "crawler:adsbot-google", "", "other", "google", "crawler:adsbot-google"},
	{"mediapartners", "Mediapartners-Google", "crawler:mediapartners-google", "", "other", "google", "crawler:mediapartners-google"},
	{"storebot", "Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36", "crawler:storebot-google", "", "linux", "google", "crawler:storebot-google"},
	{"feedfetcher", "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)", "crawler:feedfetcher-google", "", "other", "google", "crawler:feedfetcher-google"},
	{"bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "crawler:bingbot", "", "other", "bing", "crawler:bingbot"},
	{"bingbot chrome", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36", "crawler:bingbot", "", "other", "bing", "crawler:bingbot"},
	{"applebot", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", "crawler:applebot", "", "macos", "apple", "crawler:applebot"},
	{"gptbot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot", "crawler:gptbot", "", "other", "openai", "crawler:gptbot"},
	{"oai-searchbot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot", "crawler:oai-searchbot", "", "other", "openai", "crawler:oai-searchbot"},
	{"chatgpt-user", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "crawler:chatgpt-user", "", "other", "openai", "crawler:chatgpt-user"},
	{"duckduckbot", "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", "crawler:duckduckbot", "", "other", "duckduckgo", "crawler:duckduckbot"},
	{"yandex", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "crawler:yandexbot", "", "other", "", "crawler:yandexbot"},
	{"generic bot", "Mozilla/5.0 (compatible; FooBar-Bot/1.0)", "crawler:other", "", "other", "", "crawler:other"},
	{"generic spider", "my-spider 0.1", "crawler:other", "", "other", "", "crawler:other"},
	{"empty", "", "other", "", "other", "", "other"},
	{"wget", "Wget/1.21.4", "other", "", "other", "", "other"},
}

func TestParseUA(t *testing.T) {
	for _, c := range uaCases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseUA(c.ua)
			if got.Family != c.family || got.Major != c.major || got.OS != c.os || got.Operator != c.operator ||
				got.Stack != c.stack {
				t.Fatalf("ParseUA(%q) = %+v; quer família %q versão %q SO %q operador %q pilha %q", c.ua, got,
					c.family, c.major, c.os, c.operator, c.stack)
			}
			if strings.HasPrefix(got.Family, FamilyCrawlerPrefix) != (got.Crawler != "") {
				t.Fatalf("Crawler %q incoerente com a família %q", got.Crawler, got.Family)
			}
		})
	}
}

// TestParseUAKnownClients confere que todo cliente medido na base própria tem um UA real nesta tabela que cai na
// mesma família (a base cresce pelo e2e; cliente novo sem UA aqui quebra o teste).
func TestParseUAKnownClients(t *testing.T) {
	base := loadKnownClients(t)
	families := map[string]bool{}
	for _, c := range uaCases {
		families[c.family] = true
	}
	for _, e := range base.Measured {
		if !families[e.Client] {
			t.Errorf("cliente %q de known_clients.json sem UA real com essa família em uaCases", e.Client)
		}
		if ua := goldenUA[e.Client]; ParseUA(ua).Family != e.Client {
			t.Errorf("UA do golden de %q cai em %q", e.Client, ParseUA(ua).Family)
		}
	}
}

func TestParseUALongInput(t *testing.T) {
	// o marcador depois de 512 bytes não conta (o índice guarda até 512 bytes)
	ua := strings.Repeat("x", maxUALen) + " curl/8.0"
	if got := ParseUA(ua); got.Family != FamilyOther {
		t.Fatalf("família %q; quer other", got.Family)
	}
}

var validFamilies = map[string]bool{
	FamilyChrome: true, FamilyFirefox: true, FamilySafari: true, FamilyEdge: true, FamilyCurl: true, FamilyGo: true,
	FamilyPython: true, FamilyJava: true, FamilyNode: true, FamilyHeadless: true, FamilyOther: true,
}

var validOS = map[string]bool{OSWindows: true, OSMacOS: true, OSLinux: true, OSAndroid: true, OSIOS: true, OSOther: true}

func validCrawlerName(n string) bool {
	if n == "other" {
		return true
	}
	for _, r := range crawlerTable {
		if r.name == n {
			return true
		}
	}
	return false
}

func FuzzParseUA(f *testing.F) {
	for _, c := range uaCases {
		f.Add(c.ua)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ua := ParseUA(s)
		if name, ok := strings.CutPrefix(ua.Family, FamilyCrawlerPrefix); ok {
			if !validCrawlerName(name) || name != ua.Crawler {
				t.Fatalf("robô inválido %+v", ua)
			}
		} else if !validFamilies[ua.Family] {
			t.Fatalf("família inválida %q", ua.Family)
		}
		if !validOS[ua.OS] {
			t.Fatalf("SO inválido %q", ua.OS)
		}
		if len(ua.Major) > 6 || strings.Trim(ua.Major, "0123456789") != "" {
			t.Fatalf("versão inválida %q", ua.Major)
		}
		if ua.Stack == "" {
			t.Fatal("pilha vazia")
		}
	})
}
