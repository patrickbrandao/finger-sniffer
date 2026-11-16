package rules

import "strings"

// Famílias de User-Agent (spec 018 RF-06). Robôs usam FamilyCrawlerPrefix + nome.
const (
	FamilyChrome        = "chrome"
	FamilyFirefox       = "firefox"
	FamilySafari        = "safari"
	FamilyEdge          = "edge"
	FamilyCurl          = "curl"
	FamilyGo            = "go"
	FamilyPython        = "python"
	FamilyJava          = "java"
	FamilyNode          = "node"
	FamilyHeadless      = "headless"
	FamilyOther         = "other"
	FamilyCrawlerPrefix = "crawler:"
)

// Sistemas operacionais do User-Agent (spec 018 RF-06).
const (
	OSWindows = "windows"
	OSMacOS   = "macos"
	OSLinux   = "linux"
	OSAndroid = "android"
	OSIOS     = "ios"
	OSOther   = "other"
)

// Operadores de robôs verificáveis (ADR 0050 item 3). As listas de IP e a verificação de DNS (task 278) devolvem
// um destes nomes para dizer de quem é a faixa ou o nome reverso.
const (
	OperatorGoogle     = "google"
	OperatorBing       = "bing"
	OperatorApple      = "apple"
	OperatorOpenAI     = "openai"
	OperatorDuckDuckGo = "duckduckgo"
)

// maxUALen limita o que o parser lê do User-Agent (o índice guarda até 512 bytes, ADR 0056 item 3).
const maxUALen = 512

// UA é o que as regras extraem do User-Agent.
type UA struct {
	// Family é uma das famílias da RF-06 (`crawler:<nome>` para robôs).
	Family string
	// Major é a versão principal do cliente ("" quando o UA não traz versão do cliente).
	Major string
	// OS é o SO declarado (OSOther quando o UA não diz).
	OS string
	// Crawler é o nome do robô (o que vem depois de `crawler:`), "" para não robôs.
	Crawler string
	// Operator é o dono do robô verificável (OperatorGoogle...), "" quando o robô não tem lista nem DNS a conferir.
	Operator string
	// Stack é a família cuja pilha de rede (TLS, h2) o cliente usa: no iOS todo navegador usa a do Safari.
	Stack string
}

// crawlerRule associa um marcador (minúsculo) do UA ao nome do robô e ao operador.
type crawlerRule struct {
	token, name, operator string
}

// crawlerTable vem antes das famílias de navegador: o UA de robô costuma trazer `Chrome/` e `Safari/` também.
// A ordem importa: o marcador mais específico primeiro.
var crawlerTable = []crawlerRule{
	{"adsbot-google-mobile", "adsbot-google-mobile", OperatorGoogle},
	{"adsbot-google", "adsbot-google", OperatorGoogle},
	{"mediapartners-google", "mediapartners-google", OperatorGoogle},
	{"storebot-google", "storebot-google", OperatorGoogle},
	{"google-inspectiontool", "google-inspectiontool", OperatorGoogle},
	{"googleother", "googleother", OperatorGoogle},
	{"google-cloudvertexbot", "google-cloudvertexbot", OperatorGoogle},
	{"apis-google", "apis-google", OperatorGoogle},
	{"feedfetcher-google", "feedfetcher-google", OperatorGoogle},
	{"google-read-aloud", "google-read-aloud", OperatorGoogle},
	{"google-site-verification", "google-site-verification", OperatorGoogle},
	{"googleproducer", "googleproducer", OperatorGoogle},
	{"googlebot", "googlebot", OperatorGoogle},
	{"bingpreview", "bingpreview", OperatorBing},
	{"adidxbot", "adidxbot", OperatorBing},
	{"microsoftpreview", "microsoftpreview", OperatorBing},
	{"bingbot", "bingbot", OperatorBing},
	{"applebot", "applebot", OperatorApple},
	{"oai-searchbot", "oai-searchbot", OperatorOpenAI},
	{"chatgpt-user", "chatgpt-user", OperatorOpenAI},
	{"gptbot", "gptbot", OperatorOpenAI},
	{"duckassistbot", "duckassistbot", OperatorDuckDuckGo},
	{"duckduckgo-favicons-bot", "duckduckgo-favicons-bot", OperatorDuckDuckGo},
	{"duckduckbot", "duckduckbot", OperatorDuckDuckGo},
	// robôs sem lista de IP no catálogo: reconhecidos, mas sem verificação
	{"yandexbot", "yandexbot", ""},
	{"baiduspider", "baiduspider", ""},
	{"ahrefsbot", "ahrefsbot", ""},
	{"semrushbot", "semrushbot", ""},
	{"mj12bot", "mj12bot", ""},
	{"dotbot", "dotbot", ""},
	{"petalbot", "petalbot", ""},
	{"bytespider", "bytespider", ""},
	{"claudebot", "claudebot", ""},
	{"ccbot", "ccbot", ""},
	{"facebookexternalhit", "facebookexternalhit", ""},
	{"twitterbot", "twitterbot", ""},
	{"linkedinbot", "linkedinbot", ""},
	{"slackbot", "slackbot", ""},
}

// genericCrawlerTokens marcam um robô genérico (`crawler:other`): o nome não vem do UA para não abrir cardinalidade
// livre nos agregados por família.
var genericCrawlerTokens = []string{"bot/", "bot;", "bot)", "crawler", "spider", "scraper"}

// familyRule associa um marcador do UA à família e ao marcador de onde sai a versão ("" = sem versão do cliente).
type familyRule struct {
	token, family, version string
}

// familyTable na ordem de teste: derivados do Chromium (Edge) antes do Chrome, Chrome antes do Safari (o UA do Chrome
// traz `Safari/`), bibliotecas por último.
var familyTable = []familyRule{
	{"headlesschrome/", FamilyHeadless, "headlesschrome/"},
	{"phantomjs/", FamilyHeadless, "phantomjs/"},
	{"edg/", FamilyEdge, "edg/"},
	{"edga/", FamilyEdge, "edga/"},
	{"edgios/", FamilyEdge, "edgios/"},
	{"edge/", FamilyEdge, "edge/"},
	{"fxios/", FamilyFirefox, "fxios/"},
	{"firefox/", FamilyFirefox, "firefox/"},
	{"crios/", FamilyChrome, "crios/"},
	{"chrome/", FamilyChrome, "chrome/"},
	{"chromium/", FamilyChrome, "chromium/"},
	{"curl/", FamilyCurl, "curl/"},
	{"go-http-client/", FamilyGo, ""},
	{"python-requests/", FamilyPython, "python-requests/"},
	{"python-urllib/", FamilyPython, "python-urllib/"},
	{"python-httpx/", FamilyPython, "python-httpx/"},
	{"aiohttp/", FamilyPython, "aiohttp/"},
	{"python/", FamilyPython, "python/"},
	{"apache-httpclient/", FamilyJava, "apache-httpclient/"},
	{"okhttp/", FamilyJava, "okhttp/"},
	{"java/", FamilyJava, "java/"},
	{"java-http-client/", FamilyJava, "java-http-client/"},
	{"node-fetch", FamilyNode, "node-fetch/"},
	{"axios/", FamilyNode, "axios/"},
	{"undici", FamilyNode, "undici/"},
	{"node.js", FamilyNode, "node.js/"},
	{"node/", FamilyNode, "node/"},
}

// ParseUA extrai família, versão principal e SO do User-Agent (spec 018 RF-06). Nunca falha: UA vazio ou
// desconhecido dá FamilyOther e OSOther.
func ParseUA(raw string) UA {
	if len(raw) > maxUALen {
		raw = raw[:maxUALen]
	}
	s := strings.ToLower(raw)
	ua := UA{Family: FamilyOther, OS: parseOS(s)}
	if s == "" {
		ua.Stack = ua.Family
		return ua
	}
	if name, op, ok := matchCrawler(s); ok {
		ua.Family, ua.Crawler, ua.Operator = FamilyCrawlerPrefix+name, name, op
		ua.Stack = ua.Family
		return ua
	}
	ua.Family, ua.Major = matchFamily(s)
	ua.Stack = ua.Family
	// o Edge usa a pilha de rede do Chromium
	if ua.Family == FamilyEdge {
		ua.Stack = FamilyChrome
	}
	// no iOS todo navegador usa o WebKit e a pilha de rede do sistema: TLS e h2 são os do Safari
	if ua.OS == OSIOS && IsBrowserFamily(ua.Family) {
		ua.Stack = FamilySafari
	}
	return ua
}

// matchCrawler procura um robô conhecido e, sem ele, um marcador genérico.
func matchCrawler(s string) (name, operator string, ok bool) {
	for _, r := range crawlerTable {
		if strings.Contains(s, r.token) {
			return r.name, r.operator, true
		}
	}
	for _, t := range genericCrawlerTokens {
		if strings.Contains(s, t) {
			return "other", "", true
		}
	}
	return "", "", false
}

// matchFamily acha a família pela tabela e, para o Safari, exige `Version/` e `Safari/` sem Chrome.
func matchFamily(s string) (family, major string) {
	for _, r := range familyTable {
		if strings.Contains(s, r.token) {
			if r.version == "" {
				return r.family, ""
			}
			return r.family, versionAfter(s, r.version)
		}
	}
	if strings.Contains(s, "safari/") && strings.Contains(s, "version/") {
		return FamilySafari, versionAfter(s, "version/")
	}
	// Safari do iOS em WebView (sem `Version/`) ainda é a pilha do Safari
	if strings.Contains(s, "applewebkit/") && strings.Contains(s, "mobile/") {
		return FamilySafari, ""
	}
	return FamilyOther, ""
}

// versionAfter devolve os dígitos logo depois do marcador (até 6), "" sem dígitos.
func versionAfter(s, token string) string {
	i := strings.Index(s, token)
	if i < 0 {
		return ""
	}
	rest := s[i+len(token):]
	n := 0
	for n < len(rest) && n < 6 && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	return rest[:n]
}

// parseOS lê o SO declarado; iOS e Android antes de macOS e Linux, cujos marcadores eles também trazem.
func parseOS(s string) string {
	switch {
	case strings.Contains(s, "windows"):
		return OSWindows
	case strings.Contains(s, "iphone"), strings.Contains(s, "ipad"), strings.Contains(s, "ipod"),
		strings.Contains(s, "cpu os "), strings.Contains(s, "ios "):
		return OSIOS
	case strings.Contains(s, "android"):
		return OSAndroid
	case strings.Contains(s, "macintosh"), strings.Contains(s, "mac os x"), strings.Contains(s, "darwin"):
		return OSMacOS
	case strings.Contains(s, "linux"), strings.Contains(s, "x11"), strings.Contains(s, "cros "):
		return OSLinux
	}
	return OSOther
}

// IsBrowserFamily diz se a família é de navegador (os sinais de incoerência de navegador valem para ela).
func IsBrowserFamily(f string) bool {
	switch f {
	case FamilyChrome, FamilyFirefox, FamilySafari, FamilyEdge:
		return true
	}
	return false
}

// IsLibraryFamily diz se a família é de biblioteca ou ferramenta de linha de comando.
func IsLibraryFamily(f string) bool {
	switch f {
	case FamilyCurl, FamilyGo, FamilyPython, FamilyJava, FamilyNode:
		return true
	}
	return false
}
