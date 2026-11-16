package rules

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Classes do veredito (ADR 0049 item 3).
const (
	ClassHuman   = "human"
	ClassGoodBot = "good_bot"
	ClassBot     = "bot"
	ClassSuspect = "suspect"
	ClassUnknown = "unknown"
)

// Tipos de sinal (schema Signal do openapi do bot).
const (
	KindIncoherence = "incoherence"
	KindList        = "list"
	KindBehavior    = "behavior"
)

// Ids estáveis dos sinais (spec 018, tabela "Pesos iniciais"), na ordem em que aparecem no veredito.
const (
	SignalUAMissing               = "ua_missing"
	SignalUATLSMismatch           = "ua_tls_mismatch"
	SignalUAH2Mismatch            = "ua_h2_mismatch"
	SignalUAOSTCPMismatch         = "ua_os_tcp_mismatch"
	SignalUAALPNMismatch          = "ua_alpn_mismatch"
	SignalJA4HLibrary             = "ja4h_library"
	SignalTunnelMSS               = "tunnel_mss"
	SignalUAClaimsCrawler         = "ua_claims_crawler"
	SignalJA4DBMatch              = "ja4db_match"
	SignalKnownClient             = "known_client"
	SignalIPVerifiedCrawler       = "ip_verified_crawler"
	SignalIPCloud                 = "ip_cloud"
	SignalIPCrawlerListUnverified = "ip_crawler_list_unverified"
	SignalRateHigh                = "rate_high"
	SignalNoReuse                 = "no_reuse"
	SignalIntervalRegular         = "interval_regular"
	SignalRouteBreadth            = "route_breadth"
)

// signalDef é uma linha da tabela de pesos (rules v1.0, provisórios).
type signalDef struct {
	id     string
	kind   string
	weight int
}

// signalTable é a tabela da spec 018 na ordem estável da saída.
var signalTable = []signalDef{
	{SignalUAMissing, KindIncoherence, 30},
	{SignalUATLSMismatch, KindIncoherence, 45},
	{SignalUAH2Mismatch, KindIncoherence, 30},
	{SignalUAOSTCPMismatch, KindIncoherence, 25},
	{SignalUAALPNMismatch, KindIncoherence, 15},
	{SignalJA4HLibrary, KindIncoherence, 20},
	{SignalTunnelMSS, KindIncoherence, 5},
	{SignalUAClaimsCrawler, KindIncoherence, 60},
	{SignalJA4DBMatch, KindList, 40},
	{SignalKnownClient, KindList, -20},
	{SignalIPVerifiedCrawler, KindList, 0},
	{SignalIPCloud, KindList, 20},
	{SignalIPCrawlerListUnverified, KindList, 0},
	{SignalRateHigh, KindBehavior, 25},
	{SignalNoReuse, KindBehavior, 10},
	{SignalIntervalRegular, KindBehavior, 20},
	{SignalRouteBreadth, KindBehavior, 15},
}

// Limiares (spec 018, tabela de pesos; ADR 0049 item 3).
const (
	// DefaultRateHigh é o padrão de FS_BOT_RATE_HIGH (requisições/min do IP no site).
	DefaultRateHigh      = 120
	scoreBot             = 70
	scoreSuspect         = 40
	noReuseMinRequests   = 10
	intervalMinN         = 20
	intervalMaxCV        = 0.1
	routeMinPaths        = 50
	routeMaxStaticPct    = 5
	detailMaxLen         = 160
	unixTTL, windowsTTL  = 64, 128
	fullMTU              = 1500
	ja4dbNameMaxLen      = 48
	providerNameMaxLen   = 32
	ja4hPartsForBaseLook = 2
)

// Signal é um sinal presente no veredito (schema Signal do openapi do bot).
type Signal struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Result é a saída das regras; quem chama completa o Verdict (view, versões, sujeito, horário).
type Result struct {
	Class   string   `json:"class"`
	Score   int      `json:"score"`
	Signals []Signal `json:"signals"`
	// Crawler é o nome do robô verificado (só com `good_bot`).
	Crawler string `json:"crawler,omitempty"`
	// UAFamily e UAOS são o que a RF-06 extraiu do User-Agent ("" sem visão HTTP).
	UAFamily string `json:"ua_family,omitempty"`
	UAOS     string `json:"ua_os,omitempty"`
}

// Engine avalia as regras v1 sobre as fontes dadas. O valor zero vale (sem listas, limiar padrão).
type Engine struct {
	Sources Sources
	// RateHigh é FS_BOT_RATE_HIGH; 0 usa DefaultRateHigh.
	RateHigh int
}

// eval junta os sinais presentes de uma avaliação.
type eval struct {
	present map[string]string
}

func (e *eval) add(id, detail string) {
	if len(detail) > detailMaxLen {
		detail = detail[:detailMaxLen]
	}
	e.present[id] = detail
}

// Evaluate aplica as regras v1 (ADR 0049). Função pura: a mesma entrada com as mesmas fontes dá o mesmo resultado.
func (en Engine) Evaluate(in Input) Result {
	ev := &eval{present: map[string]string{}}
	var ua UA
	if in.HTTP != nil {
		ua = ParseUA(in.HTTP.UserAgent)
	}
	en.incoherence(ev, in, ua)
	good, crawler := en.lists(ev, in, ua)
	en.behavior(ev, in.Behavior)

	res := Result{Signals: []Signal{}}
	sum := 0
	for _, d := range signalTable {
		detail, ok := ev.present[d.id]
		if !ok {
			continue
		}
		sum += d.weight
		res.Signals = append(res.Signals, Signal{ID: d.id, Kind: d.kind, Weight: d.weight, Detail: detail})
	}
	res.Score = min(max(sum, 0), 100)
	if in.HTTP != nil {
		res.UAFamily, res.UAOS = ua.Family, ua.OS
	}
	res.Class = classify(res.Score, good, in.View)
	if good {
		res.Crawler = crawler
	}
	return res
}

// classify aplica a ADR 0049 item 3: `good_bot` prevalece; depois o score; `human` exige TLS e HTTP na visão.
func classify(score int, good bool, v View) string {
	switch {
	case good:
		return ClassGoodBot
	case score >= scoreBot:
		return ClassBot
	case score >= scoreSuspect:
		return ClassSuspect
	case v.TLS && v.HTTP:
		return ClassHuman
	}
	return ClassUnknown
}

// browserLike diz se o UA se apresenta como navegador (o headless é um Chrome automatizado e herda as checagens).
func browserLike(ua UA) bool {
	return IsBrowserFamily(ua.Family) || ua.Family == FamilyHeadless
}

// incoherence avalia os sinais de incoerência do UA com as outras camadas.
func (en Engine) incoherence(ev *eval, in Input, ua UA) {
	if in.HTTP != nil && strings.TrimSpace(in.HTTP.UserAgent) == "" {
		ev.add(SignalUAMissing, "no user-agent")
	}
	if in.HTTP != nil && browserLike(ua) {
		en.browserChecks(ev, in, ua)
	}
	if in.HTTP != nil && in.TCP != nil {
		osTCP(ev, ua, in.TCP)
	}
	if in.HTTP != nil && !in.HTTP.HasAcceptLanguage && en.Sources.Known != nil {
		if ab := ja4hAB(in.HTTP.JA4H); ab != "" {
			if lib := firstLibrary(en.Sources.Known.Families(KindJA4HAB, ab)); lib != "" {
				ev.add(SignalJA4HLibrary, "ja4h "+ab+" of "+lib+", no accept-language")
			}
		}
	}
	if t := in.TCP; t != nil {
		switch {
		case t.MSSReduction != nil && *t.MSSReduction > 0:
			ev.add(SignalTunnelMSS, fmt.Sprintf("mss reduced by %d", *t.MSSReduction))
		case t.MTUImplied != nil && *t.MTUImplied < fullMTU:
			ev.add(SignalTunnelMSS, fmt.Sprintf("implied mtu %d", *t.MTUImplied))
		}
	}
}

// browserChecks avalia TLS, h2 e ALPN de um UA de navegador contra a pilha esperada.
func (en Engine) browserChecks(ev *eval, in Input, ua UA) {
	known := en.Sources.Known
	if in.TLS != nil && in.TLS.JA4 != "" {
		ja4 := in.TLS.JA4
		measured := known != nil && known.Measured(ua.Stack, KindJA4)
		inBase := measured && slices.Contains(known.Families(KindJA4, ja4), ua.Stack)
		label, hasLabel := JA4DBLabel{}, false
		if en.Sources.JA4DB != nil {
			label, hasLabel = en.Sources.JA4DB.Label(ja4)
		}
		inDB := hasLabel && label.Kind == JA4DBBrowser && labelNames(label.Name, ua.Stack)
		if (measured || hasLabel) && !inBase && !inDB {
			ev.add(SignalUATLSMismatch, "ua "+ua.Family+", ja4 "+ja4+" not in "+ua.Stack+" set")
		}
	}
	isQUIC := in.TLS != nil && strings.HasPrefix(in.TLS.JA4, "q")
	if in.H2 != nil && in.H2.Akamai != "" && known != nil && known.Measured(ua.Stack, KindAkamai) &&
		!slices.Contains(known.Families(KindAkamai, in.H2.Akamai), ua.Stack) {
		ev.add(SignalUAH2Mismatch, "ua "+ua.Family+", akamai not in "+ua.Stack+" set")
	} else if in.TLS != nil && !isQUIC && strings.HasPrefix(in.HTTP.Version, "1") && !slices.Contains(in.TLS.ALPN, "h2") {
		ev.add(SignalUAH2Mismatch, "ua "+ua.Family+", http/"+in.HTTP.Version+" without h2 in alpn")
	}
	if in.TLS != nil && !isQUIC && !slices.Contains(in.TLS.ALPN, "h2") {
		ev.add(SignalUAALPNMismatch, "ua "+ua.Family+", alpn ["+strings.Join(in.TLS.ALPN, ",")+"] without h2")
	}
}

// labelNames diz se o nome rotulado na ja4db é da família (o Chromium conta como Chrome).
func labelNames(name, family string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, family) {
		return true
	}
	return family == FamilyChrome && strings.Contains(n, "chromium")
}

// osTCP compara o SO do UA com o p0f e o TTL inicial (ua_os_tcp_mismatch).
func osTCP(ev *eval, ua UA, t *TCP) {
	if ua.OS == OSOther {
		return
	}
	// com palpite do p0f (que já considera o TTL) ele decide; sem palpite, vale o TTL inicial
	if p := p0fOS(t.P0fOS); p != "" {
		if !osCompatible(ua.OS, p) {
			ev.add(SignalUAOSTCPMismatch, "ua os "+ua.OS+", p0f "+p)
		}
		return
	}
	if t.TTLInitial == 0 {
		return
	}
	// Windows sai com TTL 128; os sistemas tipo Unix (Linux, Android, macOS, iOS) com 64
	if (ua.OS == OSWindows && t.TTLInitial == unixTTL) || (ua.OS != OSWindows && t.TTLInitial == windowsTTL) {
		ev.add(SignalUAOSTCPMismatch, fmt.Sprintf("ua os %s, initial ttl %d", ua.OS, t.TTLInitial))
	}
}

// p0fOS reduz o `os` do p0f a um SO da RF-06; "" quando não há palpite útil.
func p0fOS(s string) string {
	l := strings.ToLower(s)
	switch {
	case l == "" || l == "???":
		return ""
	case strings.HasPrefix(l, "windows"):
		return OSWindows
	case strings.HasPrefix(l, "ios"):
		return OSIOS
	case strings.HasPrefix(l, "android"):
		return OSAndroid
	case strings.HasPrefix(l, "mac os"):
		return OSMacOS
	case strings.HasPrefix(l, "linux"):
		return OSLinux
	}
	return ""
}

// osCompatible diz se o SO medido pelo p0f é compatível com o declarado no UA. O p0f não separa bem macOS de iOS nem
// Android de Linux.
func osCompatible(uaOS, p0f string) bool {
	switch uaOS {
	case OSMacOS, OSIOS:
		return p0f == OSMacOS || p0f == OSIOS
	case OSAndroid:
		return p0f == OSAndroid || p0f == OSLinux
	case OSLinux:
		return p0f == OSLinux || p0f == OSAndroid
	}
	return uaOS == p0f
}

// ja4hAB devolve as partes a e b do JA4H ("" quando não há as duas).
func ja4hAB(ja4h string) string {
	parts := strings.SplitN(ja4h, "_", ja4hPartsForBaseLook+1)
	if len(parts) < ja4hPartsForBaseLook || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "_" + parts[1]
}

// firstLibrary devolve a primeira família de biblioteca (em ordem alfabética, para ser estável).
func firstLibrary(families []string) string {
	libs := []string{}
	for _, f := range families {
		if IsLibraryFamily(f) {
			libs = append(libs, f)
		}
	}
	if len(libs) == 0 {
		return ""
	}
	slices.Sort(libs)
	return libs[0]
}

// lists avalia os sinais de lista; devolve se é `good_bot` e o nome do robô.
func (en Engine) lists(ev *eval, in Input, ua UA) (good bool, crawler string) {
	src := en.Sources
	if in.TLS != nil && in.TLS.JA4 != "" && src.JA4DB != nil {
		if l, ok := src.JA4DB.Label(in.TLS.JA4); ok && (l.Kind == JA4DBLibrary || l.Kind == JA4DBTool) {
			ev.add(SignalJA4DBMatch, "ja4db "+l.Kind+" "+truncate(l.Name, ja4dbNameMaxLen))
		}
	}
	if in.HTTP != nil && IsBrowserFamily(ua.Family) && in.TLS != nil && in.TLS.JA4 != "" && src.Known != nil {
		akamai, ja4t := "", ""
		if in.H2 != nil {
			akamai = in.H2.Akamai
		}
		if in.TCP != nil {
			ja4t = in.TCP.JA4T
		}
		if slices.Contains(src.Known.Coherent(in.TLS.JA4, akamai, ja4t), ua.Stack) {
			ev.add(SignalKnownClient, "coherent with measured "+ua.Stack)
		}
	}
	ip := in.IP.Unmap()
	if !ip.IsValid() {
		// sem IP não há lista a conferir: o UA de robô verificável não se confirma
		if ua.Operator != "" {
			ev.add(SignalUAClaimsCrawler, "ua "+ua.Crawler+", no source ip to verify")
		}
		return false, ""
	}
	listOp, inList := "", false
	if src.IPs != nil {
		if p, ok := src.IPs.Cloud(ip); ok {
			ev.add(SignalIPCloud, "cloud "+truncate(p, providerNameMaxLen))
		}
		listOp, inList = src.IPs.Crawler(ip)
	}
	verify := VerifyUnknown
	if ua.Operator != "" && inList && listOp == ua.Operator && src.Verifier != nil {
		verify = src.Verifier.Verified(ip, ua.Operator)
	}
	good = ua.Operator != "" && inList && listOp == ua.Operator && verify == VerifyPassed
	switch {
	case good:
		ev.add(SignalIPVerifiedCrawler, ua.Crawler+" verified ("+ua.Operator+")")
	case inList:
		ev.add(SignalIPCrawlerListUnverified, "in "+listOp+" crawler list, verification "+unverifiedReason(ua, listOp, verify))
	}
	if ua.Operator != "" && !good {
		switch {
		case !inList || listOp != ua.Operator:
			ev.add(SignalUAClaimsCrawler, "ua "+ua.Crawler+", ip not in "+ua.Operator+" list")
		case verify == VerifyFailed:
			ev.add(SignalUAClaimsCrawler, "ua "+ua.Crawler+", reverse/forward dns failed")
		}
	}
	if good {
		return true, ua.Crawler
	}
	return false, ""
}

// unverifiedReason explica por que um IP de lista de robô não virou `good_bot`.
func unverifiedReason(ua UA, listOp string, v Verification) string {
	if ua.Operator != listOp {
		return "ua does not declare it"
	}
	return v.String()
}

// behavior avalia os sinais de comportamento (agregados por IP + site, ADR 0052).
func (en Engine) behavior(ev *eval, b *Behavior) {
	if b == nil {
		return
	}
	limit := en.RateHigh
	if limit <= 0 {
		limit = DefaultRateHigh
	}
	if b.RequestsPerMin > limit {
		ev.add(SignalRateHigh, fmt.Sprintf("%d requests/min > %d", b.RequestsPerMin, limit))
	}
	if b.RequestsHour >= noReuseMinRequests && b.ConnsHour >= b.RequestsHour {
		ev.add(SignalNoReuse, fmt.Sprintf("%d requests on %d connections in the hour", b.RequestsHour, b.ConnsHour))
	}
	if b.IntervalN >= intervalMinN && b.IntervalSum > 0 {
		n := float64(b.IntervalN)
		mean := b.IntervalSum / n
		sd := math.Sqrt(math.Max(b.IntervalSqSum/n-mean*mean, 0))
		if cv := sd / mean; cv < intervalMaxCV {
			ev.add(SignalIntervalRegular, fmt.Sprintf("%d intervals, cv %.3f", b.IntervalN, cv))
		}
	}
	if b.PathsHour >= routeMinPaths && b.StaticsHour*100 < b.PathsHour*routeMaxStaticPct {
		ev.add(SignalRouteBreadth, fmt.Sprintf("%d paths, %d static in the hour", b.PathsHour, b.StaticsHour))
	}
}

// truncate corta s em n bytes.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SignalWeight devolve o peso v1 do sinal (false para id desconhecido).
func SignalWeight(id string) (int, bool) {
	for _, d := range signalTable {
		if d.id == id {
			return d.weight, true
		}
	}
	return 0, false
}
