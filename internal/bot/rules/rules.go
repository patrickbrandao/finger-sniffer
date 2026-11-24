package rules

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
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

// Ids estáveis dos sinais (spec 018, tabela "Pesos (rules v1.6)"), na ordem em que aparecem no veredito.
const (
	SignalUAMissing               = "ua_missing"
	SignalUATLSMismatch           = "ua_tls_mismatch"
	SignalUAH2Mismatch            = "ua_h2_mismatch"
	SignalUAOSTCPMismatch         = "ua_os_tcp_mismatch"
	SignalUAALPNMismatch          = "ua_alpn_mismatch"
	SignalJA4HLibrary             = "ja4h_library"
	SignalTunnelMSS               = "tunnel_mss"
	SignalRelayRTTGap             = "relay_rtt_gap"
	SignalUAClaimsCrawler         = "ua_claims_crawler"
	SignalUAAutomation            = "ua_automation"
	SignalLibraryClient           = "library_client"
	SignalUADeclaresCrawler       = "ua_declares_crawler"
	SignalJA4DBMatch              = "ja4db_match"
	SignalKnownClient             = "known_client"
	SignalIPVerifiedCrawler       = "ip_verified_crawler"
	SignalIPCloud                 = "ip_cloud"
	SignalIPCrawlerListUnverified = "ip_crawler_list_unverified"
	SignalRateHigh                = "rate_high"
	SignalNoReuse                 = "no_reuse"
	SignalIntervalRegular         = "interval_regular"
	SignalRouteBreadth            = "route_breadth"
	SignalTTLTCPH3Mismatch        = "ttl_tcp_h3_mismatch"
	SignalRelayRTTGapAgg          = "relay_rtt_gap_agg"
)

// signalDef é uma linha da tabela de pesos (rules v1.6, provisórios; ADRs 0049, 0057, 0058, 0060, 0065, 0072 e 0078).
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
	{SignalRelayRTTGap, KindIncoherence, 15},
	{SignalUAClaimsCrawler, KindIncoherence, 60},
	{SignalUAAutomation, KindList, 70},
	{SignalLibraryClient, KindList, 50},
	{SignalUADeclaresCrawler, KindList, 50},
	{SignalJA4DBMatch, KindList, 40},
	{SignalKnownClient, KindList, -20},
	{SignalIPVerifiedCrawler, KindList, 0},
	{SignalIPCloud, KindList, 20},
	{SignalIPCrawlerListUnverified, KindList, 0},
	{SignalRateHigh, KindBehavior, 25},
	{SignalNoReuse, KindBehavior, 10},
	{SignalIntervalRegular, KindBehavior, 20},
	{SignalRouteBreadth, KindBehavior, 15},
	{SignalTTLTCPH3Mismatch, KindBehavior, 10},
	{SignalRelayRTTGapAgg, KindBehavior, 10},
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
	// relay_rtt_gap (ADR 0065 item 3 e adendo): volta TLS acima da TCP em mais de 15 ms e de 30% dela, com o
	// primeiro byte do cliente depois de mais de 5 ms do accept
	relayMinGapMicros   = 15_000
	relayMinGapFrac     = 0.3
	relayMinFirstMicros = 5_000
	// relay_rtt_gap_agg (ADR 0078 item 2): n mínimo de conexões cronometradas na hora e o limiar do rtt_gap do
	// agregado; a fração (0,3) e o primeiro byte (5 ms) são os de relayMinGapFrac e relayMinFirstMicros
	relayAggMinConns     = 5
	relayAggMinGapMicros = 10_000
)

// Classes de SO do UA para o ttl_tcp_h3_mismatch (ADR 0078 item 1).
const (
	OSClassWindows = "windows"
	OSClassUnix    = "unix"
	OSClassOther   = "other"
)

// OSClass reduz o SO do UA (RF-06) à classe do ttl_tcp_h3_mismatch: "windows"; "unix" para Linux, macOS, Android e
// iOS; "other" para o resto e para "" (sem visão HTTP).
func OSClass(os string) string {
	switch os {
	case OSWindows:
		return OSClassWindows
	case OSLinux, OSMacOS, OSAndroid, OSIOS:
		return OSClassUnix
	}
	return OSClassOther
}

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

// Engine avalia as regras v1.6 (ADR 0078) sobre as fontes dadas. O valor zero vale (sem listas, limiar padrão).
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

// Evaluate aplica as regras v1.6 (ADRs 0049, 0057, 0058, 0060, 0065, 0072 e 0078). Função pura: a mesma entrada com as mesmas fontes dá o mesmo
// resultado.
func (en Engine) Evaluate(in Input) Result {
	ev := &eval{present: map[string]string{}}
	var ua UA
	if in.HTTP != nil {
		ua = ParseUA(in.HTTP.UserAgent)
	}
	en.incoherence(ev, in, ua)
	good, crawler := en.lists(ev, in, ua)
	en.behavior(ev, in.Behavior, ua)

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
		en.ja4hLibrary(ev, in.HTTP)
	}
	if t := in.TCP; t != nil {
		switch {
		case t.MSSReduction != nil && *t.MSSReduction > 0:
			ev.add(SignalTunnelMSS, fmt.Sprintf("mss reduced by %d", *t.MSSReduction))
		case t.MTUImplied != nil && *t.MTUImplied < fullMTU:
			ev.add(SignalTunnelMSS, fmt.Sprintf("implied mtu %d", *t.MTUImplied))
		}
	}
	if !in.View.H3 {
		relayGap(ev, in.Timing)
	}
}

// relayGap avalia relay_rtt_gap (ADR 0065 item 3): atrás de um relay (SOCKS5, HTTP CONNECT, relay TCP) o kernel mede
// a volta TCP com o relay, enquanto a volta TLS e a espera pelo primeiro byte incluem o caminho cliente ↔ relay. Só
// em TCP e com as duas voltas conhecidas; a diferença é o rtt_gap do traefix, ou TLS − TCP sem ele.
func relayGap(ev *eval, t *Timing) {
	if t == nil || t.TLSRTTMicros == nil {
		return // a v1.5 exige a volta TLS mesmo com o rtt_gap do traefix
	}
	tcp, gap, est, ok := relayTimes(t)
	if ok && gap > relayMinGapMicros && float64(gap) > float64(tcp)*relayMinGapFrac && est > relayMinFirstMicros {
		ev.add(SignalRelayRTTGap, fmt.Sprintf("rtt gap %s ms, tcp rtt %s ms, first byte after %s ms", ms(gap), ms(tcp), ms(est)))
	}
}

// relayTimes valida os tempos da conexão como o relay_rtt_gap: tcp_rtt_us e est_to_first_us conhecidos e o rtt_gap
// do traefix ou, sem ele, tls_rtt_us para calculá-lo (fora de qualquer medida real = não medido).
func relayTimes(t *Timing) (tcp, gap, est int64, ok bool) {
	if t == nil || t.TCPRTTMicros == nil || t.EstToFirstMicros == nil {
		return 0, 0, 0, false
	}
	tcp, est = *t.TCPRTTMicros, *t.EstToFirstMicros
	if t.RTTGapMicros != nil {
		return tcp, *t.RTTGapMicros, est, true
	}
	if t.TLSRTTMicros == nil || outOfRange(tcp) || outOfRange(*t.TLSRTTMicros) {
		return 0, 0, 0, false // a subtração poderia estourar
	}
	return tcp, *t.TLSRTTMicros - tcp, est, true
}

// RelayShape diz se a conexão tem tempos (timed) e se passa cada limiar do agregado (ADR 0078 item 2).
// gap: rtt_gap > relayAggMinGapMicros; frac: rtt_gap > relayMinGapFrac·tcp_rtt; first: est_to_first > relayMinFirstMicros.
func RelayShape(t *Timing) (timed, gap, frac, first bool) {
	tcp, g, est, ok := relayTimes(t)
	if !ok {
		return false, false, false, false
	}
	return true, g > relayAggMinGapMicros, float64(g) > float64(tcp)*relayMinGapFrac, est > relayMinFirstMicros
}

// outOfRange diz se um tempo em microssegundos passa de ±2^40 (~12 dias).
func outOfRange(us int64) bool { return us > 1<<40 || us < -(1<<40) }

// ms escreve microssegundos em milissegundos com uma casa.
func ms(us int64) string { return strconv.FormatFloat(float64(us)/1000, 'f', 1, 64) }

// tlsID é a identidade TLS que as regras comparam com a base própria (ADR 0072 item 1): o JA4 completo, o stable
// (da entrada ou derivado do JA4_r) e a parte b do JA4 (cifras), esta só em TCP.
type tlsID struct {
	ja4, stable, ciphers string
	quic                 bool
}

// tlsIdentity monta a identidade TLS da entrada. O stable derivado do JA4_r só vale quando o JA4_r reproduz o JA4
// visto (o mesmo ClientHello, como a validação da base, ADR 0072 item 1.3).
func tlsIdentity(t *TLS) tlsID {
	id := tlsID{ja4: t.JA4, stable: t.JA4Stable, quic: strings.HasPrefix(t.JA4, "q")}
	if id.stable == "" && t.JA4R != "" {
		if full, st, ok := ja4.FromRaw(t.JA4R); ok && full == t.JA4 {
			id.stable = st
		}
	}
	if p := strings.Split(t.JA4, "_"); len(p) == 3 && strings.HasPrefix(t.JA4, "t") {
		id.ciphers = p[1]
	}
	return id
}

// families devolve as famílias da base com o stable (ou com o JA4 completo, sem stable).
func (id tlsID) families(known KnownClients) []string {
	if id.stable != "" {
		return known.Families(KindJA4Stable, id.stable)
	}
	return known.Families(KindJA4, id.ja4)
}

// browserChecks avalia TLS, h2 e ALPN de um UA de navegador contra a pilha esperada.
func (en Engine) browserChecks(ev *eval, in Input, ua UA) {
	known := en.Sources.Known
	if in.TLS != nil && in.TLS.JA4 != "" {
		en.uaTLS(ev, tlsIdentity(in.TLS), ua)
	}
	isQUIC := in.TLS != nil && strings.HasPrefix(in.TLS.JA4, "q")
	// ua_h2_mismatch, um sinal só: Akamai que a base só viu em bibliotecas (qualquer pilha, inclusive sem medida da
	// família, ADR 0072 item 3.2); Akamai fora do conjunto da família medida; HTTP/1.1 sem h2 no ALPN
	akamaiFams := []string(nil)
	if in.H2 != nil && in.H2.Akamai != "" && known != nil {
		akamaiFams = known.Families(KindAkamai, in.H2.Akamai)
	}
	if lib := libraryOnly(akamaiFams); lib != "" {
		ev.add(SignalUAH2Mismatch, "ua "+ua.Family+", akamai of measured "+lib)
	} else if in.H2 != nil && in.H2.Akamai != "" && known != nil && known.Measured(ua.Stack, KindAkamai) &&
		!slices.Contains(akamaiFams, ua.Stack) {
		ev.add(SignalUAH2Mismatch, "ua "+ua.Family+", akamai not in "+ua.Stack+" set")
	} else if alpnKnown(in.TLS) && !isQUIC && strings.HasPrefix(in.HTTP.Version, "1") && !slices.Contains(in.TLS.ALPN, "h2") {
		ev.add(SignalUAH2Mismatch, "ua "+ua.Family+", http/"+in.HTTP.Version+" without h2 in alpn")
	}
	if alpnKnown(in.TLS) && !isQUIC && !slices.Contains(in.TLS.ALPN, "h2") {
		ev.add(SignalUAALPNMismatch, "ua "+ua.Family+", alpn ["+strings.Join(in.TLS.ALPN, ",")+"] without h2")
	}
}

// uaTLS avalia ua_tls_mismatch (ADR 0072 item 1.6), um sinal só. Primeiro, a pilha só de biblioteca: o stable (o
// JA4 completo, sem stable) que a base só viu em bibliotecas, em qualquer pilha declarada, inclusive a do Safari, que
// a base não mede (item 3.1). Fora do conjunto da família: a pilha tem medida,
// o stable visto não está no conjunto dela e, em TCP, as cifras (parte b) também não; em QUIC as cifras são as
// mesmas em todas as pilhas medidas e vale só o stable. Sem stable, vale só a parte b em TCP (em QUIC não avalia).
// Sem medida da pilha, o rótulo de navegador da ja4db (pelo JA4 completo) decide como na v1.4.
func (en Engine) uaTLS(ev *eval, id tlsID, ua UA) {
	known := en.Sources.Known
	if known != nil {
		if lib := libraryOnly(id.families(known)); lib != "" {
			ev.add(SignalUATLSMismatch, "ua "+ua.Family+", ja4 of measured "+lib)
			return
		}
	}
	label, hasLabel := JA4DBLabel{}, false
	if en.Sources.JA4DB != nil {
		label, hasLabel = en.Sources.JA4DB.Label(id.ja4)
	}
	inDB := hasLabel && label.Kind == JA4DBBrowser && labelNames(label.Name, ua.Stack)
	if inDB {
		return
	}
	if known != nil && known.Measured(ua.Stack, KindJA4Stable) {
		stableOut := id.stable != "" && !slices.Contains(known.Families(KindJA4Stable, id.stable), ua.Stack)
		ciphersOut := id.ciphers != "" && !slices.Contains(known.Families(KindJA4Ciphers, id.ciphers), ua.Stack)
		switch {
		case id.stable != "" && stableOut && (id.quic || ciphersOut):
			ev.add(SignalUATLSMismatch, "ua "+ua.Family+", ja4 stable "+id.stable+" not in "+ua.Stack+" set")
		case id.stable == "" && ciphersOut:
			ev.add(SignalUATLSMismatch, "ua "+ua.Family+", ja4 "+id.ja4+" ciphers not in "+ua.Stack+" set")
		}
		return
	}
	if hasLabel {
		ev.add(SignalUATLSMismatch, "ua "+ua.Family+", ja4 "+id.ja4+" not in "+ua.Stack+" set")
	}
}

// alpnKnown diz se há visão TLS com o ALPN oferecido conhecido (ADR 0063 item 6).
func alpnKnown(t *TLS) bool { return t != nil && !t.ALPNUnknown }

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
	en.automationAndLibrary(ev, in, ua)
	// o UA que declara automação não é coerente com o navegador medido (conduzido por gente): quem se declara
	// automatizado é `bot` sozinho (ADR 0057 item 1), sem o desconto de `known_client`
	if in.HTTP != nil && IsBrowserFamily(ua.Family) && ua.Automation == "" && in.TLS != nil && in.TLS.JA4 != "" &&
		src.Known != nil {
		akamai, ja4t := "", ""
		if in.H2 != nil {
			akamai = in.H2.Akamai
		}
		if in.TCP != nil {
			ja4t = in.TCP.JA4T
		}
		// pelo stable (a retomada TLS não muda a pilha, ADR 0072 item 1.5); sem ele, pelo JA4 completo como na v1.4
		kind, value := KindJA4, in.TLS.JA4
		if id := tlsIdentity(in.TLS); id.stable != "" {
			kind, value = KindJA4Stable, id.stable
		}
		if slices.Contains(src.Known.Coherent(kind, value, akamai, ja4t), ua.Stack) {
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
	sameOp := ua.Operator != "" && inList && listOp == ua.Operator
	byList := VerifiedByList(ua.Operator)
	verify := VerifyUnknown
	// operador provado só pela lista (sem sufixo de DNS publicado): o CrawlerVerifier não é consultado
	if sameOp && !byList && src.Verifier != nil {
		verify = src.Verifier.Verified(ip, ua.Operator)
	}
	good = sameOp && (byList || verify == VerifyPassed)
	switch {
	case good && byList:
		ev.add(SignalIPVerifiedCrawler, ua.Crawler+" verified by ip list")
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

// automationAndLibrary avalia `ua_automation`, `library_client` (ADR 0057 item 1) e `ua_declares_crawler` (ADR 0072
// item 2.1).
func (en Engine) automationAndLibrary(ev *eval, in Input, ua UA) {
	if in.HTTP == nil {
		return
	}
	if ua.Automation != "" {
		ev.add(SignalUAAutomation, ua.Automation)
	}
	// robô declarado sem operador: não há lista a conferir, nunca é good_bot; o robô com operador fica com
	// ua_claims_crawler e a verificação
	if ua.Crawler != "" && ua.Operator == "" {
		ev.add(SignalUADeclaresCrawler, "ua declares crawler "+ua.Crawler)
	}
	if IsLibraryFamily(ua.Family) {
		ev.add(SignalLibraryClient, "ua declares "+ua.Family)
		return
	}
	// UA vazio, desconhecido ou de robô sem operador (ADR 0072 item 2.3): o JA4 stable (ou o completo, sem stable;
	// item 1.7) decide quando a base própria só o viu em bibliotecas. Navegador, headless e robô com operador nunca
	// chegam aqui.
	crawlerNoOp := strings.HasPrefix(ua.Family, FamilyCrawlerPrefix) && ua.Operator == ""
	if (ua.Family != FamilyOther && !crawlerNoOp) || in.TLS == nil || in.TLS.JA4 == "" || en.Sources.Known == nil {
		return
	}
	if lib := libraryOnly(tlsIdentity(in.TLS).families(en.Sources.Known)); lib != "" {
		ev.add(SignalLibraryClient, "ja4 of measured "+lib)
	}
}

// libraryOnly devolve a primeira biblioteca (firstLibrary) quando há famílias e todas são de biblioteca; "" senão.
func libraryOnly(families []string) string {
	if len(families) == 0 || !allLibrary(families) {
		return ""
	}
	return firstLibrary(families)
}

// allLibrary diz se todas as famílias são de biblioteca.
func allLibrary(families []string) bool {
	for _, f := range families {
		if !IsLibraryFamily(f) {
			return false
		}
	}
	return true
}

// unverifiedReason explica por que um IP de lista de robô não virou `good_bot`.
func unverifiedReason(ua UA, listOp string, v Verification) string {
	if ua.Operator != listOp {
		return "ua does not declare it"
	}
	return v.String()
}

// behavior avalia os sinais de comportamento (agregados por IP + site, ADR 0052).
func (en Engine) behavior(ev *eval, b *Behavior, ua UA) {
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
	// ttl_tcp_h3_mismatch (ADR 0078 item 1): na classe de SO do UA desta requisição, TTLs iniciais de TCP e de h3
	// ambos vistos na hora e sem valor em comum (outra pilha no caminho de um deles)
	os := OSClass(ua.OS)
	for _, s := range b.TTLSeen {
		if s.OS == os && len(s.TCP) > 0 && len(s.H3) > 0 && !slices.ContainsFunc(s.TCP, func(v int) bool { return slices.Contains(s.H3, v) }) {
			ev.add(SignalTTLTCPH3Mismatch, fmt.Sprintf("ua os %s: initial ttl tcp %v, h3 %v in the hour", os, s.TCP, s.H3))
		}
	}
	// relay_rtt_gap_agg (ADR 0078 item 2): a mediana passa do limiar quando mais da metade das conexões passa
	if n := b.TimedConnsHour; n >= relayAggMinConns && 2*b.RelayGapConnsHour > n && 2*b.RelayFracConnsHour > n &&
		2*b.RelayFirstConnsHour > n {
		ev.add(SignalRelayRTTGapAgg, fmt.Sprintf("%d tcp connections in the hour: rtt gap > 10 ms in %d, > 30%% of tcp rtt in %d, first byte > 5 ms in %d",
			n, b.RelayGapConnsHour, b.RelayFracConnsHour, b.RelayFirstConnsHour))
	}
}

// truncate corta s em n bytes.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SignalWeight devolve o peso v1.6 do sinal (ADR 0078) (false para id desconhecido).
func SignalWeight(id string) (int, bool) {
	for _, d := range signalTable {
		if d.id == id {
			return d.weight, true
		}
	}
	return 0, false
}
