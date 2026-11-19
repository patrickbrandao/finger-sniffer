package bot

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
)

// ForkTCP é a visão TCP da conexão do traefix (ADR 0063 item 5, spec 018 RF-03): o SYN que o traefix salvou
// (`TCP_SAVE_SYN`) e o que ele mediu. Os campos seguem as regras do store (spec 013) para as regras lerem a mesma
// coisa das duas visões.
type ForkTCP struct {
	JA4T string
	// TTL é o TTL recebido (tcp.ttl); TTLInitial, o inicial estimado como o store (0 = desconhecido).
	TTL        int
	TTLInitial int
	// SynMSS, MTUImplied e MSSReduction saem do MSS do JA4T (spec 013 RF-06a); nil sem a opção MSS.
	SynMSS       *int
	MTUImplied   *int
	MSSReduction *int
	// OSGuess é o palpite de SO do p0f a partir de tcp.syn com o p0f.fp do bot (FS_BOT_P0F_DB); "" sem SYN, sem
	// banco ou sem correspondência.
	OSGuess string
	// P0f é o raw_sig do traefix (tcp.p0f) e RTTMicros, o tcp.rttMicros: guardados, sem regra (spec 019 RF-07).
	P0f       string
	RTTMicros *int64
	// UDP marca a visão de transporte de uma conexão h3 (só o TTL do primeiro Initial, ADR 0065 item 4): não é TCP
	// (view.tcp fica false), mas a parte de TTL de ua_os_tcp_mismatch a lê.
	UDP  bool
	cost int64 // estrutura e textos criados (somado ao connCost da conexão)
}

// forkTCPBytes é o custo fixo da visão TCP do traefix no índice.
var forkTCPBytes = allocBytes(unsafe.Sizeof(ForkTCP{}))

// rules devolve a visão na forma que as regras leem (a mesma que o store dá).
func (t *ForkTCP) rules() *rules.TCP {
	return &rules.TCP{
		JA4T: t.JA4T, P0fOS: t.OSGuess, TTLInitial: t.TTLInitial, MSSReduction: t.MSSReduction, MTUImplied: t.MTUImplied,
	}
}

// traefixTCP é o objeto tcp do registro de conexão traefix.fingerprint/v1.
type traefixTCP struct {
	JA4T      *string `json:"ja4t"`
	P0f       *string `json:"p0f"`
	TTL       *int    `json:"ttl"`
	RTTMicros *int64  `json:"rttMicros"`
	SYN       *string `json:"syn"`
}

// Formatos aceitos das partes prontas (os do esquema do traefix); fora deles a parte é tratada como ausente.
var (
	// O esquema do traefix pede dois dígitos na escala, mas o JA4T da FoxIO (e o do store) escreve a escala sem zero
	// à esquerda (`..._1430_6`): o bot aceita os dois para não perder o JA4T real.
	ja4tPattern   = regexp.MustCompile(`^[0-9]+_[0-9-]+_[0-9]{2,}_[0-9]+$`)
	p0fSigPattern = regexp.MustCompile(`^[46]:[0-9]+\+[0-9?]+:[0-9]+:[0-9*]+:[^:]*,[0-9]+:[^:]*:[^:]*:[0+]$`)
)

// maxTCPText é o teto dos textos prontos da visão TCP (JA4T e raw_sig têm dezenas de bytes; acima, malformado).
const maxTCPText = 256

// discardTCPOrigin diz se a visão TCP do traefix deve ser descartada pela origem: loopback, link-local, privada
// (10/8, 172.16/12, 192.168/16, fc00::/7) ou sem origem válida. Nesses casos o SYN salvo é de um proxy local (ex.:
// docker-proxy), não do cliente (ADR 0063 item 5).
func discardTCPOrigin(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

// tcpViewResult é a visão montada e as divergências entre o calculado do SYN e o pronto do traefix.
type tcpViewResult struct {
	view       *ForkTCP
	mismatches []string
}

// buildTCPView monta a visão TCP do traefix do objeto tcp do registro de conexão. src é a origem do registro
// (descarta com origem local ou privada) e db, o banco p0f (nil = sem palpite de SO). Com tcp.syn válido, o JA4T e o
// SO vêm do SYN (pkg/fingerprint/ja4plus e pkg/fingerprint/p0f, os mesmos do store) e o JA4T pronto só é conferido;
// sem ele, vale o JA4T pronto. Partes malformadas são tratadas como ausentes.
func buildTCPView(t *traefixTCP, src netip.Addr, db *p0f.DB) tcpViewResult {
	var res tcpViewResult
	if t == nil || discardTCPOrigin(src) {
		return res
	}
	v := &ForkTCP{cost: forkTCPBytes}
	family := 4
	if src.Unmap().Is6() {
		family = 6
	}
	ready := ""
	if t.JA4T != nil && len(*t.JA4T) <= maxTCPText && ja4tPattern.MatchString(*t.JA4T) {
		ready = *t.JA4T
	}
	synTTL := -1
	if t.SYN != nil {
		if syn, err := base64.StdEncoding.DecodeString(*t.SYN); err == nil {
			if s, ok := analyzeSYN(syn, db); ok {
				v.JA4T, v.OSGuess, family, synTTL = s.ja4t, s.os, s.family, s.ttl
			}
		}
	}
	switch {
	case v.JA4T == "":
		v.JA4T = ready
	case ready != "" && ready != v.JA4T:
		res.mismatches = append(res.mismatches, mismatchJA4T)
	}
	switch {
	case t.TTL != nil && *t.TTL >= 0 && *t.TTL <= 255:
		v.TTL = *t.TTL
		v.TTLInitial = initialTTL(v.TTL)
	case synTTL >= 0:
		v.TTL = synTTL
		v.TTLInitial = initialTTL(v.TTL)
	}
	if mss, ok := ja4tMSS(v.JA4T); ok {
		v.SynMSS, v.MTUImplied, v.MSSReduction = mssDerived(mss, family)
	}
	if t.P0f != nil && len(*t.P0f) <= maxTCPText && p0fSigPattern.MatchString(*t.P0f) {
		v.P0f = *t.P0f
	}
	if t.RTTMicros != nil && *t.RTTMicros >= 0 {
		v.RTTMicros = ptr(*t.RTTMicros)
		v.cost += strBytes(int(unsafe.Sizeof(*v.RTTMicros)))
	}
	if v.JA4T == "" && v.TTLInitial == 0 && v.OSGuess == "" {
		return res // nada que as regras leiam
	}
	c := &v.cost
	v.JA4T, v.OSGuess, v.P0f = shared.str(v.JA4T, c), shared.str(v.OSGuess, c), shared.str(v.P0f, c)
	for _, p := range []*int{v.SynMSS, v.MTUImplied, v.MSSReduction} {
		if p != nil {
			*c += strBytes(int(unsafe.Sizeof(*p)))
		}
	}
	res.view = v
	return res
}

// synInfo é o que o SYN cru dá: JA4T, SO do p0f, família e TTL recebido.
type synInfo struct {
	ja4t   string
	os     string
	family int
	ttl    int
}

// analyzeSYN lê o SYN cru desde o cabeçalho IP como o store (internal/store/analysis.go, synPacket): p0f.Parse e o
// casamento do p0f.fp para o SO, ja4plus.JA4T sobre o cabeçalho TCP para o JA4T. Sem um SYN inicial TCP legível,
// ok é false.
func analyzeSYN(syn []byte, db *p0f.DB) (synInfo, bool) {
	pk, err := p0f.Parse(syn)
	if err != nil || !pk.IsSYN() {
		return synInfo{}, false
	}
	hl := 40
	if pk.IPVersion == 4 {
		hl = 20 + int(pk.IPOptLen)
	}
	if hl >= len(syn) {
		return synInfo{}, false
	}
	j, err := ja4plus.JA4T(syn[hl:])
	if err != nil {
		return synInfo{}, false
	}
	s := synInfo{ja4t: j, family: int(pk.IPVersion), ttl: int(pk.TTL)}
	if db != nil {
		if obs, err := db.Fingerprint(pk, 0); err == nil && obs.Matched {
			s.os = obs.OS
		}
	}
	return s, true
}

// ja4tMSS devolve o MSS do JA4T (`janela_opções_mss_escala`) quando a lista de opções tem a MSS (tipo 2).
func ja4tMSS(j string) (int, bool) {
	parts := strings.Split(j, "_")
	if len(parts) != 4 {
		return 0, false
	}
	has := false
	for _, k := range strings.Split(parts[1], "-") {
		if k == "2" {
			has = true
			break
		}
	}
	if !has {
		return 0, false
	}
	m, err := strconv.Atoi(parts[2])
	if err != nil || m < 0 || m > 65535 {
		return 0, false
	}
	return m, true
}

// initialTTL estima o TTL inicial do TTL recebido como o store (spec 013, internal/store/analysis.go).
func initialTTL(ttl int) int {
	switch {
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	}
	return 255
}

// mssDerived calcula syn_mss, mtu_implied e mss_reduction como o store (spec 013 RF-06a, ADR 0031): cabeçalhos
// fixos de IP e TCP (40 B no IPv4, 60 B no IPv6), sem os 12 B de timestamps; referência = MSS de um MTU Ethernet de
// 1500.
func mssDerived(mss, family int) (synMSS, mtu, reduction *int) {
	hdr, ref := 40, 1460
	if family == 6 {
		hdr, ref = 60, 1440
	}
	return ptr(mss), ptr(mss + hdr), ptr(ref - mss)
}

// p0fSource carrega o p0f.fp do bot (FS_BOT_P0F_DB) uma vez, no primeiro SYN que precisar dele. Ausente ou
// inválido: uma linha de log e a visão TCP sem palpite de SO (ADR 0063 item 5).
type p0fSource struct {
	path string
	once sync.Once
	db   *p0f.DB
	log  *slog.Logger
}

func newP0FSource(path string, log *slog.Logger) *p0fSource {
	if log == nil {
		log = slog.Default()
	}
	return &p0fSource{path: path, log: log}
}

// get devolve o banco (nil sem ele).
func (s *p0fSource) get() *p0f.DB {
	if s == nil || s.path == "" {
		return nil
	}
	s.once.Do(func() {
		db, err := p0f.LoadDB(s.path)
		if err != nil {
			s.log.Warn("bot: p0f.fp not loaded, traefix TCP view without OS guess", "path", s.path, "err", err)
			return
		}
		s.db = db
	})
	return s.db
}

// udpViewFrom monta a visão de transporte de uma conexão h3 do traefix só com o TTL do primeiro Initial (udp.ttl ou
// X-Traefix-Ttl): o TTL inicial estimado como o store (spec 013), sem JA4T, MSS nem SO (ADR 0065 item 4). Com origem
// local ou privada ou sem TTL, nil, como a visão TCP.
func udpViewFrom(ttl int, src netip.Addr) *ForkTCP {
	if ttl < 0 || ttl > 255 || discardTCPOrigin(src) {
		return nil
	}
	return &ForkTCP{TTL: ttl, TTLInitial: initialTTL(ttl), UDP: true, cost: forkTCPBytes}
}

// traefixUDPTTL lê o objeto udp do registro de conexão (h3; ADR 0065 item 4): só o ttl. Fora de inteiro de 0 a 255 (ou
// udp que não é objeto), -1.
func traefixUDPTTL(raw json.RawMessage) int {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return -1
	}
	v, ok := parseMicros(string(m["ttl"]), true)
	if !ok || v > 255 {
		return -1
	}
	return int(v)
}

// Origem dos horários dos tempos do traefix (timing.source, `src` de X-Traefix-Timing).
const (
	timingKernel = "kernel"
	timingUser   = "user"
)

// maxTimingMicros é o maior tempo aceito (1 h, em módulo): acima disso o valor não é medida de início de conexão e
// é tratado como ausente (e as contas das regras não estouram).
const maxTimingMicros = 3_600_000_000

// micros é um tempo opcional em microssegundos (ok=false é desconhecido, nunca 0).
type micros struct {
	v  int64
	ok bool
}

// ptr devolve o tempo como ponteiro (nil desconhecido).
func (m micros) ptr() *int64 {
	if !m.ok {
		return nil
	}
	return ptr(m.v)
}

// ForkTiming são os tempos do início da conexão medidos pelo traefix (timing do registro de conexão ou
// X-Traefix-Timing; ADR 0065 item 2): só os campos que o bot usa. Tamanho fixo, sem textos alocados (Source é uma das
// constantes).
type ForkTiming struct {
	Source string // timingKernel | timingUser | "" (desconhecida)
	// QUIC diz que os tempos são de uma conexão h3 (as voltas TCP e TLS não existem nela).
	QUIC                               bool
	TCPRTT, EstToFirst, TLSRTT, RTTGap micros
	QUICRTT, QUICMinRTT                micros
	cost                               int64
}

// forkTimingBytes é o custo dos tempos no índice (somado ao connCost da conexão).
var forkTimingBytes = allocBytes(unsafe.Sizeof(ForkTiming{}))

// gap é o rtt_gap do traefix ou, sem ele, TLS − TCP com as duas voltas conhecidas.
func (t *ForkTiming) gap() micros {
	if t.RTTGap.ok {
		return t.RTTGap
	}
	if t.TCPRTT.ok && t.TLSRTT.ok {
		return micros{v: t.TLSRTT.v - t.TCPRTT.v, ok: true}
	}
	return micros{}
}

// rules devolve os tempos na forma que as regras leem (nil em h3: relay_rtt_gap é só de TCP).
func (t *ForkTiming) rules() *rules.Timing {
	if t == nil || t.QUIC || !t.TCPRTT.ok {
		return nil
	}
	return &rules.Timing{
		TCPRTTMicros: t.TCPRTT.ptr(), TLSRTTMicros: t.TLSRTT.ptr(), RTTGapMicros: t.gap().ptr(), EstToFirstMicros: t.EstToFirst.ptr(),
	}
}

// empty diz que nenhum tempo veio.
func (t *ForkTiming) empty() bool {
	for _, m := range []micros{t.TCPRTT, t.EstToFirst, t.TLSRTT, t.RTTGap, t.QUICRTT, t.QUICMinRTT} {
		if m.ok {
			return false
		}
	}
	return true
}

// parseMicros lê um inteiro decimal (sinal opcional, até 16 caracteres) dentro de ±maxTimingMicros; nonNeg recusa os
// negativos. Qualquer outra forma (fração, expoente, texto, vazio) é ausente.
func parseMicros(s string, nonNeg bool) (int64, bool) {
	if s == "" || len(s) > 16 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (i != 0 || c != '-') {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v > maxTimingMicros || v < -maxTimingMicros || (nonNeg && v < 0) {
		return 0, false
	}
	return v, true
}

// timingSourceOf devolve a constante da origem dos horários ("" para outro valor).
func timingSourceOf(s string) string {
	switch s {
	case timingKernel:
		return timingKernel
	case timingUser:
		return timingUser
	}
	return ""
}

// timingFields liga as chaves do registro (timing) e do cabeçalho (X-Traefix-Timing) a cada tempo guardado; nonNeg
// marca as voltas, que não podem ser negativas (esquema do traefix).
var timingFields = []struct {
	record, header string
	nonNeg         bool
	field          func(*ForkTiming) *micros
}{
	{"tcpRttMicros", "tcp_rtt_us", true, func(t *ForkTiming) *micros { return &t.TCPRTT }},
	{"estToFirstMicros", "est_to_first_us", false, func(t *ForkTiming) *micros { return &t.EstToFirst }},
	{"tlsRttMicros", "tls_rtt_us", false, func(t *ForkTiming) *micros { return &t.TLSRTT }},
	{"rttGapMicros", "rtt_gap_us", false, func(t *ForkTiming) *micros { return &t.RTTGap }},
	{"quicRttMicros", "quic_rtt_us", true, func(t *ForkTiming) *micros { return &t.QUICRTT }},
	{"quicMinRttMicros", "quic_min_rtt_us", true, func(t *ForkTiming) *micros { return &t.QUICMinRTT }},
}

// traefixTiming lê o objeto timing do registro de conexão (ADR 0065 item 2): os campos da lista, cada um ausente
// quando fora de inteiro; campos desconhecidos ignorados; timing que não é objeto, ou sem nenhum tempo, nil. quic
// marca a conexão h3.
func traefixTiming(raw json.RawMessage, quic bool) *ForkTiming {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	t := &ForkTiming{QUIC: quic, cost: forkTimingBytes}
	var src string
	if json.Unmarshal(m["source"], &src) == nil {
		t.Source = timingSourceOf(src)
	}
	for _, f := range timingFields {
		if v, ok := parseMicros(string(m[f.record]), f.nonNeg); ok {
			*f.field(t) = micros{v: v, ok: true}
		}
	}
	if t.empty() {
		return nil
	}
	return t
}

// maxTimingHeader é o teto de X-Traefix-Timing (2 KiB, o dos cabeçalhos de detalhe do traefix).
const maxTimingHeader = 2048

// parseTimingHeader lê X-Traefix-Timing (`chave=valor` por vírgula; ADR 0065 item 2): `src` em kernel|user, `proto`
// udp marca h3 (como quic), os tempos da lista como inteiros; chave desconhecida ou par sem `=` ignorados, valor fora
// de inteiro ou chave repetida = aquele tempo ausente. Acima de 2 KiB ou sem nenhum tempo, nil.
func parseTimingHeader(s string, quic bool) *ForkTiming {
	if s == "" || len(s) > maxTimingHeader {
		return nil
	}
	t := &ForkTiming{QUIC: quic}
	seen := map[string]int{}
	vals := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		seen[k]++
		vals[k] = v
	}
	if seen["src"] == 1 {
		t.Source = timingSourceOf(vals["src"])
	}
	if seen["proto"] == 1 && vals["proto"] == "udp" {
		t.QUIC = true
	}
	for _, f := range timingFields {
		if seen[f.header] != 1 {
			continue
		}
		if v, ok := parseMicros(vals[f.header], f.nonNeg); ok {
			*f.field(t) = micros{v: v, ok: true}
		}
	}
	if t.empty() {
		return nil
	}
	return t
}
