package bot

import (
	"encoding/base64"
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
	cost      int64 // estrutura e textos criados (somado ao connCost da conexão)
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
