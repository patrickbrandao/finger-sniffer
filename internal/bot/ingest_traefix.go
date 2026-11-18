package bot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
)

// SchemaTraefixV1 é o esquema do lote do traefix (ADR 0062 item 2, openapi TraefixFingerprintBatch); sem o campo
// `schema`, o lote é o TraefikIngestBatch anterior.
const SchemaTraefixV1 = "traefix.fingerprint/v1"

// Métricas do ingest do traefix (spec 018 RF-12, ADRs 0062 item 3 e 0063 itens 2 e 4).
const (
	metricIngestIgnored  = "bot_ingest_ignored_total"
	metricIngestMismatch = "bot_ingest_fingerprint_mismatch_total"
)

// Tipos de divergência entre o calculado pelo bot e o pronto do traefix (rótulo kind).
const (
	mismatchJA3    = "ja3"
	mismatchJA3N   = "ja3n"
	mismatchJA4    = "ja4"
	mismatchJA4R   = "ja4r"
	mismatchJA4O   = "ja4o"
	mismatchAkamai = "akamai"
	mismatchJA4T   = "ja4t"
)

// mismatchKinds são os valores de kind de bot_ingest_fingerprint_mismatch_total (spec 018 RF-12).
var mismatchKinds = []string{mismatchJA3, mismatchJA3N, mismatchJA4, mismatchJA4R, mismatchJA4O, mismatchAkamai, mismatchJA4T}

func mismatchMetric(kind string) string { return metricIngestMismatch + `{kind="` + kind + `"}` }

// ingestBatch é o lote lido, de qualquer dos dois esquemas.
type ingestBatch struct {
	schema     string // "" = TraefikIngestBatch (formato anterior)
	entryPoint string
	records    []json.RawMessage
}

// errBadSchema marca o lote com `schema` desconhecido (400 com o lote inteiro recusado).
var errBadSchema = errors.New("unknown schema")

// decodeBatch lê o lote e escolhe o esquema pelo campo `schema` (ADR 0062 item 2): ausente (ou null) é o formato
// anterior, `traefix.fingerprint/v1` é o do traefix, qualquer outro valor é erro do lote. Os limites são os mesmos
// nos dois.
func decodeBatch(body []byte) (ingestBatch, error) {
	var b struct {
		Schema     *string           `json:"schema"`
		EntryPoint string            `json:"entryPoint"`
		Records    []json.RawMessage `json:"records"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&b); err != nil {
		return ingestBatch{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return ingestBatch{}, errors.New("trailing data after the batch")
	}
	out := ingestBatch{records: b.Records}
	if b.Schema != nil {
		if *b.Schema != SchemaTraefixV1 {
			return out, fmt.Errorf("%w %q", errBadSchema, clip(*b.Schema, 64))
		}
		out.schema, out.entryPoint = *b.Schema, b.EntryPoint
	}
	if b.Records == nil {
		return out, errors.New("records is required")
	}
	if len(b.Records) > MaxIngestRecords {
		return out, fmt.Errorf("more than %d records", MaxIngestRecords)
	}
	return out, nil
}

// traefixRecord é um registro do lote traefix.fingerprint/v1 (openapi TraefixConnectionRecord e
// TraefixRequestRecord): só o que a spec 019 RF-07 lê; o resto é ignorado (ADR 0063 item 2).
type traefixRecord struct {
	Type        string         `json:"type"`
	ConnID      string         `json:"connId"`
	Time        *string        `json:"time"`
	Start       *string        `json:"start"`
	End         *string        `json:"end"`
	EntryPoint  string         `json:"entryPoint"`
	Src         *endpoint      `json:"src"`
	Dst         *endpoint      `json:"dst"`
	Proto       string         `json:"proto"`
	TLS         *traefixTLS    `json:"tls"`
	HTTP2       *traefixH2     `json:"http2"`
	TCP         *traefixTCP    `json:"tcp"`
	Method      string         `json:"method"`
	Authority   string         `json:"authority"`
	Path        string         `json:"path"`
	HTTPVersion string         `json:"httpVersion"`
	FieldNames  []string       `json:"fieldNames"`
	Fields      []traefixField `json:"fields"`
	CookieNames []string       `json:"cookieNames"`
	JA4H        *string        `json:"ja4h"`
	Status      *int           `json:"status"`
	Router      *string        `json:"router"`
	Service     *string        `json:"service"`
}

type traefixTLS struct {
	SNI                  *string  `json:"sni"`
	ALPNOffered          []string `json:"alpnOffered"`
	ALPN                 *string  `json:"alpn"`
	Version              *string  `json:"version"`
	Cipher               *string  `json:"cipher"`
	JA3                  *string  `json:"ja3"`
	JA3String            *string  `json:"ja3String"`
	JA3N                 *string  `json:"ja3n"`
	JA3NString           *string  `json:"ja3nString"`
	JA4                  *string  `json:"ja4"`
	JA4R                 *string  `json:"ja4r"`
	JA4O                 *string  `json:"ja4o"`
	ClientHello          *string  `json:"clientHello"`
	ClientHelloTruncated bool     `json:"clientHelloTruncated"`
}

type traefixH2 struct {
	Akamai          *string `json:"akamai"`
	HeadersPriority *string `json:"headersPriority"`
	Prefix          *string `json:"prefix"`
	PrefixTruncated bool    `json:"prefixTruncated"`
}

type traefixField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Formatos aceitos das fingerprints prontas (os do esquema do traefix); fora deles a parte é ausente.
var (
	md5Pattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ja4Pattern     = regexp.MustCompile(`^[tqd][0-9a-z?]{2}[di][0-9]{4}.{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	ja4rPattern    = regexp.MustCompile(`^[tqd][0-9a-z?]{2}[di][0-9]{4}.{2}_`)
	ja3TextPattern = regexp.MustCompile(`^[0-9]+,[0-9-]*,[0-9-]*,[0-9-]*,[0-9-]*$`)
	akamaiPattern  = regexp.MustCompile(`^[^|]*\|[^|]*\|[^|]*\|[^|]*$`)
	h2PrioPattern  = regexp.MustCompile(`^[0-9]+:[01]:[0-9]+:[0-9]+$`)
)

// Tetos dos textos prontos guardados no índice: acima deles, a parte é malformada (memória, spec 018 RNF-02).
const (
	maxReadyText   = 4096 // ja3String, ja3nString e ja4r de ClientHellos grandes
	maxReadyAkamai = 512  // o mesmo teto do cabeçalho X-Traefix-H2 (ADR 0062 item 4)
)

// ingestEnv é o que a leitura do registro do traefix usa além dos bytes: o banco p0f (nil = sem palpite de SO).
type ingestEnv struct {
	p0f *p0f.DB
}

// parseTraefixRecord confere um registro traefix.fingerprint/v1 e o converte para o registro do formato anterior
// (ADR 0062 item 2), com as fingerprints prontas como reserva e a visão TCP (ADR 0063 itens 4 e 5). Tipo de
// registro desconhecido volta com ignored (fora de accepted e rejected); faltando o que o bot lê (connId, time ou
// start), o registro é recusado mesmo que o esquema do traefix o declare completo de outra forma.
func parseTraefixRecord(raw json.RawMessage, batchEntryPoint string, env ingestEnv) (parsedRecord, error) {
	var p parsedRecord
	var head struct {
		Type *string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Type == nil {
		return p, fmt.Errorf("%w: type", errBadRecord)
	}
	if *head.Type != "connection" && *head.Type != "request" {
		p.ignored, p.ignoredType = true, *head.Type
		return p, nil
	}
	var t traefixRecord
	if err := json.Unmarshal(raw, &t); err != nil {
		return p, fmt.Errorf("%w: %w", errBadRecord, err)
	}
	r := TraefikRecord{
		Type: t.Type, FsConnID: t.ConnID, Src: t.Src, Dst: t.Dst, EntryPoint: t.EntryPoint, Proto: t.Proto,
		Method: t.Method, Authority: t.Authority, Path: t.Path, HTTPVersion: t.HTTPVersion, FieldNames: t.FieldNames,
		CookieNames: t.CookieNames, JA4H: t.JA4H, Status: t.Status, Ended: t.End, Router: t.Router, Service: t.Service,
	}
	if r.EntryPoint == "" {
		r.EntryPoint = batchEntryPoint
	}
	if t.Type == "connection" {
		r.Ts = deref(t.Time)
	} else {
		r.Ts = deref(t.Start)
	}
	if t.TLS != nil {
		r.SNI, r.ALPNOffered, r.ALPN, r.TLSVersion, r.Cipher = t.TLS.SNI, t.TLS.ALPNOffered, t.TLS.ALPN, t.TLS.Version, t.TLS.Cipher
		r.ClientHello, r.ClientHelloTruncated = t.TLS.ClientHello, t.TLS.ClientHelloTruncated
	}
	if t.HTTP2 != nil {
		r.H2Prefix, r.H2PrefixTruncated = t.HTTP2.Prefix, t.HTTP2.PrefixTruncated
	}
	// fields é lista {name, value} na ordem recebida: o primeiro valor de cada nome permitido, sem diferenciar
	// caixa (como o UA do web); os repetidos seguem em fieldNames.
	if len(t.Fields) > 0 {
		r.Fields = map[string]string{}
		seen := map[string]bool{}
		for _, f := range t.Fields {
			k := strings.ToLower(f.Name)
			if seen[k] || !allowedField(f.Name) {
				continue
			}
			seen[k] = true
			r.Fields[f.Name] = f.Value
		}
	}
	p.r = r
	if err := p.check(); err != nil {
		return p, err
	}
	if t.Type != "connection" {
		return p, nil
	}
	switch {
	case t.TLS == nil:
	case p.tls == nil:
		p.tls = readyTLS(t.TLS)
	case !p.tls.ParseError:
		p.mismatches = append(p.mismatches, tlsMismatches(p.tls, t.TLS)...)
	}
	switch {
	case t.HTTP2 == nil:
	case p.h2 == nil:
		p.h2 = readyH2(t.HTTP2)
	case !p.h2.ParseError:
		if a := readyAkamai(t.HTTP2.Akamai); a != "" && a != p.h2.Akamai {
			p.mismatches = append(p.mismatches, mismatchAkamai)
		}
		if hp := readyText(t.HTTP2.HeadersPriority, h2PrioPattern, maxReadyText); hp != "" {
			p.h2.HeadersPriority = shared.str(hp, &p.h2.cost)
		}
	}
	// Visão TCP: nunca em h3 (QUIC não tem TCP), nem com origem local ou privada (buildTCPView).
	if t.TCP != nil && !p.quic {
		tv := buildTCPView(t.TCP, p.src, env.p0f)
		p.tcp = tv.view
		p.mismatches = append(p.mismatches, tv.mismatches...)
	}
	return p, nil
}

// readyText devolve o texto pronto quando bem formado (e dentro do teto); "" quando ausente ou malformado.
func readyText(s *string, re *regexp.Regexp, maxLen int) string {
	if s == nil || len(*s) > maxLen || !re.MatchString(*s) {
		return ""
	}
	return *s
}

// readyTLS monta a visão TLS das fingerprints prontas do traefix (sem tls.clientHello, ADR 0063 item 4): JA3 e JA3N
// (texto e MD5), JA4, JA4_r e JA4_o, SNI e ALPN oferecido. Sem nenhuma fingerprint bem formada, nil.
func readyTLS(t *traefixTLS) *ForkTLS {
	v := &ForkTLS{Ready: true, cost: forkTLSBytes}
	c := &v.cost
	v.JA3MD5 = readyText(t.JA3, md5Pattern, maxReadyText)
	v.JA3 = readyText(t.JA3String, ja3TextPattern, maxReadyText)
	v.JA3NMD5 = readyText(t.JA3N, md5Pattern, maxReadyText)
	v.JA3N = readyText(t.JA3NString, ja3TextPattern, maxReadyText)
	v.JA4 = readyText(t.JA4, ja4Pattern, maxReadyText)
	v.JA4R = readyText(t.JA4R, ja4rPattern, maxReadyText)
	v.JA4O = readyText(t.JA4O, ja4Pattern, maxReadyText)
	if v.JA3MD5 == "" && v.JA3 == "" && v.JA3NMD5 == "" && v.JA3N == "" && v.JA4 == "" && v.JA4R == "" && v.JA4O == "" {
		return nil
	}
	v.JA3, v.JA3MD5, v.JA3N, v.JA3NMD5 = shared.str(v.JA3, c), shared.str(v.JA3MD5, c), shared.str(v.JA3N, c), shared.str(v.JA3NMD5, c)
	v.JA4, v.JA4R, v.JA4O = shared.str(v.JA4, c), shared.str(v.JA4R, c), shared.str(v.JA4O, c)
	v.SNI, v.ALPN = shared.str(deref(t.SNI), c), shared.list(t.ALPNOffered, c)
	return v
}

// tlsMismatches compara o calculado dos bytes crus com o pronto do traefix (só os prontos bem formados).
func tlsMismatches(calc *ForkTLS, t *traefixTLS) []string {
	var out []string
	for _, x := range []struct {
		kind, calc string
		ready      *string
		re         *regexp.Regexp
	}{
		{mismatchJA3, calc.JA3MD5, t.JA3, md5Pattern},
		{mismatchJA3N, calc.JA3NMD5, t.JA3N, md5Pattern},
		{mismatchJA4, calc.JA4, t.JA4, ja4Pattern},
		{mismatchJA4R, calc.JA4R, t.JA4R, ja4rPattern},
		{mismatchJA4O, calc.JA4O, t.JA4O, ja4Pattern},
	} {
		if r := readyText(x.ready, x.re, maxReadyText); r != "" && r != x.calc {
			out = append(out, x.kind)
		}
	}
	return out
}

// readyAkamai devolve o Akamai pronto quando bem formado (formato do web do espelho, até 512 bytes).
func readyAkamai(s *string) string {
	a := readyText(s, akamaiPattern, maxReadyAkamai)
	if a == "" {
		return ""
	}
	if _, ok := parseAkamai(a); !ok {
		return ""
	}
	return a
}

// readyH2 monta a visão h2 da forma pronta do traefix (sem http2.prefix, ADR 0063 item 4): o Akamai e as partes
// dele (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-headers) e o headersPriority. Sem Akamai bem formado, nil.
func readyH2(t *traefixH2) *ForkH2 {
	a := readyAkamai(t.Akamai)
	if a == "" {
		return nil
	}
	parts, _ := parseAkamai(a)
	h := &ForkH2{Ready: true, cost: forkH2Bytes}
	h.Settings = parts.settings
	h.cost += allocBytes(uintptr(cap(h.Settings)) * unsafe.Sizeof([2]uint32{}))
	if parts.windowUpdate != nil {
		h.WindowUpdate = parts.windowUpdate
		h.cost += strBytes(int(unsafe.Sizeof(*h.WindowUpdate)))
	}
	h.Priorities = parts.priorities
	h.cost += allocBytes(uintptr(cap(h.Priorities)) * priorityBytes)
	h.PseudoOrder = shared.list(parts.pseudo, &h.cost)
	h.HeadersSeen = len(parts.pseudo) > 0
	h.Akamai = shared.str(a, &h.cost)
	h.HeadersPriority = shared.str(readyText(t.HeadersPriority, h2PrioPattern, maxReadyText), &h.cost)
	return h
}

// akamaiParts são as partes do Akamai (`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers`).
type akamaiParts struct {
	settings     [][2]uint32
	windowUpdate *uint32
	priorities   []h2passive.Priority
	pseudo       []string
}

// pseudoNames são as pseudo-headers pela letra do Akamai.
var pseudoNames = map[string]string{"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}

// parseAkamai separa o Akamai no formato do web do espelho (pkg/fingerprint/akamai): SETTINGS `id:valor` por `;`,
// WINDOW_UPDATE (`00` = ausente), PRIORITY `stream:exclusivo:depende:peso` por `,` (`0` = nenhuma) e as letras
// das pseudo-headers por `,`.
func parseAkamai(s string) (akamaiParts, bool) {
	var out akamaiParts
	f := strings.Split(s, "|")
	if len(f) != 4 {
		return out, false
	}
	if f[0] != "" {
		for _, kv := range strings.Split(f[0], ";") {
			k, v, ok := strings.Cut(kv, ":")
			id, err1 := strconv.ParseUint(k, 10, 32)
			val, err2 := strconv.ParseUint(v, 10, 32)
			if !ok || err1 != nil || err2 != nil {
				return out, false
			}
			out.settings = append(out.settings, [2]uint32{uint32(id), uint32(val)})
		}
	}
	wu, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return out, false
	}
	if wu != 0 {
		out.windowUpdate = ptr(uint32(wu))
	}
	if f[2] != "0" {
		for _, p := range strings.Split(f[2], ",") {
			q := strings.Split(p, ":")
			if len(q) != 4 || (q[1] != "0" && q[1] != "1") {
				return out, false
			}
			sid, err1 := strconv.ParseUint(q[0], 10, 32)
			dep, err2 := strconv.ParseUint(q[2], 10, 32)
			w, err3 := strconv.Atoi(q[3])
			if err1 != nil || err2 != nil || err3 != nil || w < 0 || len(out.priorities) >= maxForkPriorities {
				return out, false
			}
			out.priorities = append(out.priorities, h2passive.Priority{
				StreamID: uint32(sid), Exclusive: q[1] == "1", DependsOn: uint32(dep), Weight: w,
			})
		}
	}
	if f[3] != "" {
		for _, l := range strings.Split(f[3], ",") {
			if len(l) != 1 {
				return out, false
			}
			name := pseudoNames[l]
			if name == "" {
				name = ":" + l
			}
			out.pseudo = append(out.pseudo, name)
		}
	}
	return out, true
}

// maxIgnoredTypes é quantos valores distintos o rótulo type de bot_ingest_ignored_total pode ter; os demais vão
// para `other` (ADR 0063 item 2).
const (
	maxIgnoredTypes     = 16
	maxIgnoredTypeBytes = 32
	ignoredTypeOther    = "other"
)

// ignoredTypes guarda os rótulos já usados em bot_ingest_ignored_total{type}.
type ignoredTypes struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// label devolve o rótulo do tipo: caracteres fora do formato das métricas (ADR 0056 item 4) viram `_`, cortado em
// 32 bytes; vazio ou além dos 16 distintos, `other`.
func (g *ignoredTypes) label(t string) string {
	var b strings.Builder
	for i := 0; i < len(t) && b.Len() < maxIgnoredTypeBytes; i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == ':', c == '-', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	l := b.String()
	if l == "" || l == ignoredTypeOther {
		return ignoredTypeOther
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]struct{}{}
	}
	if _, ok := g.seen[l]; ok {
		return l
	}
	if len(g.seen) >= maxIgnoredTypes {
		return ignoredTypeOther
	}
	g.seen[l] = struct{}{}
	return l
}

// mismatchLogEvery é o intervalo mínimo entre duas linhas de log de divergência (ADR 0062 item 3).
const mismatchLogEvery = time.Minute

// rateLog escreve no máximo uma linha por intervalo.
type rateLog struct {
	mu   sync.Mutex
	last time.Time
}

// allow diz se uma linha pode sair agora (e marca o instante).
func (l *rateLog) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < mismatchLogEvery {
		return false
	}
	l.last = now
	return true
}

// logger devolve o logger do pacote para as linhas do ingest (o padrão do slog quando o serviço não deu um).
func logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}
