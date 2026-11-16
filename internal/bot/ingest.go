package bot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/akamai"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Limites do ingest (spec 020 RF-04 e openapi TraefikIngestBatch).
const (
	MaxIngestBytes   = 4 << 20
	MaxIngestRecords = 1024
	maxPathBytes     = 256
	maxFieldValue    = 512
)

// sensitiveFields nunca têm o valor guardado, mesmo que o fork os mande (ADR 0052 item 2).
var sensitiveFields = map[string]bool{"cookie": true, "authorization": true, "proxy-authorization": true, "set-cookie": true}

// TraefikIngestBatch é o corpo de POST /bot/v1/ingest/traefik.
type TraefikIngestBatch struct {
	Sender  string            `json:"sender"`
	Records []json.RawMessage `json:"records"`
}

// TraefikRecord é um registro do lote (openapi TraefikRecord).
type TraefikRecord struct {
	Type                 string            `json:"type"`
	FsConnID             string            `json:"fs_conn_id"`
	Ts                   string            `json:"ts"`
	Src                  *endpoint         `json:"src"`
	Dst                  *endpoint         `json:"dst"`
	EntryPoint           string            `json:"entry_point"`
	SNI                  *string           `json:"sni"`
	ALPNOffered          []string          `json:"alpn_offered"`
	ALPN                 *string           `json:"alpn"`
	TLSVersion           *string           `json:"tls_version"`
	Cipher               *string           `json:"cipher"`
	ClientHello          *string           `json:"client_hello"`
	ClientHelloTruncated bool              `json:"client_hello_truncated"`
	H2Prefix             *string           `json:"h2_prefix"`
	H2PrefixTruncated    bool              `json:"h2_prefix_truncated"`
	Proto                string            `json:"proto"`
	Method               string            `json:"method"`
	Authority            string            `json:"authority"`
	Path                 string            `json:"path"`
	HTTPVersion          string            `json:"http_version"`
	FieldNames           []string          `json:"field_names"`
	Fields               map[string]string `json:"fields"`
	CookieNames          []string          `json:"cookie_names"`
	JA4H                 *string           `json:"ja4h"`
	Status               *int              `json:"status"`
	Ended                *string           `json:"ended"`
	Router               *string           `json:"router"`
	Service              *string           `json:"service"`
}

// errBadRecord marca um registro fora do contrato (contado em `rejected`).
var errBadRecord = errors.New("bot: invalid ingest record")

// Partes do registro que podem falhar na análise (rótulo `part` de bot_ingest_parse_errors_total, ADR 0056).
const (
	PartClientHello = "client_hello"
	PartH2Prefix    = "h2_prefix"
)

// parsedRecord é um registro validado, pronto para o índice. As fingerprints são calculadas aqui, fora da trava do
// índice; os bytes crus não seguem para o índice (memória, spec 018 RNF-02).
type parsedRecord struct {
	r   TraefikRecord
	ts  time.Time
	src netip.Addr
	tls *ForkTLS
	h2  *ForkH2
}

// ParseErrors devolve as partes que não puderam ser analisadas (para bot_ingest_parse_errors_total{part}).
func (p *parsedRecord) ParseErrors() []string {
	var out []string
	if p.tls != nil && p.tls.ParseError {
		out = append(out, PartClientHello)
	}
	if p.h2 != nil && p.h2.ParseError {
		out = append(out, PartH2Prefix)
	}
	return out
}

// DecodeIngestBatch lê o lote; erro aqui é do lote inteiro (400).
func DecodeIngestBatch(body []byte) (TraefikIngestBatch, error) {
	var b TraefikIngestBatch
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return b, errors.New("trailing data after the batch")
	}
	if b.Records == nil {
		return b, errors.New("records is required")
	}
	if len(b.Records) > MaxIngestRecords {
		return b, fmt.Errorf("more than %d records", MaxIngestRecords)
	}
	return b, nil
}

// parseRecord confere um registro contra o contrato.
func parseRecord(raw json.RawMessage) (parsedRecord, error) {
	var p parsedRecord
	if err := json.Unmarshal(raw, &p.r); err != nil {
		return p, fmt.Errorf("%w: %w", errBadRecord, err)
	}
	r := &p.r
	if r.Type != "connection" && r.Type != "request" {
		return p, fmt.Errorf("%w: type %q", errBadRecord, r.Type)
	}
	if !ulidPattern(r.FsConnID) {
		return p, fmt.Errorf("%w: fs_conn_id", errBadRecord)
	}
	ts, err := time.Parse(time.RFC3339Nano, r.Ts)
	if err != nil {
		return p, fmt.Errorf("%w: ts", errBadRecord)
	}
	p.ts = ts
	for _, e := range []*endpoint{r.Src, r.Dst} {
		if e == nil {
			continue
		}
		if _, err := netip.ParseAddr(e.IP); err != nil || e.Port < 0 || e.Port > 65535 {
			return p, fmt.Errorf("%w: endpoint", errBadRecord)
		}
	}
	if r.Src != nil {
		p.src, _ = netip.ParseAddr(r.Src.IP)
	}
	if r.Proto != "" && r.Proto != "h1" && r.Proto != "h2" && r.Proto != "h3" {
		return p, fmt.Errorf("%w: proto %q", errBadRecord, r.Proto)
	}
	if len(r.Path) > maxPathBytes {
		return p, fmt.Errorf("%w: path longer than %d bytes", errBadRecord, maxPathBytes)
	}
	for _, v := range r.Fields {
		if len([]rune(v)) > maxFieldValue {
			return p, fmt.Errorf("%w: field value longer than %d", errBadRecord, maxFieldValue)
		}
	}
	if r.Ended != nil {
		if _, err := time.Parse(time.RFC3339Nano, *r.Ended); err != nil {
			return p, fmt.Errorf("%w: ended", errBadRecord)
		}
	}
	// Base64 inválido está fora do contrato (o registro é recusado); bytes que decodificam mas não analisam viram
	// parse_error na visão daquela parte, sem recusar o registro (spec 018 RF-03).
	if r.ClientHello != nil {
		raw, err := base64.StdEncoding.DecodeString(*r.ClientHello)
		if err != nil {
			return p, fmt.Errorf("%w: client_hello", errBadRecord)
		}
		p.tls = analyzeClientHello(raw, r.ClientHelloTruncated)
	}
	if r.H2Prefix != nil {
		raw, err := base64.StdEncoding.DecodeString(*r.H2Prefix)
		if err != nil {
			return p, fmt.Errorf("%w: h2_prefix", errBadRecord)
		}
		p.h2 = analyzeH2Prefix(raw, r.H2PrefixTruncated)
	}
	return p, nil
}

// site devolve o domínio do registro (SNI ou authority).
func (p *parsedRecord) site() string {
	if p.r.SNI != nil && *p.r.SNI != "" {
		return NormalizeSite(*p.r.SNI)
	}
	return NormalizeSite(p.r.Authority)
}

// apply incorpora o registro à conexão do fork.
func (p *parsedRecord) apply(c *ForkConn) {
	r := &p.r
	if c.First.IsZero() || p.ts.Before(c.First) {
		c.First = p.ts
	}
	if r.Src != nil && r.Dst != nil {
		c.SrcIP, c.SrcPort, c.DstPort, c.HasSrc = p.src.Unmap(), r.Src.Port, r.Dst.Port, true
	}
	switch r.Type {
	case "connection":
		var cost int64
		c.HasConnRecord = true
		c.EntryPoint = shared.str(r.EntryPoint, &cost)
		c.SNI = shared.str(deref(r.SNI), &cost)
		c.ALPNOffered = shared.list(r.ALPNOffered, &cost)
		c.ALPN, c.TLSVersion, c.Cipher = shared.str(deref(r.ALPN), &cost), shared.str(deref(r.TLSVersion), &cost), shared.str(deref(r.Cipher), &cost)
		c.TLS, c.H2, c.connCost = p.tls, p.h2, cost
	case "request":
		path, _, _ := strings.Cut(r.Path, "?") // nada de query (ADR 0052 item 2)
		fields := make(map[string]string, len(r.Fields))
		for k, v := range r.Fields {
			if !sensitiveFields[strings.ToLower(k)] {
				fields[k] = v
			}
		}
		// Textos repetidos entre requisições (método, UA, nomes de campo, JA4H...) vêm do interner (memória do
		// índice cheio, spec 018 RNF-02); o caminho é copiado à parte (é quase sempre único). cost soma o que a
		// requisição aloca (caminho, status e os textos novos no interner, ADR 0057 item 2).
		cost := strBytes(len(path))
		if r.Status != nil {
			cost += allocBytes(unsafe.Sizeof(*r.Status))
		}
		req := ForkRequest{
			Ts: p.ts, Proto: shared.str(r.Proto, &cost), Method: shared.str(r.Method, &cost), Authority: shared.str(r.Authority, &cost),
			Path: strings.Clone(path), HTTPVersion: shared.str(r.HTTPVersion, &cost), FieldNames: shared.list(r.FieldNames, &cost),
			Fields: shared.fields(fields, &cost), CookieNames: shared.list(r.CookieNames, &cost), JA4H: shared.str(deref(r.JA4H), &cost),
			Status: r.Status, Router: shared.str(deref(r.Router), &cost), Service: shared.str(deref(r.Service), &cost),
		}
		req.cost = cost
		// Vetor novo do tamanho exato: quem leu uma cópia rasa da conexão não vê a lista mudar por baixo, e as
		// requisições cortadas (as mais antigas além de maxForkRequests) não ficam presas no vetor antigo.
		keep := c.Requests
		if len(keep) >= maxForkRequests {
			keep = keep[len(keep)-maxForkRequests+1:]
		}
		next := make([]ForkRequest, len(keep), len(keep)+1)
		copy(next, keep)
		c.Requests = append(next, req)
	}
}

// maxForkPriorities é quantos frames PRIORITY anteriores ao primeiro HEADERS a visão h2 guarda (o Akamai já os
// resume todos).
const maxForkPriorities = 64

// analyzeClientHello calcula as fingerprints do ClientHello cru como o web do espelho (internal/web/conn.go):
// tlsparse.Parse sobre os registros TLS e, só sem erro, JA3 e JA4 (transporte TCP). O ClientHello do QUIC (spec
// 019 RF-13) ainda não tem formato no contrato: bytes fora de registros TLS são parse_error.
func analyzeClientHello(raw []byte, truncated bool) *ForkTLS {
	t := &ForkTLS{Truncated: truncated, cost: forkTLSBytes}
	ch, err := tlsparse.Parse(raw)
	// Cortado (acima de 16 KiB no traefix) também é parse_error: a mensagem não está inteira (spec 019 RF-03).
	if err != nil || ch == nil || truncated {
		t.ParseError = true
		return t
	}
	j3 := ja3.Compute(ch)
	j4 := ja4.Compute(ch, ja4.TCP)
	c := &t.cost
	t.JA3, t.JA3MD5, t.JA3N, t.JA3NMD5 = shared.str(j3.JA3, c), shared.str(j3.JA3MD5, c), shared.str(j3.JA3N, c), shared.str(j3.JA3NMD5, c)
	t.JA4, t.JA4R, t.JA4O = shared.str(j4.JA4, c), shared.str(j4.JA4R, c), shared.str(j4.JA4O, c)
	t.SNI, t.ALPN = shared.str(ch.SNI, c), shared.list(ch.ALPN, c)
	return t
}

// analyzeH2Prefix analisa o prefixo h2 do cliente (depois do prefácio) com o parser passivo do espelho e guarda
// só o que entra nos sinais: SETTINGS, WINDOW_UPDATE, PRIORITY anteriores ao HEADERS, a ordem das
// pseudo-headers e o Akamai (calculado como o web, internal/web/h2_events.go). Os campos decodificados (cookies
// incluídos) são descartados aqui (ADR 0052 item 2). Erro do parser, prefixo cortado, curto demais para um
// frame ou que não começa por SETTINGS (RFC 9113 3.4) é parse_error.
func analyzeH2Prefix(raw []byte, truncated bool) *ForkH2 {
	h := &ForkH2{Truncated: truncated, cost: forkH2Bytes}
	const frameHeaderLen, frameSettings = 9, 0x4
	if truncated || len(raw) < frameHeaderLen || raw[3] != frameSettings {
		h.ParseError = true
		return h
	}
	p := h2passive.NewParser(h2passive.Options{Dir: h2passive.DirIn, SkipPreface: true})
	p.Feed(0, raw)
	if p.Err() != nil {
		h.ParseError = true
		return h
	}
	info := p.Info()
	h.Settings = slices.Clone(info.Settings)
	h.cost += allocBytes(uintptr(cap(h.Settings)) * unsafe.Sizeof([2]uint32{}))
	if info.WindowUpdate != nil {
		h.WindowUpdate = ptr(*info.WindowUpdate)
		h.cost += strBytes(int(unsafe.Sizeof(*h.WindowUpdate))) // sem ponteiros: alocador tiny
	}
	n := min(info.PrioritiesBeforeHeaders, len(info.Priorities), maxForkPriorities)
	h.Priorities = slices.Clone(info.Priorities[:n])
	h.cost += allocBytes(uintptr(cap(h.Priorities)) * priorityBytes)
	for i := range info.Streams {
		if info.Streams[i].StreamID == info.FirstHeadersStream && info.FirstHeadersStream != 0 {
			h.PseudoOrder = shared.list(info.Streams[i].PseudoOrder, &h.cost)
			break
		}
	}
	h.HeadersSeen = info.FirstHeadersStream != 0
	if info.FirstHeadersStream != 0 || len(info.Settings) > 0 {
		h.Akamai = shared.str(akamai.FromInfo(info), &h.cost)
	}
	return h
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
