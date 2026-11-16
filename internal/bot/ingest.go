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

// parsedRecord é um registro validado, pronto para o índice.
type parsedRecord struct {
	r           TraefikRecord
	ts          time.Time
	src         netip.Addr
	clientHello []byte
	h2Prefix    []byte
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
	if r.ClientHello != nil {
		if p.clientHello, err = base64.StdEncoding.DecodeString(*r.ClientHello); err != nil {
			return p, fmt.Errorf("%w: client_hello", errBadRecord)
		}
	}
	if r.H2Prefix != nil {
		if p.h2Prefix, err = base64.StdEncoding.DecodeString(*r.H2Prefix); err != nil {
			return p, fmt.Errorf("%w: h2_prefix", errBadRecord)
		}
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
		c.HasConnRecord = true
		c.EntryPoint = r.EntryPoint
		c.SNI = deref(r.SNI)
		c.ALPNOffered = r.ALPNOffered
		c.ALPN, c.TLSVersion, c.Cipher = deref(r.ALPN), deref(r.TLSVersion), deref(r.Cipher)
		c.ClientHello, c.ClientHelloTruncated = p.clientHello, r.ClientHelloTruncated
		c.H2Prefix, c.H2PrefixTruncated = p.h2Prefix, r.H2PrefixTruncated
	case "request":
		path, _, _ := strings.Cut(r.Path, "?") // nada de query (ADR 0052 item 2)
		fields := make(map[string]string, len(r.Fields))
		for k, v := range r.Fields {
			if !sensitiveFields[strings.ToLower(k)] {
				fields[k] = v
			}
		}
		req := ForkRequest{
			Ts: p.ts, Proto: r.Proto, Method: r.Method, Authority: r.Authority, Path: path,
			HTTPVersion: r.HTTPVersion, FieldNames: r.FieldNames, Fields: fields, CookieNames: r.CookieNames,
			JA4H: deref(r.JA4H), Status: r.Status, Router: deref(r.Router), Service: deref(r.Service),
		}
		// Clip força uma cópia: quem leu uma cópia rasa da conexão não vê a lista mudar por baixo.
		c.Requests = append(slices.Clip(c.Requests), req)
		if len(c.Requests) > maxForkRequests {
			c.Requests = c.Requests[len(c.Requests)-maxForkRequests:]
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
