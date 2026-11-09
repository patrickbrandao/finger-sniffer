package dns

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// QueryEvent é o payload de fs.v1.dns.query (openapi DNSQuery, spec 007 RF-06).
type QueryEvent struct {
	Ts          string        `json:"ts"`
	ProbeID     *string       `json:"probe_id"`
	Resolver    Endpoint      `json:"resolver"`
	Proto       string        `json:"proto"`
	ConnID      *string       `json:"conn_id"`
	ID          int           `json:"id"`
	Opcode      int           `json:"opcode"`
	Flags       QueryFlags    `json:"flags"`
	Qname       string        `json:"qname"`
	Qtype       string        `json:"qtype"`
	Qclass      string        `json:"qclass"`
	EDNS        *EDNSInfo     `json:"edns"`
	Response    *ResponseInfo `json:"response,omitempty"`
	RateLimited bool          `json:"rate_limited"`
	RawB64      string        `json:"raw_b64"`
}

// Endpoint é IP e porta.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// QueryFlags são os bits RD, CD e AD da consulta.
type QueryFlags struct {
	RD bool `json:"rd"`
	CD bool `json:"cd"`
	AD bool `json:"ad"`
}

// EDNSInfo descreve o OPT da consulta.
type EDNSInfo struct {
	Version    int          `json:"version"`
	UDPSize    int          `json:"udp_size"`
	DO         bool         `json:"do"`
	CookieHex  *string      `json:"cookie_hex"`
	ECS        *ECSInfo     `json:"ecs"`
	PaddingLen *int         `json:"padding_len"`
	Options    []EDNSOption `json:"options"`
}

// ECSInfo é o EDNS Client Subnet (RFC 7871).
type ECSInfo struct {
	Family       int    `json:"family"`
	SourcePrefix int    `json:"source_prefix"`
	ScopePrefix  int    `json:"scope_prefix"`
	Address      string `json:"address"`
}

// EDNSOption é uma opção EDNS sem tratamento próprio, em hex.
type EDNSOption struct {
	Code    int    `json:"code"`
	DataHex string `json:"data_hex"`
}

// ResponseInfo é a resposta enviada.
type ResponseInfo struct {
	Rcode     string       `json:"rcode"`
	Truncated bool         `json:"truncated"`
	Answers   []AnswerInfo `json:"answers"`
}

// AnswerInfo é um RR da seção de respostas.
type AnswerInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
	Data string `json:"data"`
}

// BuildQuery monta o payload a partir da consulta atendida.
func (z *Zone) BuildQuery(q *Query) QueryEvent {
	d := QueryEvent{
		Ts:          event.FormatTime(q.At),
		Resolver:    Endpoint{IP: q.Src.Addr().String(), Port: int(q.Src.Port())},
		Proto:       q.Proto,
		RateLimited: q.RateLimited,
		RawB64:      base64.StdEncoding.EncodeToString(q.Raw),
	}
	if len(q.Raw) >= 4 {
		d.ID = int(q.Raw[0])<<8 | int(q.Raw[1])
		d.Opcode = int(q.Raw[2]>>3) & 0x0f
		d.Flags = QueryFlags{RD: q.Raw[2]&0x01 != 0, AD: q.Raw[3]&0x20 != 0, CD: q.Raw[3]&0x10 != 0}
	}
	if q.Req != nil && len(q.Req.Question) > 0 {
		qq := q.Req.Question[0]
		d.Qname, d.Qtype, d.Qclass = qq.Name, typeString(qq.Qtype), classString(qq.Qclass)
		if id := z.ProbeID(qq.Name); id != "" {
			d.ProbeID = &id
		}
	}
	if q.Req != nil {
		d.EDNS = ednsInfo(q.Req.IsEdns0())
	}
	if q.Resp != nil {
		r := &ResponseInfo{Rcode: rcodeString(q.Resp.Rcode), Truncated: q.Resp.Truncated, Answers: []AnswerInfo{}}
		for _, rr := range q.Resp.Answer {
			h := rr.Header()
			r.Answers = append(r.Answers, AnswerInfo{
				Name: h.Name, Type: typeString(h.Rrtype), TTL: int(h.Ttl),
				Data: strings.TrimPrefix(rr.String(), h.String()),
			})
		}
		d.Response = r
	}
	return d
}

func ednsInfo(opt *mdns.OPT) *EDNSInfo {
	if opt == nil {
		return nil
	}
	e := &EDNSInfo{Version: int(opt.Version()), UDPSize: int(opt.UDPSize()), DO: opt.Do(), Options: []EDNSOption{}}
	for _, o := range opt.Option {
		if v, ok := o.(*mdns.EDNS0_SUBNET); ok {
			e.ECS = &ECSInfo{
				Family: int(v.Family), SourcePrefix: int(v.SourceNetmask), ScopePrefix: int(v.SourceScope),
				Address: v.Address.String(),
			}
		}
	}
	// Os bytes de cada opção saem do OPT reempacotado (o miekg não exporta o pack por opção).
	for _, tlv := range optionTLVs(opt) {
		switch tlv.code {
		case mdns.EDNS0COOKIE:
			c := hex.EncodeToString(tlv.data)
			e.CookieHex = &c
		case mdns.EDNS0SUBNET:
		case mdns.EDNS0PADDING:
			n := len(tlv.data)
			e.PaddingLen = &n
		default:
			e.Options = append(e.Options, EDNSOption{Code: int(tlv.code), DataHex: hex.EncodeToString(tlv.data)})
		}
	}
	return e
}

type optionTLV struct {
	code uint16
	data []byte
}

// optionTLVs reempacota o OPT e lê as opções (código, tamanho, dados) da RDATA, na ordem.
func optionTLVs(opt *mdns.OPT) []optionTLV {
	buf := make([]byte, mdns.MaxMsgSize)
	n, err := mdns.PackRR(opt, buf, 0, nil, false)
	// Cabeçalho do RR do OPT: nome raiz (1) + tipo (2) + classe (2) + TTL (4) + RDLENGTH (2).
	const hdr = 11
	if err != nil || n < hdr {
		return nil
	}
	rd := buf[hdr:n]
	var out []optionTLV
	for len(rd) >= 4 {
		code := binary.BigEndian.Uint16(rd)
		l := int(binary.BigEndian.Uint16(rd[2:]))
		if 4+l > len(rd) {
			break
		}
		out = append(out, optionTLV{code: code, data: slices.Clone(rd[4 : 4+l])})
		rd = rd[4+l:]
	}
	return out
}

func typeString(t uint16) string {
	if s, ok := mdns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func classString(c uint16) string {
	if s, ok := mdns.ClassToString[c]; ok {
		return s
	}
	return fmt.Sprintf("CLASS%d", c)
}

func rcodeString(r int) string {
	if s, ok := mdns.RcodeToString[r]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", r)
}

// QueryMessage monta a mensagem NATS de fs.v1.dns.query: envelope com o fluxo resolvedor → espelho e o
// probe_id.
func (z *Zone) QueryMessage(q *Query, serviceVersion string) (*nats.Msg, error) {
	p := z.BuildQuery(q)
	flow := &event.Flow{
		L4: q.Proto, SrcIP: q.Src.Addr().String(), SrcPort: int(q.Src.Port()),
		DstIP: q.Dst.Addr().String(), DstPort: int(q.Dst.Port()),
	}
	env, err := event.New(event.ServiceDNS, serviceVersion, q.At, flow, p)
	if err != nil {
		return nil, err
	}
	env.ProbeID = p.ProbeID
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &nats.Msg{Subject: SubjectQuery, Data: data}, nil
}

// SubjectQuery é o subject do evento por consulta.
const SubjectQuery = event.SubjectDNSQuery
