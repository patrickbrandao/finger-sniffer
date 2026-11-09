package dns

import (
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Parâmetros do SOA. O TTL negativo (minttl) é o FS_DNS_TTL, para que um NODATA não fique em cache além
// do TTL dos registros.
const (
	soaRefresh = 3600
	soaRetry   = 600
	soaExpire  = 86400
	// acmeLabel é o primeiro rótulo dos nomes TXT do DNS-01.
	acmeLabel = "_acme-challenge"
	// maxTXTValue é o maior valor TXT aceito (uma string de caracteres do DNS).
	maxTXTValue = 255
)

// Zone responde às consultas da zona. É segura para uso concorrente.
type Zone struct {
	cfg    Config
	now    func() time.Time
	serial uint32

	probes *probe.Extractor

	mu   sync.Mutex
	acme map[string]map[string]time.Time // nome canônico → valor → expiração
}

// NewZone cria a zona. now é o relógio (nil = time.Now); o serial do SOA é o instante da criação.
func NewZone(cfg Config, now func() time.Time) *Zone {
	if now == nil {
		now = time.Now
	}
	cfg.Zone = mdns.CanonicalName(cfg.Zone)
	cfg.NS = mdns.Fqdn(cfg.NS)
	return &Zone{cfg: cfg, now: now, probes: probe.NewExtractor(strings.TrimSuffix(cfg.Zone, ".")), serial: clampU32(now().Unix()), acme: map[string]map[string]time.Time{}}
}

// InZone informa se o nome (qualquer caixa, com ou sem ponto final) pertence à zona.
func (z *Zone) InZone(name string) bool {
	return mdns.IsSubDomain(z.cfg.Zone, mdns.CanonicalName(name))
}

// acmeName valida e normaliza um nome do DNS-01: dentro da zona e com _acme-challenge como primeiro rótulo.
func (z *Zone) acmeName(name string) (string, bool) {
	n := mdns.CanonicalName(strings.TrimSpace(name))
	if _, ok := mdns.IsDomainName(n); !ok || !z.InZone(n) {
		return "", false
	}
	first, _, _ := strings.Cut(n, ".")
	return n, first == acmeLabel
}

// SetACME acrescenta value ao conjunto do nome (idempotente: renova a expiração).
func (z *Zone) SetACME(name, value string) error {
	n, ok := z.acmeName(name)
	if !ok {
		return errNotACMEName
	}
	if value == "" || len(value) > maxTXTValue {
		return errBadValue
	}
	now := z.now()
	z.mu.Lock()
	defer z.mu.Unlock()
	z.pruneLocked(now)
	set := z.acme[n]
	if set == nil {
		set = map[string]time.Time{}
		z.acme[n] = set
	}
	set[value] = now.Add(z.cfg.ACMETTL)
	return nil
}

// ClearACME remove só aquele valor do conjunto do nome (remover o que não existe não é erro).
func (z *Zone) ClearACME(name, value string) error {
	n, ok := z.acmeName(name)
	if !ok {
		return errNotACMEName
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.pruneLocked(z.now())
	if set := z.acme[n]; set != nil {
		delete(set, value)
		if len(set) == 0 {
			delete(z.acme, n)
		}
	}
	return nil
}

// ACMEValues devolve os valores vivos do nome canônico, em ordem estável (ordem alfabética).
func (z *Zone) ACMEValues(name string) []string {
	n := mdns.CanonicalName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.pruneLocked(z.now())
	set := z.acme[n]
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// pruneLocked remove os valores expirados.
func (z *Zone) pruneLocked(now time.Time) {
	for n, set := range z.acme {
		for v, exp := range set {
			if !now.Before(exp) {
				delete(set, v)
			}
		}
		if len(set) == 0 {
			delete(z.acme, n)
		}
	}
}

// SOA devolve o SOA do apex.
func (z *Zone) SOA() *mdns.SOA {
	ttl := z.cfg.ttlSeconds()
	return &mdns.SOA{
		Hdr:     mdns.RR_Header{Name: z.cfg.Zone, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: ttl},
		Ns:      z.cfg.NS,
		Mbox:    "hostmaster." + z.cfg.Zone,
		Serial:  z.serial,
		Refresh: soaRefresh,
		Retry:   soaRetry,
		Expire:  soaExpire,
		Minttl:  ttl,
	}
}

func (z *Zone) ns() *mdns.NS {
	return &mdns.NS{
		Hdr: mdns.RR_Header{Name: z.cfg.Zone, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: z.cfg.ttlSeconds()},
		Ns:  z.cfg.NS,
	}
}

// Answer monta a resposta à consulta já decodificada. Nunca devolve nil.
func (z *Zone) Answer(req *mdns.Msg) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = false
	resp.RecursionAvailable = false
	// SetReply copia RD e CD; AD não vai na resposta (sem DNSSEC).
	resp.AuthenticatedData = false

	if req.Opcode != mdns.OpcodeQuery {
		resp.Rcode = mdns.RcodeNotImplemented
		return resp
	}
	if len(req.Question) != 1 {
		resp.Rcode = mdns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	// Nome ou classe de fora: não somos autoritativos (sem recursão).
	if !z.InZone(q.Name) || (q.Qclass != mdns.ClassINET && q.Qclass != mdns.ClassANY) {
		resp.Rcode = mdns.RcodeRefused
		return resp
	}
	resp.Authoritative = true
	switch q.Qtype {
	case mdns.TypeAXFR, mdns.TypeIXFR:
		resp.Rcode = mdns.RcodeRefused
		return resp
	}

	name := mdns.CanonicalName(q.Name)
	apex := name == z.cfg.Zone
	info, _ := z.probes.Host(name)
	// Rótulos de controle (spec 007 RF-03).
	if info.Has(probe.ControlNX) {
		resp.Rcode = mdns.RcodeNameError
		resp.Ns = append(resp.Ns, z.SOA())
		return resp
	}
	if !info.Has(probe.ControlNoData) {
		resp.Answer = z.records(q, name, apex, info)
	}
	// Todo nome da zona existe: sem resposta é NOERROR/NODATA com o SOA na autoridade (o Let's Encrypt
	// consulta CAA e precisa disso, nunca REFUSED ou SERVFAIL).
	if len(resp.Answer) == 0 {
		resp.Ns = append(resp.Ns, z.SOA())
	}
	return resp
}

// ProbeID devolve o probe ID do qname ("" se não houver).
func (z *Zone) ProbeID(qname string) string {
	info, _ := z.probes.Host(qname)
	return info.ID
}

// records devolve os RRs da resposta para a pergunta, já com o dono na caixa da pergunta (0x20).
func (z *Zone) records(q mdns.Question, name string, apex bool, info probe.HostInfo) []mdns.RR {
	ttl := z.cfg.ttlSeconds()
	hdr := func(t uint16) mdns.RR_Header {
		return mdns.RR_Header{Name: q.Name, Rrtype: t, Class: mdns.ClassINET, Ttl: ttl}
	}
	v4 := z.cfg.IPv4.IsValid() && !info.Has(probe.ControlV6)
	v6 := z.cfg.IPv6.IsValid() && !info.Has(probe.ControlV4)
	all := q.Qtype == mdns.TypeANY
	var out []mdns.RR
	if apex && (all || q.Qtype == mdns.TypeSOA) {
		soa := z.SOA()
		soa.Hdr.Name = q.Name
		out = append(out, soa)
	}
	if apex && (all || q.Qtype == mdns.TypeNS) {
		ns := z.ns()
		ns.Hdr.Name = q.Name
		out = append(out, ns)
	}
	if v4 && (all || q.Qtype == mdns.TypeA) {
		out = append(out, &mdns.A{Hdr: hdr(mdns.TypeA), A: z.cfg.IPv4.AsSlice()})
	}
	if v6 && (all || q.Qtype == mdns.TypeAAAA) {
		out = append(out, &mdns.AAAA{Hdr: hdr(mdns.TypeAAAA), AAAA: z.cfg.IPv6.AsSlice()})
	}
	if (all || q.Qtype == mdns.TypeHTTPS) && !info.Has(probe.ControlNoH3) && (v4 || v6) {
		rr := &mdns.HTTPS{SVCB: mdns.SVCB{Hdr: hdr(mdns.TypeHTTPS), Priority: 1, Target: "."}}
		alpn := []string{"h2"}
		if z.cfg.H3 {
			alpn = []string{"h3", "h2"}
		}
		rr.Value = append(rr.Value, &mdns.SVCBAlpn{Alpn: alpn})
		if v4 {
			rr.Value = append(rr.Value, &mdns.SVCBIPv4Hint{Hint: []net.IP{z.cfg.IPv4.AsSlice()}})
		}
		if v6 {
			rr.Value = append(rr.Value, &mdns.SVCBIPv6Hint{Hint: []net.IP{z.cfg.IPv6.AsSlice()}})
		}
		out = append(out, rr)
	}
	if all || q.Qtype == mdns.TypeTXT {
		for _, v := range z.ACMEValues(name) {
			out = append(out, &mdns.TXT{Hdr: hdr(mdns.TypeTXT), Txt: []string{v}})
		}
	}
	return out
}
