package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

var update = flag.Bool("update", false, "regrava os exemplos golden em testdata/events")

var eventT0 = time.Date(2026, 11, 8, 12, 0, 0, 123456789, time.UTC)

// eventCase monta uma consulta crua, passa pelo handle real do servidor e devolve a Query observada.
func eventCase(t *testing.T, srv *Server, proto string, src string, raw []byte) *Query {
	t.Helper()
	ap := netip.MustParseAddrPort(src)
	out, req, resp, limited := srv.handle(raw, proto == "tcp", ap.Addr())
	_ = out
	return &Query{
		At: eventT0, Proto: proto, Src: ap, Dst: netip.MustParseAddrPort("172.233.24.85:53"),
		Raw: raw, Req: req, Resp: resp, RateLimited: limited,
	}
}

func pack(t *testing.T, m *mdns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenQueries(t *testing.T) map[string]*Query {
	t.Helper()
	z := newDualZone()
	srv := NewServer(z.cfg, z, nil, nil)
	srv.RRL = nil

	// 1. UDP A com caixa 0x20, EDNS com ECS, cookie, padding e uma opção sem tratamento próprio (NSID).
	m := query("AbCdEfGh.dns-monitor.TMSOFT.com.br.", mdns.TypeA)
	m.Id = 0x1234
	m.CheckingDisabled = true
	m.AuthenticatedData = true
	m.SetEdns0(1232, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&mdns.EDNS0_SUBNET{Code: mdns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("200.1.2.0").To4()},
		&mdns.EDNS0_COOKIE{Code: mdns.EDNS0COOKIE, Cookie: "0102030405060708"},
		&mdns.EDNS0_NSID{Code: mdns.EDNS0NSID},
		&mdns.EDNS0_PADDING{Padding: make([]byte, 12)},
	)
	out := map[string]*Query{"udp-a-ecs": eventCase(t, srv, "udp", "198.51.100.7:40123", pack(t, m))}

	// 2. TCP HTTPS sem EDNS, IPv6, com rótulo de controle.
	m = query("t1a2b3c4.v4.dns-monitor.tmsoft.com.br.", mdns.TypeHTTPS)
	m.Id = 7
	out["tcp-https-v4"] = eventCase(t, srv, "tcp", "[2001:db8::53]:51000", pack(t, m))

	// 3. Fora da zona.
	m = query("example.com.", mdns.TypeA)
	m.Id = 8
	out["udp-refused"] = eventCase(t, srv, "udp", "198.51.100.7:40124", pack(t, m))

	// 4. Acima do RRL: TC=1 sem dados.
	srv.RRL = NewRRL(1, func() time.Time { return eventT0 })
	m = query("abcdefgh.dns-monitor.tmsoft.com.br.", mdns.TypeAAAA)
	m.Id = 9
	_ = eventCase(t, srv, "udp", "198.51.100.8:5353", pack(t, m))
	out["udp-rate-limited"] = eventCase(t, srv, "udp", "198.51.100.8:5353", pack(t, m))
	srv.RRL = nil

	// 5. Mensagem malformada → FORMERR.
	out["udp-formerr"] = eventCase(t, srv, "udp", "198.51.100.9:1000",
		[]byte{0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x05, 'a'})
	return out
}

// TestQueryEventsGolden confere os eventos fs.v1.dns.query contra os exemplos em testdata/events.
func TestQueryEventsGolden(t *testing.T) {
	z := newDualZone()
	for name, q := range goldenQueries(t) {
		msg, err := z.QueryMessage(q, "0.1.0")
		if err != nil {
			t.Fatal(err)
		}
		if msg.Subject != SubjectQuery {
			t.Fatalf("subject %s", msg.Subject)
		}
		env, err := event.Decode(msg.Data)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, msg.Data, "", "  "); err != nil {
			t.Fatal(err)
		}
		buf.WriteByte('\n')
		file := filepath.Join("testdata", "events", name+".json")
		if *update {
			_ = os.MkdirAll(filepath.Dir(file), 0o750)
			if err := os.WriteFile(file, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%v (rode com -update)", err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s diverge do golden; rode go test ./internal/dns -run TestQueryEventsGolden -update\n%s", name, buf.Bytes())
		}
		if env.Flow == nil || env.Flow.L4 != q.Proto || env.Flow.DstPort != 53 {
			t.Errorf("%s: flow %+v", name, env.Flow)
		}
	}
}

// TestQueryEventFields confere os campos pedidos pela spec 007 RF-06 no caso com ECS.
func TestQueryEventFields(t *testing.T) {
	z := newDualZone()
	qs := goldenQueries(t)
	d := z.BuildQuery(qs["udp-a-ecs"])
	if d.Qname != "AbCdEfGh.dns-monitor.TMSOFT.com.br." || d.ProbeID == nil || *d.ProbeID != "abcdefgh" {
		t.Fatalf("qname/probe %q %v", d.Qname, d.ProbeID)
	}
	if d.ID != 0x1234 || !d.Flags.RD || !d.Flags.CD || !d.Flags.AD || d.Qtype != "A" || d.Qclass != "IN" {
		t.Fatalf("cabeçalho %+v", d)
	}
	e := d.EDNS
	if e == nil || e.Version != 0 || e.UDPSize != 1232 || !e.DO || e.CookieHex == nil || *e.CookieHex != "0102030405060708" {
		t.Fatalf("edns %+v", e)
	}
	if e.ECS == nil || *e.ECS != (ECSInfo{Family: 1, SourcePrefix: 24, Address: "200.1.2.0"}) {
		t.Fatalf("ecs %+v", e.ECS)
	}
	if e.PaddingLen == nil || *e.PaddingLen != 12 || len(e.Options) != 1 || e.Options[0].Code != 3 {
		t.Fatalf("opções %+v %v", e.Options, e.PaddingLen)
	}
	if d.Response == nil || d.Response.Rcode != "NOERROR" || len(d.Response.Answers) != 1 ||
		d.Response.Answers[0].Data != "172.233.24.85" || d.Response.Answers[0].TTL != 5 {
		t.Fatalf("resposta %+v", d.Response)
	}
	raw, _ := base64.StdEncoding.DecodeString(d.RawB64)
	if !bytes.Equal(raw, qs["udp-a-ecs"].Raw) {
		t.Fatal("raw_b64")
	}
	if rl := z.BuildQuery(qs["udp-rate-limited"]); !rl.RateLimited || !rl.Response.Truncated {
		t.Fatalf("rate limited %+v", rl)
	}
	if fe := z.BuildQuery(qs["udp-formerr"]); fe.Qname != "" || fe.Response.Rcode != "FORMERR" || fe.ID != 0xbeef {
		t.Fatalf("formerr %+v", fe)
	}
	// Mensagem descartada (QR=1): sem response.
	if d := z.BuildQuery(&Query{At: eventT0, Proto: "udp", Raw: []byte{1}}); d.Response != nil || d.ID != 0 {
		t.Fatalf("descartada %+v", d)
	}
	if typeString(65000) != "TYPE65000" || classString(999) != "CLASS999" || rcodeString(4000) != "RCODE4000" {
		t.Fatal("nomes desconhecidos")
	}
}

// TestQueryEventMatchesOpenAPI: toda chave dos exemplos existe no schema DNSQuery do openapi e as
// obrigatórias estão presentes.
func TestQueryEventMatchesOpenAPI(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/finger-sniffer-store/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	i := strings.Index(doc, "\n    DNSQuery:\n")
	if i < 0 {
		t.Fatal("DNSQuery not in openapi")
	}
	block := doc[i+1:]
	if j := regexp.MustCompile(`\n    [A-Za-z]+:\n`).FindStringIndex(block[1:]); j != nil {
		block = block[:j[0]+1]
	}
	props := map[string]bool{}
	for _, m := range regexp.MustCompile(`\n\s+([a-z_0-9]+):`).FindAllStringSubmatch(block, -1) {
		props[m[1]] = true
	}
	// resolver é um $ref para Endpoint.
	if !strings.Contains(block, `resolver: { $ref: "#/components/schemas/Endpoint" }`) {
		t.Fatal("resolver deixou de ser Endpoint")
	}
	props["ip"], props["port"] = true, true
	req := regexp.MustCompile(`required: \[([^\]]*)\]`).FindStringSubmatch(block)
	// Só os eventos fs.v1.dns.query: as respostas do DNS-01 (dns.acme.reply.*) têm outro schema.
	all, _ := filepath.Glob("testdata/events/*.json")
	var files []string
	for _, f := range all {
		if !strings.HasPrefix(filepath.Base(f), "dns.acme.") {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatal("sem exemplos")
	}
	var walk func(string, any)
	walk = func(file string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				if !props[k] {
					t.Errorf("%s: chave %q fora do schema DNSQuery", file, k)
				}
				walk(file, vv)
			}
		case []any:
			for _, vv := range x {
				walk(file, vv)
			}
		}
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		var env struct {
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatal(err)
		}
		for _, r := range strings.Split(req[1], ", ") {
			if _, ok := env.Payload[r]; !ok {
				t.Errorf("%s: obrigatório %s ausente", f, r)
			}
		}
		walk(f, env.Payload)
	}
}
