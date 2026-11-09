package web

import (
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/nats-io/nats.go"

	"github.com/patrickbrandao/finger-sniffer/internal/dns"
	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// testDNSZone é a zona real do serviço dns (task 016) com os parâmetros dos testes.
func testDNSZone() *dns.Zone {
	return dns.NewZone(dns.Config{
		Zone: "dns-monitor.tmsoft.com.br.", NS: dns.DefaultNS, TTL: 5 * time.Second,
		IPv4: netip.MustParseAddr("127.0.0.1"), ACMETTL: dns.ACMEValueTTL,
	}, nil)
}

// TestNATSDNSProviderSetClear: o provedor libdns faz set e clear no dns real pelo NATS; o TXT aparece e some.
func TestNATSDNSProviderSetClear(t *testing.T) {
	nc := startNATS(t)
	z := testDNSZone()
	if _, err := dns.SubscribeACME(nc, z, nil); err != nil {
		t.Fatal(err)
	}
	p := &natsDNSProvider{nc: nc, timeout: 2 * time.Second}
	ctx := context.Background()
	const zone = "dns-monitor.tmsoft.com.br."
	const fqdn = "_acme-challenge.dns-monitor.tmsoft.com.br."
	recs := []libdns.Record{
		libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "value-one"},
		libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "value-two"},
	}
	out, err := p.AppendRecords(ctx, zone, recs)
	if err != nil || len(out) != 2 {
		t.Fatalf("append %v %v", out, err)
	}
	if txt, ok := out[0].(libdns.TXT); !ok || txt.Text != "value-one" || txt.Name != "_acme-challenge" {
		t.Fatalf("append result %#v", out[0])
	}
	if got := z.ACMEValues(fqdn); len(got) != 2 {
		t.Fatalf("values after set %v", got)
	}
	if _, err := p.DeleteRecords(ctx, zone, out[:1]); err != nil {
		t.Fatal(err)
	}
	if got := z.ACMEValues(fqdn); len(got) != 1 || got[0] != "value-two" {
		t.Fatalf("values after clear %v", got)
	}
	// Nome sem ponto final na zona também funciona.
	if _, err := p.DeleteRecords(ctx, strings.TrimSuffix(zone, "."), out[1:]); err != nil {
		t.Fatal(err)
	}
	if got := z.ACMEValues(fqdn); len(got) != 0 {
		t.Fatalf("values after second clear %v", got)
	}
}

// TestNATSDNSProviderErrors: sem dns, dns mudo, nome fora da zona e tipo que não é TXT viram erros claros.
func TestNATSDNSProviderErrors(t *testing.T) {
	nc := startNATS(t)
	ctx := context.Background()
	rec := []libdns.Record{libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: "v"}}

	p := &natsDNSProvider{nc: nc, timeout: 300 * time.Millisecond}
	if _, err := p.AppendRecords(ctx, "dns-monitor.tmsoft.com.br.", rec); err == nil ||
		!strings.Contains(err.Error(), "no responder") {
		t.Fatalf("no responder: %v", err)
	}

	// dns que recebe e não responde.
	sub, err := nc.Subscribe(event.SubjectDNSACMESet, func(*nats.Msg) {})
	if err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	if _, err := p.AppendRecords(ctx, "dns-monitor.tmsoft.com.br.", rec); err == nil ||
		!strings.Contains(err.Error(), "no reply within") {
		t.Fatalf("timeout: %v", err)
	}
	_ = sub.Unsubscribe()

	z := testDNSZone()
	if _, err := dns.SubscribeACME(nc, z, nil); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	if _, err := p.AppendRecords(ctx, "example.com.", rec); err == nil ||
		!strings.Contains(err.Error(), "refused by dns") {
		t.Fatalf("outside zone: %v", err)
	}
	a := []libdns.Record{libdns.RR{Name: "x", Type: "A", Data: "127.0.0.1"}}
	if _, err := p.AppendRecords(ctx, "dns-monitor.tmsoft.com.br.", a); err == nil ||
		!strings.Contains(err.Error(), "only TXT") {
		t.Fatalf("type A: %v", err)
	}
}

// TestACMERequestGolden grava em testdata/events/dns.acme.set.json o fs.v1.dns.acme.set real do provedor
// libdns (sem envelope, contrato 0.2.1), respondido pelo dns real, e confere as chaves com o asyncapi.
func TestACMERequestGolden(t *testing.T) {
	nc := startNATS(t)
	if _, err := dns.SubscribeACME(nc, testDNSZone(), nil); err != nil {
		t.Fatal(err)
	}
	// Um assinante comum (sem resposta) recebe a mesma requisição que o dns.
	got := make(chan []byte, 1)
	sub, err := nc.Subscribe(event.SubjectDNSACMESet, func(m *nats.Msg) {
		select {
		case got <- m.Data:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	p := &natsDNSProvider{nc: nc, timeout: 2 * time.Second}
	// Valor no formato do DNS-01 (base64url de 43 caracteres do SHA-256 do key authorization).
	const value = "Qm9n9W2qkfQx1h4rM5fJb2u8yYxT0yQ8c0xYk7oHk1E"
	recs := []libdns.Record{libdns.RR{Name: "_acme-challenge", Type: "TXT", Data: value}}
	if _, err := p.AppendRecords(context.Background(), "dns-monitor.tmsoft.com.br.", recs); err != nil {
		t.Fatal(err)
	}
	var data []byte
	select {
	case data = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no acme.set seen")
	}
	var req map[string]any
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req["name"] != "_acme-challenge.dns-monitor.tmsoft.com.br." || req["value"] != value || len(req) != 2 {
		t.Fatalf("request %s", data)
	}
	schema := block(t, readDoc(t, "eventbus/nats/asyncapi.yaml"), "ACMERequest")
	schema = schema[strings.Index(schema, "\n      payload:"):]
	for k := range req {
		if !regexp.MustCompile(`\n\s+` + regexp.QuoteMeta(k) + `:`).MatchString(schema) {
			t.Errorf("key %q not in ACMERequest", k)
		}
	}
	compareGolden(t, "dns.acme.set.json", req)
}
