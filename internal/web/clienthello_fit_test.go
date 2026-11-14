package web

import (
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// hugeHelloRecords monta registros TLS com um ClientHello válido de ciphers cópias de 0xc02b (nome IANA
// conhecido), SNI testSNI e versões TLS 1.2/1.3, repartido em registros de 16 KiB.
func hugeHelloRecords(ciphers int) []byte {
	u16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }
	var ex []byte
	sni := []byte(testSNI)
	ex = u16(ex, 0)
	ex = u16(ex, len(sni)+5)
	ex = u16(ex, len(sni)+3)
	ex = append(ex, 0)
	ex = u16(ex, len(sni))
	ex = append(ex, sni...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = u16(body, 2*ciphers)
	for range ciphers {
		body = u16(body, 0xc02b)
	}
	body = append(body, 1, 0)
	body = u16(body, len(ex))
	body = append(body, ex...)
	n := len(body)
	msg := append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	var out []byte
	for len(msg) > 0 {
		k := min(16384, len(msg))
		out = append(out, 0x16, 0x03, 0x01, byte(k>>8), byte(k))
		out = append(out, msg[:k]...)
		msg = msg[k:]
	}
	return out
}

// TestClientHelloHugeListsFit: ClientHello com 15.000 cifras gera o evento dentro do teto, com
// lists_truncated e os fingerprints do ClientHello completo, sem contar descarte (task 165).
func TestClientHelloHugeListsFit(t *testing.T) {
	var metrics *service.Metrics
	h := newHarness(t, harnessOpts{deps: func(d *Deps) { metrics = d.Metrics }})
	rec := hugeHelloRecords(15000)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	full := tlsparse.NewInfo(ch, rec, 0)
	ja3.Fill(full, ch)
	ja4.Fill(full, ch, ja4.TCP)

	c := dial(t, h.addr443)
	if _, err := c.Write(rec); err != nil {
		t.Fatal(err)
	}
	port := srcPort(c)
	ev := h.events.wait(t, event.SubjectWebTLSClientHello, port, 1)[0]
	_ = c.Close()
	if ev.Size > event.MaxEventBytes {
		t.Fatalf("evento com %d bytes", ev.Size)
	}
	p := ev.Payload
	if p["lists_truncated"] != true || p["sni"] != testSNI {
		t.Fatalf("lists_truncated=%v sni=%v", p["lists_truncated"], p["sni"])
	}
	if p["ja3_md5"] != full.JA3MD5 || p["ja4"] != full.JA4 || full.JA4 == "" {
		t.Fatalf("fingerprints %v %v, completo %s %s", p["ja3_md5"], p["ja4"], full.JA3MD5, full.JA4)
	}
	if got := metrics.Get(MetricEventsOversize); got != 0 {
		t.Fatalf("%s = %v", MetricEventsOversize, got)
	}
}
