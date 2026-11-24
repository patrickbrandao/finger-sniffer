package web

import (
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// issueHelloRecords monta um ClientHello com SNI, ALPN repetido (h2 e depois x1) e cipher_suites de tamanho
// ímpar, num registro só.
func issueHelloRecords() []byte {
	u16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }
	ext := func(b []byte, typ int, data ...byte) []byte {
		b = u16(b, typ)
		b = u16(b, len(data))
		return append(b, data...)
	}
	sni := []byte(testSNI)
	sniData := u16(nil, len(sni)+3)
	sniData = append(sniData, 0)
	sniData = u16(sniData, len(sni))
	sniData = append(sniData, sni...)
	var ex []byte
	ex = ext(ex, 0x0000, sniData...)
	ex = ext(ex, 0x0010, 0, 3, 2, 'h', '2')
	ex = ext(ex, 0x0010, 0, 3, 2, 'x', '1')
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 3, 0x13, 0x01, 0xff) // cipher_suites ímpar
	body = append(body, 1, 0)
	body = u16(body, len(ex))
	body = append(body, ex...)
	n := len(body)
	msg := append([]byte{1, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	out := []byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}
	return append(out, msg...)
}

// TestClientHelloParseIssuesEvent (task 386): o evento fs.v1.web.tls.client_hello de um ClientHello com
// extensão repetida e cipher_suites ímpar traz extension_errors (duplicate) e field_errors (odd_length), com as
// chaves do contrato (TLSInfo/TLSParseIssue), e o ALPN da primeira ocorrência.
func TestClientHelloParseIssuesEvent(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c := dial(t, h.addr443)
	defer func() { _ = c.Close() }()
	if _, err := c.Write(issueHelloRecords()); err != nil {
		t.Fatal(err)
	}
	ev := h.events.wait(t, event.SubjectWebTLSClientHello, srcPort(c), 1)[0]
	checkContract(t, contractBlocks(t), ev)
	p := ev.Payload
	ee, _ := p["extension_errors"].([]any)
	fe, _ := p["field_errors"].([]any)
	if len(ee) != 1 || len(fe) != 1 {
		t.Fatalf("extension_errors %v field_errors %v", p["extension_errors"], p["field_errors"])
	}
	e0, _ := ee[0].(map[string]any)
	f0, _ := fe[0].(map[string]any)
	if e0["field"] != "extension 0x0010" || e0["error"] != "duplicate" || e0["offset"].(float64) <= 0 {
		t.Fatalf("extension_errors[0] %v", e0)
	}
	if f0["field"] != "cipher_suites" || f0["error"] != "odd_length" || f0["offset"].(float64) != 39 {
		t.Fatalf("field_errors[0] %v", f0)
	}
	if alpn, _ := p["alpn"].([]any); len(alpn) != 1 || alpn[0] != "h2" || p["sni"] != testSNI {
		t.Fatalf("alpn %v sni %v", p["alpn"], p["sni"])
	}
}
