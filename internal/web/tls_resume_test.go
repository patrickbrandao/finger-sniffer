package web

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// TestTLSResumption confere que o web retoma sessões TLS entre conexões TCP (task 346): com o mesmo
// ClientSessionCache, a segunda conexão retoma no cliente, o evento de handshake marca resumed=true e o
// ClientHello cru da conexão retomada (com pre_shared_key no 1.3, session_ticket no 1.2) continua publicado
// uma vez, com JA4.
func TestTLSResumption(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, tc := range []struct {
		name    string
		version uint16
		ja4     string
		ext     string
	}{
		{"tls13", tls.VersionTLS13, "t13d", "pre_shared_key"},
		{"tls12", tls.VersionTLS12, "t12d", "session_ticket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := tls.NewLRUClientSessionCache(4)
			var ports []int
			for i := range 2 {
				raw := dial(t, h.addr443)
				c := tls.Client(raw, &tls.Config{
					ServerName: testSNI, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"},
					MinVersion: tc.version, MaxVersion: tc.version, ClientSessionCache: cache,
				})
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.Handshake(); err != nil {
					t.Fatal(err)
				}
				if got, want := c.ConnectionState().DidResume, i == 1; got != want {
					t.Fatalf("conn %d: DidResume %v, want %v", i, got, want)
				}
				// Uma troca completa: no 1.3 o cliente só guarda o ticket ao ler o NewSessionTicket pós-handshake.
				cl := newClient(t, c)
				cl.send(get("/", testSNI))
				cl.response("GET")
				_ = c.Close()
				ports = append(ports, srcPort(c))
			}
			for i, port := range ports {
				hs := h.events.wait(t, event.SubjectWebTLSHandshake, port, 1)
				neg, _ := hs[0].Payload["negotiated"].(map[string]any)
				if neg == nil || neg["resumed"] != (i == 1) {
					t.Fatalf("conn %d: handshake %v", i, hs[0].Payload)
				}
				chs := h.events.wait(t, event.SubjectWebTLSClientHello, port, 1)
				if len(chs) != 1 {
					t.Fatalf("conn %d: %d client hello events", i, len(chs))
				}
				p := chs[0].Payload
				ja4, _ := p["ja4"].(string)
				if !strings.HasPrefix(ja4, tc.ja4) || p["client_hello_b64"] == nil {
					t.Fatalf("conn %d: client hello %v", i, p)
				}
				if i == 1 && p[tc.ext] != true {
					t.Fatalf("conn %d: %s not seen in resumed client hello: %v", i, tc.ext, p)
				}
			}
		})
	}
}
