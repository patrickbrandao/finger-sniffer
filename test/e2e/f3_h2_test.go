//go:build e2e

package e2e

// HTTP/2 no caminho direto (spec 010): h2c por prior knowledge e por Upgrade, e controles de resposta em h2
// (status, h=, rst=1 → RST_STREAM). O Akamai e o JA4H contra o tshark/ja4 estão no caso 7 (f3_tls_test.go).

import (
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestH2Cleartext: h2c por prior knowledge (Go net/http) e por Upgrade (curl --http2 em http://).
func TestH2Cleartext(t *testing.T) {
	t.Parallel()
	id := newID(t)
	base := "http://" + probeHost(id) + "/p/" + id + "/"

	// h2c por prior knowledge: HTTP/2 sem TLS desde o primeiro byte (net/http, Protocols)
	protos := new(http.Protocols)
	protos.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: protos, DialContext: (&net.Dialer{}).DialContext}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	for _, q := range []string{"?pk=1", "r?pk=2&status=201&h=X-Fs-E2E:H2c"} {
		resp, err := cl.Get(base + q)
		if err != nil {
			t.Fatalf("h2c prior knowledge %s: %v", q, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 || !strings.Contains(string(body), "probe_id: "+id) {
			t.Fatalf("h2c prior knowledge %s: %s %d %q", q, resp.Proto, resp.StatusCode, body)
		}
		if strings.Contains(q, "status=201") && (resp.StatusCode != 201 || resp.Header.Get("X-Fs-E2E") != "H2c") {
			t.Errorf("h2c controles: %d %v", resp.StatusCode, resp.Header)
		}
	}
	tr.CloseIdleConnections()

	out, err := exec.Command(curlLibreSSL, "-4", "-sS", "--http2", "--max-time", "20", "-w", "\n%{http_version}", base+"?upgrade=1").CombinedOutput()
	if err != nil || !strings.HasSuffix(string(out), "\n2") {
		t.Fatalf("curl --http2 (Upgrade: h2c): %v %s", err, out)
	}

	p := waitProbe(t, id, atLeast(2, 80))
	modes := map[string]record{}
	for _, c := range p.conns(80) {
		if c.HTTP2 != nil {
			modes[c.HTTP2.Mode] = c
		}
	}
	pk, ok := modes["prior-knowledge"]
	if !ok {
		t.Fatalf("sem conexão h2c prior-knowledge no registro (modos %v)", keysOf(modes))
	}
	if pk.Proto != "h2c" || !pk.HTTP2.PrefaceOK || len(pk.HTTP2.Settings) == 0 || pk.HTTP2.Akamai == "" || len(pk.HTTP2.Streams) != 2 {
		t.Errorf("prior-knowledge: proto=%s preface=%v settings=%v akamai=%q streams=%d", pk.Proto, pk.HTTP2.PrefaceOK,
			pk.HTTP2.Settings, pk.HTTP2.Akamai, len(pk.HTTP2.Streams))
	}
	for _, s := range pk.HTTP2.Streams {
		if strings.Join(s.PseudoOrder, ",") == "" || s.JA4H == nil || !strings.HasPrefix(*s.JA4H, "ge20") {
			t.Errorf("prior-knowledge stream %d: pseudo_order=%v ja4h=%v", s.StreamID, s.PseudoOrder, ptr(s.JA4H))
		}
	}
	if st := pk.HTTP2.Streams[len(pk.HTTP2.Streams)-1]; st.Status != 201 {
		t.Errorf("prior-knowledge: status do 2º stream = %d, esperado 201", st.Status)
	}
	if !hasFrame(pk.HTTP2, "out", "SETTINGS") || !hasFrame(pk.HTTP2, "in", "HEADERS") {
		t.Errorf("prior-knowledge: frames sem SETTINGS do servidor ou HEADERS do cliente: %+v", pk.HTTP2.Frames)
	}

	up, ok := modes["upgrade"]
	if !ok {
		t.Fatalf("sem conexão h2c upgrade no registro (modos %v)", keysOf(modes))
	}
	if up.Proto != "h2c" || len(up.HTTP) == 0 || ptr(up.HTTP[0].Upgrade) != "h2c" {
		t.Errorf("upgrade: proto=%s http=%d upgrade=%v", up.Proto, len(up.HTTP), func() any {
			if len(up.HTTP) == 0 {
				return nil
			}
			return ptr(up.HTTP[0].Upgrade)
		}())
	}
}

// TestH2Controls: em h2 sobre TLS, rst=1 vira RST_STREAM só daquele stream e a conexão segue servindo.
func TestH2Controls(t *testing.T) {
	t.Parallel()
	id := newID(t)
	base := "https://" + probeHost(id) + "/p/" + id + "/r?"
	tr := &http.Transport{ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}

	resp, err := cl.Get(base + "status=202")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 202 {
		t.Fatalf("status=202: %s %d", resp.Proto, resp.StatusCode)
	}
	resp, err = cl.Get(base + "rst=1&size=100000")
	if err == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "stream error") {
		t.Errorf("rst=1 em h2: esperava erro de stream (RST_STREAM), veio %v", err)
	}
	resp, err = cl.Get(base + "status=200")
	if err != nil {
		t.Fatalf("depois do RST_STREAM: %v", err)
	}
	_ = resp.Body.Close()
	tr.CloseIdleConnections()

	p := waitProbe(t, id, atLeast(1, 443))
	var c *record
	for _, x := range p.conns(443) {
		if x.HTTP2 != nil && len(x.HTTP2.Streams) >= 3 {
			c = &x
		}
	}
	if c == nil {
		t.Fatalf("sem conexão h2 com os 3 streams")
	}
	if c.Proto != "tls/h2" || c.HTTP2.Mode != "alpn" {
		t.Errorf("proto=%s mode=%s", c.Proto, c.HTTP2.Mode)
	}
	if !hasFrame(c.HTTP2, "out", "RST_STREAM") {
		t.Errorf("rst=1: nenhum RST_STREAM do servidor nos frames registrados")
	}
}

func hasFrame(h *h2Info, dir, typ string) bool {
	for _, f := range h.Frames {
		if f.Dir == dir && strings.EqualFold(f.Type, typ) {
			return true
		}
	}
	return false
}
