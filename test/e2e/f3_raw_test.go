//go:build e2e

package e2e

// Caso 8 da matriz da spec 017 no caminho direto: o que um CONNECT para portas baixas entregaria ao espelho.
// Portas cruas em banner (21, 25) e echo (7) com a linha PROBE e meio-fechamento; TLS na 993 (tls-banner) e
// TLS numa porta em claro (echo na 7, spec 006 RF-03); modo source (critério de aceite da spec 006).

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const halfCloseMsg = "half-close test\r\n"

var banners = map[int]string{
	21:  "220 finger-sniffer FTP ready\r\n",
	25:  "220 finger-sniffer ESMTP ready\r\n",
	993: "* OK finger-sniffer IMAP ready\r\n",
}

// TestCase8RawPorts: banner antes de o cliente falar, PROBE não ecoado, eco, e a mensagem do servidor depois do
// FIN do cliente (meio-fechamento) registrada.
func TestCase8RawPorts(t *testing.T) {
	t.Parallel()
	id := newID(t)
	payload := "line one\r\nline two, still open\r\n"

	for _, port := range []int{21, 25} {
		c := dialTCP(t, port)
		// o servidor fala primeiro
		if got := string(c.readN(t, len(banners[port]))); got != banners[port] {
			t.Fatalf("porta %d: banner %q", port, got)
		}
		c.send(t, "PROBE "+id+"\r\n")
		c.send(t, payload)
		time.Sleep(100 * time.Millisecond)
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		rest, err := c.readAll(10 * time.Second)
		if err != nil || string(rest) != halfCloseMsg {
			t.Errorf("porta %d: depois do FIN do cliente veio %q / %v, esperado %q", port, rest, err, halfCloseMsg)
		}
		_ = c.Close()
	}

	c := dialTCP(t, 7)
	c.send(t, "PROBE "+id+"\r\n")
	c.send(t, payload)
	if got := string(c.readN(t, len(payload))); got != payload {
		t.Errorf("echo: %q, esperado %q (a linha PROBE não é ecoada)", got, payload)
	}
	_ = c.CloseWrite()
	if rest, err := c.readAll(10 * time.Second); err != nil || string(rest) != halfCloseMsg {
		t.Errorf("echo: depois do FIN do cliente veio %q / %v", rest, err)
	}
	_ = c.Close()

	// source: n bytes depois do banner e o servidor fecha
	c = dialTCP(t, 21)
	c.readN(t, len(banners[21]))
	c.send(t, "PROBE "+id+" mode=source n=1000\r\n")
	if got, err := c.readAll(15 * time.Second); err != nil || len(got) != 1000 {
		t.Errorf("source n=1000: %d bytes / %v", len(got), err)
	}
	_ = c.Close()

	p := waitProbe(t, id, func(p *probeResp) bool {
		return len(p.conns(21)) >= 2 && len(p.conns(25)) >= 1 && len(p.conns(7)) >= 1
	})
	for _, rc := range p.Connections {
		r := rc.Raw
		if r == nil {
			t.Errorf("%s (porta %d): sem raw", rc.ConnID, rc.Dst.Port)
			continue
		}
		if rc.Proto != "raw" || r.TLS || ptr(r.ProbeLine) == "<nil>" || !strings.HasPrefix(ptr2(r.ProbeLine), "PROBE "+id) {
			t.Errorf("%s (porta %d): proto=%s tls=%v probe_line=%v", rc.ConnID, rc.Dst.Port, rc.Proto, r.TLS, ptr(r.ProbeLine))
		}
		in := rawStream(t, rc.ConnID, "in")
		out := rawStream(t, rc.ConnID, "out")
		switch {
		case r.Mode == "source":
			if len(r.WritesOut) == 0 || !bytes.HasPrefix(out, []byte(banners[21])) || len(out) != len(banners[21])+1000 {
				t.Errorf("%s source: out=%d bytes writes_out=%d", rc.ConnID, len(out), len(r.WritesOut))
			}
		case rc.Dst.Port == 7:
			if r.Mode != "echo" || string(in) != "PROBE "+id+"\r\n"+payload || string(out) != payload+halfCloseMsg {
				t.Errorf("%s echo: mode=%s in=%q out=%q", rc.ConnID, r.Mode, in, out)
			}
			checkHalfClose(t, rc)
		default:
			if r.Mode != "banner" || ptr2(r.Banner) != banners[rc.Dst.Port] || string(in) != "PROBE "+id+"\r\n"+payload ||
				string(out) != banners[rc.Dst.Port]+halfCloseMsg || len(r.ReadsIn) == 0 {
				t.Errorf("%s banner %d: mode=%s banner=%q in=%q out=%q reads_in=%d", rc.ConnID, rc.Dst.Port, r.Mode, ptr2(r.Banner),
					in, out, len(r.ReadsIn))
			}
			checkHalfClose(t, rc)
		}
	}
}

func checkHalfClose(t *testing.T, rc record) {
	t.Helper()
	hc := rc.Raw.HalfClose
	if hc == nil || !hc.ServerSentAfterClientFin || hc.Bytes != len(halfCloseMsg) {
		t.Errorf("%s: half_close = %+v, esperado server_sent_after_client_fin=true, bytes=%d", rc.ConnID, hc, len(halfCloseMsg))
	}
	if !rc.Close.HalfClose || rc.Close.By != "client" {
		t.Errorf("%s: close = %+v, esperado half_close=true pelo cliente", rc.ConnID, rc.Close)
	}
}

// TestCase8RawTLS: TLS na 993 (tls-banner) com Go e openssl s_client, e TLS na porta 7 em claro (o raw termina
// o TLS por detecção e ecoa dentro do túnel). O probe vem do SNI.
func TestCase8RawTLS(t *testing.T) {
	t.Parallel()
	id := newID(t)
	sni := probeHost(id)

	// Go na 993: certificado válido para o nome do probe, banner dentro do TLS, meio-fechamento
	d := &net.Dialer{Timeout: 10 * time.Second}
	tc, err := tls.DialWithDialer(d, "tcp4", fmt.Sprintf("%s:993", vps4), &tls.Config{ServerName: sni})
	if err != nil {
		t.Fatalf("TLS na 993: %v", err)
	}
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	got := make([]byte, len(banners[993]))
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != banners[993] {
		t.Fatalf("993: banner %q / %v", got, err)
	}
	_, _ = io.WriteString(tc, "a1 CAPABILITY\r\n")
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(tc)
	if string(rest) != halfCloseMsg {
		t.Errorf("993: depois do close_notify e do FIN veio %q", rest)
	}
	_ = tc.Close()

	// Go na 7 (echo em claro) com TLS
	tc, err = tls.DialWithDialer(d, "tcp4", fmt.Sprintf("%s:7", vps4), &tls.Config{ServerName: sni})
	if err != nil {
		t.Fatalf("TLS na 7: %v", err)
	}
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(tc, "echo over tls\r\n")
	got = make([]byte, len("echo over tls\r\n"))
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != "echo over tls\r\n" {
		t.Errorf("TLS na 7: eco %q / %v", got, err)
	}
	_ = tc.Close()

	// openssl s_client (LibreSSL do macOS) na 993: completa o TLS e recebe "* OK" (critério da spec 006)
	// sem -quiet (que implica -ign_eof): o stdin fecha 2 s depois e o s_client encerra a sessão
	cmd := exec.Command("/usr/bin/openssl", "s_client", "-connect", vps4+":993", "-servername", sni, "-verify_return_error")
	pr, pw := io.Pipe()
	cmd.Stdin = pr
	go func() {
		_, _ = io.WriteString(pw, "a1 LOGOUT\r\n")
		time.Sleep(2 * time.Second)
		_ = pw.Close()
	}()
	out, err := runWithTimeout(cmd, 20*time.Second)
	if !strings.Contains(out, "* OK finger-sniffer IMAP ready") {
		t.Errorf("openssl s_client na 993: %v\n%s", err, out)
	}

	p := waitProbe(t, id, func(p *probeResp) bool { return len(p.conns(993)) >= 2 && len(p.conns(7)) >= 1 })
	for _, rc := range p.Connections {
		if rc.Proto != "tls/raw" || rc.TLS == nil || rc.Raw == nil || !rc.Raw.TLS || ptr2(rc.TLS.SNI) != sni {
			t.Errorf("%s (porta %d): proto=%s tls=%v raw=%+v", rc.ConnID, rc.Dst.Port, rc.Proto, rc.TLS != nil, rc.Raw)
			continue
		}
		if rc.TLS.JA4 == "" || rc.TLS.ClientHelloB64 == "" {
			t.Errorf("%s: TLS sem JA4/ClientHello", rc.ConnID)
		}
		switch rc.Dst.Port {
		case 993:
			if rc.Raw.Mode != "banner" || ptr2(rc.Raw.Banner) != banners[993] {
				t.Errorf("%s: 993 mode=%s banner=%q", rc.ConnID, rc.Raw.Mode, ptr2(rc.Raw.Banner))
			}
		case 7:
			if rc.Raw.Mode != "echo" {
				t.Errorf("%s: 7 com TLS mode=%s", rc.ConnID, rc.Raw.Mode)
			}
		}
	}
	// a conexão do Go na 993 mostra o meio-fechamento dentro do TLS
	found := false
	for _, rc := range p.conns(993) {
		if rc.Raw != nil && rc.Raw.HalfClose != nil && rc.Raw.HalfClose.ServerSentAfterClientFin {
			found = true
		}
	}
	if !found {
		t.Errorf("993: nenhuma conexão com half_close.server_sent_after_client_fin=true")
	}
}

// runWithTimeout roda o comando com prazo e devolve a saída combinada.
func runWithTimeout(cmd *exec.Cmd, d time.Duration) (string, error) {
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		werr := <-done
		return buf.String(), fmt.Errorf("prazo de %s esgotado (%v)", d, werr)
	}
}
