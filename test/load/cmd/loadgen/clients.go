//go:build load

package main

// Clientes de carga: h1 em claro, h1 sobre TLS, h2, h3 e raw (echo, banner, sink). Cada um abre uma única
// conexão para um probe novo, faz -reqs trocas espaçadas ao longo de -life e fecha; o instante do fim é o
// retorno do Close no cliente (base do RNF-04).

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const zone = "dns-monitor.tmsoft.com.br"

// newProbeID devolve um probe ID novo ([a-z0-9]{16}, começa por "ld" para achar nos logs).
func newProbeID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 14)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "ld" + string(b)
}

// connSpec descreve um tipo de conexão do mix.
type connSpec struct {
	Kind string // h1, h1tls, h2, h3, raw-echo, raw-banner, raw-sink
	Port int
}

// connResult é o que o cliente sabe da conexão.
type connResult struct {
	Spec   connSpec
	Probe  string
	Start  time.Time // antes do dial
	End    time.Time // retorno do Close (zero se falhou antes)
	Reqs   int
	Err    string
	Closed bool // fechou normalmente (sem erro)
}

// gapSleep espera até o instante base+d ou o contexto acabar.
func gapSleep(ctx context.Context, base time.Time, d time.Duration) error {
	t := time.NewTimer(time.Until(base.Add(d)))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// trackedDialer guarda a conexão TCP aberta pelo Transport para fechá-la explicitamente.
type trackedDialer struct {
	ip   string
	port int
	mu   sync.Mutex
	conn net.Conn
}

func (d *trackedDialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(d.ip, strconv.Itoa(d.port)))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.conn = c
	d.mu.Unlock()
	return c, nil
}

func (d *trackedDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		_ = d.conn.Close()
	}
}

// runConn executa uma conexão do tipo pedido até o fim.
func runConn(ctx context.Context, ip string, spec connSpec, reqs int, life time.Duration) connResult {
	r := connResult{Spec: spec, Probe: newProbeID(), Start: time.Now()}
	var err error
	switch spec.Kind {
	case "h1", "h1tls", "h2":
		err = runHTTP(ctx, ip, &r, reqs, life)
	case "h3":
		err = runH3(ctx, ip, &r, reqs, life)
	case "raw-echo", "raw-banner", "raw-sink":
		err = runRaw(ctx, ip, &r, reqs, life)
	default:
		err = fmt.Errorf("tipo desconhecido %q", spec.Kind)
	}
	if err != nil {
		r.Err = err.Error()
	} else {
		r.Closed = true
	}
	return r
}

func probeURL(r *connResult, scheme string, defPort int) string {
	host := r.Probe + "." + zone
	if r.Spec.Port != defPort {
		host = net.JoinHostPort(host, strconv.Itoa(r.Spec.Port))
	}
	return scheme + "://" + host + "/p/" + r.Probe + "/"
}

func fetch(ctx context.Context, c *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("status %d", resp.StatusCode)
	}
	return err
}

func runHTTP(ctx context.Context, ip string, r *connResult, reqs int, life time.Duration) error {
	d := &trackedDialer{ip: ip, port: r.Spec.Port}
	tr := &http.Transport{DialContext: d.dial, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableCompression: true}
	tr.Protocols = new(http.Protocols)
	url := probeURL(r, "https", 443)
	switch r.Spec.Kind {
	case "h1":
		tr.Protocols.SetHTTP1(true)
		url = probeURL(r, "http", 80)
	case "h1tls":
		tr.Protocols.SetHTTP1(true)
	case "h2":
		tr.Protocols.SetHTTP2(true)
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	defer d.close()
	for i := 0; i < reqs; i++ {
		if err := gapSleep(ctx, r.Start, time.Duration(i)*life/time.Duration(reqs)); err != nil {
			return err
		}
		if err := fetch(ctx, client, url); err != nil {
			return err
		}
		r.Reqs++
	}
	if err := gapSleep(ctx, r.Start, life); err != nil {
		return err
	}
	tr.CloseIdleConnections()
	d.close()
	r.End = time.Now()
	return nil
}

func runH3(ctx context.Context, ip string, r *connResult, reqs int, life time.Duration) error {
	var mu sync.Mutex
	var pcs []net.PacketConn
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			pc, err := net.ListenUDP("udp4", nil)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			pcs = append(pcs, pc)
			mu.Unlock()
			return quic.DialEarly(ctx, pc, &net.UDPAddr{IP: net.ParseIP(ip), Port: r.Spec.Port}, tlsCfg, cfg)
		},
	}
	closeAll := func() {
		_ = tr.Close()
		mu.Lock()
		for _, pc := range pcs {
			_ = pc.Close()
		}
		pcs = nil
		mu.Unlock()
	}
	defer closeAll()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	url := probeURL(r, "https", 443)
	for i := 0; i < reqs; i++ {
		if err := gapSleep(ctx, r.Start, time.Duration(i)*life/time.Duration(reqs)); err != nil {
			return err
		}
		if err := fetch(ctx, client, url); err != nil {
			return err
		}
		r.Reqs++
	}
	if err := gapSleep(ctx, r.Start, life); err != nil {
		return err
	}
	// Close manda CONNECTION_CLOSE (H3_NO_ERROR) antes de soltar o socket.
	_ = tr.Close()
	r.End = time.Now()
	closeAll()
	return nil
}

func runRaw(ctx context.Context, ip string, r *connResult, reqs int, life time.Duration) error {
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(r.Spec.Port)))
	if err != nil {
		return err
	}
	defer c.Close() //nolint:errcheck // fechado explicitamente no fim
	tc := c.(*net.TCPConn)
	_ = c.SetDeadline(time.Now().Add(life + 15*time.Second))
	br := bufio.NewReader(c)
	if r.Spec.Kind != "raw-echo" {
		// banner: o servidor fala primeiro
		if _, err := br.ReadString('\n'); err != nil {
			return fmt.Errorf("banner: %w", err)
		}
	}
	probe := "PROBE " + r.Probe
	if r.Spec.Kind == "raw-sink" {
		probe += " mode=sink"
	}
	if _, err := io.WriteString(c, probe+"\r\n"); err != nil {
		return err
	}
	for i := 0; i < reqs; i++ {
		if err := gapSleep(ctx, r.Start, time.Duration(i)*life/time.Duration(reqs)); err != nil {
			return err
		}
		line := fmt.Sprintf("load %s %d %s\n", r.Probe, i, strings.Repeat("x", 32))
		if _, err := io.WriteString(c, line); err != nil {
			return err
		}
		if r.Spec.Kind == "raw-echo" {
			buf := make([]byte, len(line))
			if _, err := io.ReadFull(br, buf); err != nil {
				return fmt.Errorf("eco: %w", err)
			}
			if string(buf) != line {
				return fmt.Errorf("eco diferente: %q", buf)
			}
		}
		r.Reqs++
	}
	if err := gapSleep(ctx, r.Start, life); err != nil {
		return err
	}
	// meio-fechamento: o servidor responde com a mensagem de fim e fecha (spec 006)
	if err := tc.CloseWrite(); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, br); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("depois do meio-fechamento: %w", err)
	}
	_ = c.Close()
	r.End = time.Now()
	return nil
}
