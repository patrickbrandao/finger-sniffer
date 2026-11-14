package raw

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// hugeHelloRecords monta registros TLS com um ClientHello válido de ciphers cópias de 0xc02b (nome IANA
// conhecido), repartido em registros de 16 KiB.
func hugeHelloRecords(ciphers int) []byte {
	u16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = u16(body, 2*ciphers)
	for range ciphers {
		body = u16(body, 0xc02b)
	}
	body = append(body, 1, 0)
	body = u16(body, 0)
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

// TestTLSHugeClientHelloFits: ClientHello de ~64 KiB com cifras de nome conhecido numa porta TLS do raw
// gera o evento dentro do teto com lists_truncated e os fingerprints do ClientHello completo; outra conexão
// logo depois publica sem atraso (tasks 149 e 165).
func TestTLSHugeClientHelloFits(t *testing.T) {
	env := startEnv(t, []PortSpec{{Port: 0, Mode: "echo", TLS: true}}, withTLS(t))
	rec := hugeHelloRecords(32000)
	ch, err := tlsparse.Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	full := tlsparse.NewInfo(ch, rec, 0)
	ja3.Fill(full, ch)
	ja4.Fill(full, ch, ja4.TCP)

	c := dial(t, env.addr[0])
	if _, err := c.Write(rec); err != nil {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	var hello []byte
	timeout := time.After(10 * time.Second)
	for hello == nil {
		select {
		case m := <-env.msgs:
			if len(m.Data) > event.MaxEventBytes {
				t.Fatalf("%s com %d bytes", m.Subject, len(m.Data))
			}
			if m.Subject == event.SubjectWebTLSClientHello {
				hello = m.Data
			}
		case <-timeout:
			t.Fatal("no client_hello")
		}
	}
	envl, err := event.Decode(hello)
	if err != nil {
		t.Fatal(err)
	}
	info := decodeTLSInfo(t, &envl)
	if !info.ListsTruncated || info.JA3MD5 != full.JA3MD5 || info.JA4 != full.JA4 || full.JA4 == "" {
		t.Fatalf("lists_truncated=%v ja3_md5=%s ja4=%s, completo %s %s", info.ListsTruncated, info.JA3MD5, info.JA4, full.JA3MD5, full.JA4)
	}
	_ = c.Close()
	env.waitSession(t)
	if got := env.srv.metrics.Get(MetricEventsOversize); got != 0 {
		t.Fatalf("%s = %v", MetricEventsOversize, got)
	}

	// A conexão seguinte não espera atrás de nada na fila do produtor.
	start := time.Now()
	c2 := dialTLS(t, env.addr[0], "", nil)
	if _, err := c2.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, c2, 2); got != "x\n" {
		t.Fatalf("echo = %q", got)
	}
	_ = c2.Close()
	if res := env.waitSession(t); res.clientHello == nil {
		t.Fatal("segunda sessão sem client_hello")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("segunda sessão levou %v", d)
	}
}

// TestEmitterDropsOversize: evento acima de event.MaxEventBytes não é publicado, conta em
// raw_events_oversize_total, e o seguinte sai normalmente (task 149).
func TestEmitterDropsOversize(t *testing.T) {
	pub := &fakePub{}
	m := service.NewMetrics()
	em := &emitter{pub: pub, log: quietLog(), flow: &event.Flow{L4: "tcp"}, metrics: m}
	big := event.StreamBytes{Dir: event.DirectionIn, Data: bytes.Repeat([]byte{'a'}, event.MaxEventBytes)}
	em.publish(event.SubjectRawRead, time.Now(), "", big)
	em.publish(event.SubjectRawRead, time.Now(), "", event.StreamBytes{Dir: event.DirectionIn, Data: []byte("ok")})
	msgs := pub.all()
	if len(msgs) != 1 || m.Get(MetricEventsOversize) != 1 {
		t.Fatalf("%d publicadas, oversize=%v", len(msgs), m.Get(MetricEventsOversize))
	}
	var env event.Envelope
	if err := json.Unmarshal(msgs[0].Data, &env); err != nil || len(msgs[0].Data) > event.MaxEventBytes {
		t.Fatalf("mensagem publicada inválida: %v", err)
	}
}
