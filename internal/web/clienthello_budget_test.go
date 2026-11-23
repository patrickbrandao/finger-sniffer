package web

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// oneByteRecords reparte os registros de rec (já remontados) em registros de 1 byte de handshake.
func oneByteRecords(t *testing.T, rec []byte) (msg, out []byte) {
	t.Helper()
	r, err := tlsparse.Reassemble(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range r.Message {
		out = append(out, 0x16, 0x03, 0x01, 0, 1, b)
	}
	return r.Message, out
}

// TestClientHelloCaptureBudget (task 323, ADR 0070 item 7): um ClientHello de ~30 KB em registros de 1 byte
// reserva a mensagem remontada e os registros crus (até 16 KiB) enquanto espera o resto; completo, sai com os
// fingerprints da mensagem inteira e client_hello_truncated, e a reserva volta a zero depois de publicar.
func TestClientHelloCaptureBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	msg, stream := oneByteRecords(t, hugeHelloRecords(15000))
	ch, err := tlsparse.ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := ja4.Compute(ch, ja4.TCP)

	// incompleto: a captura fica reservada enquanto o cliente não termina
	c := dial(t, h.addr443)
	if _, err := c.Write(stream[:len(stream)-6]); err != nil {
		t.Fatal(err)
	}
	floor := int64(len(msg) + tlsparse.MaxCapturedRecords)
	waitFor(t, 5*time.Second, func() bool { return h.srv.budget.inUse() >= floor },
		func() string { return "reserva da captura não apareceu" })
	_ = c.Close()
	waitFor(t, 5*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return "reserva não voltou a zero" })

	// completo: evento com a mensagem inteira, registros crus cortados e reserva solta depois de publicar
	c = dial(t, h.addr443)
	defer func() { _ = c.Close() }()
	if _, err := c.Write(stream); err != nil {
		t.Fatal(err)
	}
	ev := h.events.wait(t, event.SubjectWebTLSClientHello, srcPort(c), 1)[0]
	p := ev.Payload
	if p["ja4"] != want.JA4 || p["client_hello_truncated"] != true || p["sni"] != testSNI {
		t.Fatalf("ja4 %v (quer %s) truncated %v sni %v", p["ja4"], want.JA4, p["client_hello_truncated"], p["sni"])
	}
	waitFor(t, 5*time.Second, func() bool { return h.srv.budget.inUse() == 0 },
		func() string { return "reserva presa depois de publicar" })
}

// TestClientHelloCaptureNoBudget (task 323): sem orçamento para a captura, a conexão fecha antes do
// handshake e a recusa conta em web_input_budget_denied_total.
func TestClientHelloCaptureNoBudget(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	b := h.srv.budget
	free := b.limit - b.inUse()
	if !b.reserve(free) {
		t.Fatal("reserva do teste")
	}
	defer b.release(free)
	denied := h.srv.metrics.Get(MetricInputBudgetDenied)
	c := dial(t, h.addr443)
	defer func() { _ = c.Close() }()
	if _, err := c.Write(hugeHelloRecords(10)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// o fechamento chega como FIN ou RST (bytes do cliente não lidos); prazo vencido é falha
	n, err := io.ReadAll(c)
	var ne net.Error
	if len(n) != 0 || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("esperava fechamento sem resposta: %d bytes, %v", len(n), err)
	}
	if got := h.srv.metrics.Get(MetricInputBudgetDenied); got <= denied {
		t.Fatalf("denied %v → %v", denied, got)
	}
	if b.inUse() != free {
		t.Fatalf("em uso %d, quer %d", b.inUse(), free)
	}
}
