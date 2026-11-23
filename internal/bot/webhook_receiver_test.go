package bot

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hookReceiver devolve o cliente e a URL do webhook de um receptor httptest TLS. A URL usa o nome example.com (o
// certificado do httptest vale para ele) em vez do 127.0.0.1 do rcv.URL, que o key create recusa (task 372); o
// cliente conecta esse nome ao endereço do receptor.
func hookReceiver(t *testing.T, rcv *httptest.Server, path string) (*http.Client, string) {
	t.Helper()
	tr, ok := rcv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("transporte do httptest inesperado")
	}
	tr = tr.Clone()
	addr := rcv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	_, port, _ := net.SplitHostPort(addr)
	return &http.Client{Transport: tr}, "https://example.com:" + port + path
}
