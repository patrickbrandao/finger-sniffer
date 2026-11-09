package store

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

func TestClientHelloLen(t *testing.T) {
	if n := clientHelloLen(clientHelloRaw(95), 0); n != 100 {
		t.Fatal(n)
	}
	if n := clientHelloLen(clientHelloRaw(95, 300), 0); n != 405 {
		t.Fatal(n)
	}
	if n := clientHelloLen(clientHelloRaw(95, 300), 1); n != 100 {
		t.Fatal(n)
	}
	if n := clientHelloLen([]byte{23, 3, 3, 0, 1, 0}, 0); n != 0 {
		t.Fatal(n)
	}
	ch := map[string]any{"client_hello_b64": base64.StdEncoding.EncodeToString(clientHelloRaw(95))}
	tcp := &tcpJSON{SegmentsIn: []timedLen{{1, 0}, {2, 60}, {3, 40}, {4, 500}}}
	if n := clientHelloSegments(ch, tcp); n != 2 {
		t.Fatal(n)
	}
	if clientHelloSegments(ch, nil) != 0 || clientHelloSegments(map[string]any{}, tcp) != 0 {
		t.Fatal("no data → 0")
	}
}

// TestClientHelloSplitInTwoSegments: ClientHello de 100 bytes em dois segmentos TCP (60 + 40) → 2.
func TestClientHelloSplitInTwoSegments(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	split := []pkt{
		{0, true, tcpSYN, 0},
		{10, false, tcpSYN | tcpACK, 0},
		{20, true, tcpACK, 0},
		{25, true, tcpACK, 60},
		{26, true, tcpACK | tcpPSH, 40},
		{35, false, tcpACK | tcpPSH, 1000},
		{1040, true, tcpFIN | tcpACK, 0},
		{1050, false, tcpFIN | tcpACK, 0},
		{1060, true, tcpACK, 0},
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, split),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 26, "", tlsHelloPayload(clientHelloRaw(95))))
	_, r := onlyConn(t, db)
	var tls map[string]any
	if err := json.Unmarshal(r.TLS, &tls); err != nil || tls["client_hello_segments"] != 2.0 {
		t.Fatalf("%v %v", tls["client_hello_segments"], err)
	}
}

// TestAlertNameFromIANA: o nome vem do pkg/iana (sem tabela própria no store).
func TestAlertNameFromIANA(t *testing.T) {
	cases := map[int]string{
		0: "close_notify", 40: "handshake_failure", 121: "ech_required", // conhecidos
		21:  "decryption_failed_RESERVED",                           // reservado: nome do registro IANA
		255: "unknown", 7: "unknown", -1: "unknown", 300: "unknown", // desconhecidos e fora de uint8
	}
	for code, want := range cases {
		if got := alertName(code); got != want {
			t.Errorf("alertName(%d) = %q, want %q", code, got, want)
		}
	}
}
