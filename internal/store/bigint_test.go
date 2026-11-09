package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// Inteiros acima de 2^53 (task 062): o store não pode arredondá-los por float64 ao fundir o evento no registro.
const (
	big62    = uint64(1)<<62 - 1 // SETTINGS_MAX_FIELD_SECTION_SIZE do curl --http3-only
	big62Str = "4611686018427387903"
	big64Str = "18446744073709551615" // 2^64-1
)

// mustHaveBig confere que o JSON contém os inteiros exatos e não a forma arredondada.
func mustHaveBig(t *testing.T, where string, b []byte, want ...string) {
	t.Helper()
	s := string(b)
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Fatalf("%s: %s missing (rounded?): %s", where, w, s)
		}
	}
	if strings.Contains(s, "4611686018427388000") || strings.Contains(s, "e+18") || strings.Contains(s, "e+19") {
		t.Fatalf("%s: rounded value: %s", where, s)
	}
}

// TestBigIntHTTP3Settings: h3_settings [[6, 2^62-1]] sai idêntico no registro aberto, no fechado e no /probes.
func TestBigIntHTTP3Settings(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	info := h3Conn("h3", true, nil)
	info.H3Settings = [][2]uint64{{6, big62}, {0x2b603742, big62}}
	run(t, in, 900, udpBatch(quicClient, quicMirror, quicPackets(dcidA, 0)),
		h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 30, info))
	id, _ := onlyConn(t, db)
	check := func(where string, rec []byte) {
		t.Helper()
		var r connectionJSON
		if err := json.Unmarshal(rec, &r); err != nil {
			t.Fatal(err)
		}
		var h3 http3JSON
		if err := json.Unmarshal(r.HTTP3, &h3); err != nil {
			t.Fatalf("%s: %v %s", where, err, r.HTTP3)
		}
		if len(h3.H3Settings) != 2 || h3.H3Settings[0] != [2]uint64{6, big62} || h3.H3Settings[1][1] != big62 {
			t.Fatalf("%s: h3_settings %v", where, h3.H3Settings)
		}
		mustHaveBig(t, where, r.HTTP3, "[6,"+big62Str+"]")
	}
	q := NewQueries(db, in.flows.live, 65535)
	live, err := q.Connection(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	check("live /connections", live)
	cl := &event.HTTP3Close{By: "client", How: event.QUICCloseApplication, ErrorCode: ptrTo(uint64(0x100)), Reason: ptrTo("")}
	closing := h3Conn("h3", true, cl)
	closing.H3Settings = info.H3Settings
	run(t, in, 5000, h3Msg(t, event.SubjectWebHTTP3Connection, quicClient, dcidA, 1000, closing))
	stored, err := q.Connection(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	check("stored /connections", stored)
	p, err := q.Probe(context.Background(), probeID, 0)
	if err != nil || len(p.Connections) != 1 {
		t.Fatalf("probe %+v %v", p, err)
	}
	check("/probes", p.Connections[0])
}

// TestBigIntHTTP2Settings: settings do nível de conexão h2 com valor de 64 bits.
func TestBigIntHTTP2Settings(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebHTTP2Connection, "tcp", client, mirror, 41, "", json.RawMessage(
			`{"mode":"h2c","preface_ok":true,"settings":[[6,`+big62Str+`],[255,`+big64Str+`]],"streams":[]}`)))
	_, r := onlyConn(t, db)
	mustHaveBig(t, "http2", r.HTTP2, "[6,"+big62Str+"]", "[255,"+big64Str+"]")
}

// TestBigIntTLS: campo numérico grande do ClientHello passa intacto, e client_hello_records (json.Number) ainda
// alimenta client_hello_segments.
func TestBigIntTLS(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	hello := tlsHelloPayload(clientHelloRaw(95))
	hello["ext_big"] = json.Number(big64Str)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", hello))
	_, r := onlyConn(t, db)
	mustHaveBig(t, "tls", r.TLS, `"ext_big":`+big64Str, `"client_hello_segments":1`)
}

// TestBigIntRaw: a sessão raw (guardada crua) mantém contadores de 64 bits.
func TestBigIntRaw(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectRawSession, "tcp", client, mirror, 1040, "", json.RawMessage(`{"mode":"sink","tls":false,"bytes_in":`+big62Str+`}`)))
	_, r := onlyConn(t, db)
	mustHaveBig(t, "raw", r.Raw, `"bytes_in":`+big62Str)
}

// TestBigIntDNS: o registro DNS (refeito com probe_id/conn_id) mantém inteiros de 64 bits.
func TestBigIntDNS(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	p := dnsPayload("udp")
	p["ecs_big"] = json.Number(big64Str)
	processAt(t, in, 0, appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, 0, "t1a2b3c4", p))
	list, err := NewQueries(db, in.flows.live, 65535).DNS(context.Background(), ListFilter{Limit: 10})
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	mustHaveBig(t, "dns", list[0], `"ecs_big":`+big64Str)
}

// TestDecodeObjectUseNumber: o helper devolve json.Number e nil para não-objetos.
func TestDecodeObjectUseNumber(t *testing.T) {
	m := decodeObject([]byte(`{"v":` + big62Str + `}`))
	if n, ok := m["v"].(json.Number); !ok || n.String() != big62Str {
		t.Fatalf("%#v", m["v"])
	}
	for _, s := range []string{`[]`, `null`, `x`, ``} {
		if decodeObject([]byte(s)) != nil {
			t.Fatalf("%q must be nil", s)
		}
	}
}
