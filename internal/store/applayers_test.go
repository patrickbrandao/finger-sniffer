package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/event"
)

// clientHelloRaw monta registros TLS de handshake com n bytes de corpo cada.
func clientHelloRaw(bodies ...int) []byte {
	var b []byte
	for _, n := range bodies {
		b = append(b, 22, 3, 1, byte(n>>8), byte(n))
		b = append(b, make([]byte, n)...)
		if len(b) > 5 && b[5] == 0 {
			b[5] = 1 // client_hello
		}
	}
	return b
}

// tlsHelloPayload é um TLSInfo sintético (subconjunto do contrato).
func tlsHelloPayload(raw []byte) map[string]any {
	return map[string]any{
		"client_hello_b64": base64.StdEncoding.EncodeToString(raw), "client_hello_truncated": false,
		"client_hello_records": 1, "record_version": 769, "handshake_version": 771, "session_id_len": 32,
		"sni": "t1a2b3c4.dns-monitor.tmsoft.com.br", "alpn": []string{"http/1.1"},
		"cipher_suites": []map[string]any{{"code": 4865, "name": "TLS_AES_128_GCM_SHA256"}},
		"ja3":           "771,4865,0-16,29,0", "ja3_md5": "d41d8cd98f00b204e9800998ecf8427e",
		"ja4": "t13d0102h1_0b5e1e0e6d6c_7f0d0b5c1d2e", "ja4_r": "t13d0102h1_1301_0000,0010",
	}
}

func handshakePayload() event.TLSHandshake {
	alpn, ms := "http/1.1", 12.5
	return event.TLSHandshake{
		Negotiated:  &event.TLSNegotiated{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Group: "x25519", ALPN: &alpn},
		HandshakeMs: &ms, Alerts: []event.TLSAlert{{Dir: event.DirectionIn, Level: 1, Description: 0}},
	}
}

func http1Payload(index int, version string) map[string]any {
	head := "GET /p/t1a2b3c4/ " + version + "\r\nHost: t1a2b3c4.dns-monitor.tmsoft.com.br\r\n\r\n"
	return map[string]any{
		"index": index, "in_offset": 0, "out_offset": 0, "raw_head_b64": base64.StdEncoding.EncodeToString([]byte(head)),
		"request_line": map[string]any{"method": "GET", "target": "/p/t1a2b3c4/", "form": "origin", "version": version, "terminator": "crlf"},
		"fields":       [][]string{{"Host", ": ", "t1a2b3c4.dns-monitor.tmsoft.com.br", "crlf"}},
		"field_count":  1, "head_size": len(head), "status": 200, "response_sent_size": 120,
		// instantes da aplicação (ADR 0029), 10 ms por requisição a partir de 30 ms
		"request_started_at": tsAt(30 + 10*index), "request_ended_at": tsAt(31 + 10*index),
		"response_started_at": tsAt(33 + 10*index), "response_ended_at": tsAt(35 + 10*index),
	}
}

// reqTimes são os quatro instantes de uma requisição (ADR 0029) como chegam no registro.
type reqTimes struct {
	RequestStartedAt  *string `json:"request_started_at"`
	RequestEndedAt    *string `json:"request_ended_at"`
	ResponseStartedAt *string `json:"response_started_at"`
	ResponseEndedAt   *string `json:"response_ended_at"`
}

func (r reqTimes) String() string {
	s := func(p *string) string {
		if p == nil {
			return "null"
		}
		return *p
	}
	return s(r.RequestStartedAt) + " " + s(r.RequestEndedAt) + " " + s(r.ResponseStartedAt) + " " + s(r.ResponseEndedAt)
}

// TestLayersRequestTimes: os instantes de cada requisição e resposta publicados pelo web chegam inalterados em
// http[], http2.streams[] e http3.requests[] (spec 013 RF-01, ADR 0029); o ts do envelope não é copiado.
func TestLayersRequestTimes(t *testing.T) {
	want := tsAt(30) + " " + tsAt(31) + " " + tsAt(33) + " " + tsAt(35)
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, "", http1Payload(0, "HTTP/1.1")))
	_, r := onlyConn(t, db)
	var h1 reqTimes
	if len(r.HTTP) != 1 || json.Unmarshal(r.HTTP[0], &h1) != nil || h1.String() != want {
		t.Fatalf("http[0] = %s, quer %s", h1, want)
	}

	in, db = newTestIngestor(t, nil)
	stream := map[string]any{
		"stream_id": 1, "status": 200, "request_started_at": tsAt(30), "request_ended_at": tsAt(31),
		"response_started_at": tsAt(33), "response_ended_at": tsAt(35),
	}
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebHTTP2Stream, "tcp", client, mirror, 40, "", stream),
		appMsg(t, event.SubjectWebHTTP2Connection, "tcp", client, mirror, 41, "", map[string]any{"mode": "alpn", "preface_ok": true, "streams": []any{}}))
	_, r = onlyConn(t, db)
	var h2 struct {
		Streams []reqTimes `json:"streams"`
	}
	if json.Unmarshal(r.HTTP2, &h2) != nil || len(h2.Streams) != 1 || h2.Streams[0].String() != want {
		t.Fatalf("http2 = %s, quer %s", r.HTTP2, want)
	}

	in, _ = newTestIngestor(t, nil)
	msgs := h3Session(t, 1000)
	run(t, in, 900, msgs[:6]...)
	run(t, in, 1100, msgs[6])
	run(t, in, 3100)
	_, r = onlyConn(t, in.db)
	var h3 struct {
		Requests []reqTimes `json:"requests"`
	}
	r0 := h3Req(0, "/", 200)
	w3 := reqTimes{r0.RequestStartedAt, r0.RequestEndedAt, r0.ResponseStartedAt, r0.ResponseEndedAt}.String()
	if json.Unmarshal(r.HTTP3, &h3) != nil || len(h3.Requests) != 2 || h3.Requests[0].String() != w3 || h3.Requests[0].RequestStartedAt == nil {
		t.Fatalf("http3 = %s, quer %s", r.HTTP3, w3)
	}
}

func TestLayersTLSAndHTTP1(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "t1a2b3c4", tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 38, "", handshakePayload()),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 45, "", http1Payload(1, "HTTP/1.1")),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, "", http1Payload(0, "HTTP/1.0")))
	_, r := onlyConn(t, db)
	if r.Proto != "tls/http1.0" || r.Requests != 2 || len(r.HTTP) != 2 {
		t.Fatalf("proto %q requests %d http %d", r.Proto, r.Requests, len(r.HTTP))
	}
	var first struct{ Index int }
	_ = json.Unmarshal(r.HTTP[0], &first)
	if first.Index != 0 {
		t.Fatal("http[] must be ordered by index")
	}
	var tls map[string]any
	_ = json.Unmarshal(r.TLS, &tls)
	if tls["sni"] != "t1a2b3c4.dns-monitor.tmsoft.com.br" || tls["handshake_ms"] != 12.5 || tls["client_hello_segments"] != 1.0 {
		t.Fatalf("tls %v", tls)
	}
	alerts, _ := tls["alerts"].([]any)
	if len(alerts) != 1 || alerts[0].(map[string]any)["name"] != "close_notify" {
		t.Fatalf("alerts %v", tls["alerts"])
	}
	if r.Times.TLSDone == nil || *r.Times.TLSDone != tsAt(38) {
		t.Fatalf("tls_done %v", r.Times.TLSDone)
	}
	if count(t, db, "SELECT count(*) FROM connections WHERE proto = 'tls/http1.0'") != 1 {
		t.Fatal("proto column")
	}
}

// TestLayersTLSFailedHandshake: handshake sem negotiated (cliente mandou só o ClientHello e fechou com FIN) não
// preenche times.tls_done (task 125).
func TestLayersTLSFailedHandshake(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 38, "", event.TLSHandshake{Alerts: []event.TLSAlert{}}))
	_, r := onlyConn(t, db)
	if r.Times == nil || r.Times.TLSDone != nil {
		t.Fatalf("tls_done %v", r.Times)
	}
	var tls map[string]any
	if json.Unmarshal(r.TLS, &tls) != nil || tls["negotiated"] != nil {
		t.Fatalf("tls %s", r.TLS)
	}
}

func tsAt(ms int) string { return *tsPtr(base + int64(ms)*1e6) }

// TestLayersLiveRecord: as camadas aparecem no registro ao vivo e nas colunas antes do fim.
func TestLayersLiveRecord(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 100, batch(client, mirror, protoTCP, fullTCP[:4]),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 30, "t1a2b3c4", http1Payload(0, "HTTP/1.1")))
	id, _ := onlyConn(t, db)
	r := recordOf(t, in, id)
	if r.Proto != "http1.1" || r.Requests != 1 || r.Ended != nil {
		t.Fatalf("%+v", r)
	}
	list, err := NewQueries(db, in.flows.live, 65535).Connections(context.Background(), ListFilter{DstPort: -1, Limit: 10})
	if err != nil || len(list) != 1 || list[0].Proto != "http1.1" || list[0].ProbeID == nil {
		t.Fatalf("%+v %v", list, err)
	}
}

func TestLayersHTTP2(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebHTTP2Stream, "tcp", client, mirror, 40, "", map[string]any{"stream_id": 1, "status": 404}),
		appMsg(t, event.SubjectWebHTTP2Connection, "tcp", client, mirror, 41, "", map[string]any{"mode": "alpn", "preface_ok": true, "akamai": "1:65536|0|0|m,a,s,p", "streams": []any{}}),
		appMsg(t, event.SubjectWebHTTP2Stream, "tcp", client, mirror, 42, "", map[string]any{"stream_id": 3, "status": 200}),
		appMsg(t, event.SubjectWebHTTP2Stream, "tcp", client, mirror, 43, "", map[string]any{"stream_id": 1, "status": 200}))
	_, r := onlyConn(t, db)
	var h2 struct {
		Akamai  string
		Streams []struct {
			StreamID int `json:"stream_id"`
			Status   int
		}
	}
	_ = json.Unmarshal(r.HTTP2, &h2)
	if r.Proto != "tls/h2" || r.Requests != 2 || h2.Akamai == "" || len(h2.Streams) != 2 || h2.Streams[0].StreamID != 1 || h2.Streams[0].Status != 200 {
		t.Fatalf("%q %d %+v", r.Proto, r.Requests, h2)
	}
}

func TestLayersWebSocket(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	key := "a1b2c3d4"
	ext := "permessage-deflate"
	code, reason := 1000, "bye"
	msgs := []fakeMsg{
		batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 25, "", http1Payload(0, "HTTP/1.1")),
		appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 30, "", event.WebSocketFrame{
			Dir: "in", Opcode: 1, Fin: true, Masked: true, MaskKeyHex: &key, Length: 5,
			Upgrade: &event.WebSocketUpgrade{Over: "http1.1", Path: "/p/t1a2b3c4/ws", Extensions: &ext},
		}),
	}
	for i := range wsMaxFrames + 5 {
		msgs = append(msgs, appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 31+i%5, "", event.WebSocketFrame{Dir: "out", Opcode: 1, Fin: true, Length: 5}))
	}
	msgs = append(msgs, appMsg(t, event.SubjectWebWebSocketFrame, "tcp", client, mirror, 40, "", event.WebSocketFrame{
		Dir: "in", Opcode: 8, Fin: true, Close: &event.WebSocketClose{By: "client", Code: &code, Reason: &reason},
	}))
	run(t, in, 5000, msgs...)
	_, r := onlyConn(t, db)
	ws := r.WebSocket
	if r.Proto != "http1.1/ws" || ws == nil || ws.Over != "http1.1" || ws.Path != "/p/t1a2b3c4/ws" || *ws.Extensions != ext {
		t.Fatalf("%q %+v", r.Proto, ws)
	}
	if len(ws.Frames) != wsMaxFrames || !ws.FramesTruncated || ws.Close == nil || *ws.Close.Code != 1000 || ws.Frames[0].TMs != 30 {
		t.Fatalf("frames %d truncated %v close %+v t_ms %v", len(ws.Frames), ws.FramesTruncated, ws.Close, ws.Frames[0].TMs)
	}
}

func TestLayersRaw(t *testing.T) {
	for _, c := range []struct {
		subject string
		hello   bool
		want    string
	}{
		{event.SubjectRawSession, false, "raw"},
		{event.SubjectRawSession, true, "tls/raw"},
		{event.SubjectWebRawSession, false, "raw/unknown"},
	} {
		in, db := newTestIngestor(t, nil)
		msgs := []fakeMsg{batch(client, mirror, protoTCP, fullTCP)}
		if c.hello {
			msgs = append(msgs, appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", tlsHelloPayload(clientHelloRaw(95))))
		}
		msgs = append(msgs, appMsg(t, c.subject, "tcp", client, mirror, 1040, "", map[string]any{"mode": "echo", "tls": c.hello}),
			appMsg(t, c.subject, "tcp", client, mirror, 1041, "", map[string]any{"mode": "sink", "tls": c.hello}))
		run(t, in, 5000, msgs...)
		_, r := onlyConn(t, db)
		if r.Proto != c.want || !strings.Contains(string(r.Raw), `"sink"`) {
			t.Errorf("%s: %q %s", c.subject, r.Proto, r.Raw)
		}
	}
}

// TestLayersLateEventRebuild: evento depois do fim refaz as camadas a partir de app_events.
func TestLayersLateEventRebuild(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000, batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "", tlsHelloPayload(clientHelloRaw(95))))
	processAt(t, in, 6000, appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 1000, "", http1Payload(0, "HTTP/1.1")))
	_, r := onlyConn(t, db)
	if r.Proto != "tls/http1.1" || r.Requests != 1 || r.TLS == nil || r.TCP == nil {
		t.Fatalf("%q %d", r.Proto, r.Requests)
	}
}

// TestProbeTLSHTTPDNS: critério da spec 001 — uma sondagem TLS + HTTP/1 + DNS resulta, sob o mesmo conn_id, em
// pacotes (pcap), TCP, TLS e HTTP, e a consulta DNS do probe aparece no mesmo /probes/{id}.
func TestProbeTLSHTTPDNS(t *testing.T) {
	in, db := newTestIngestor(t, nil)
	run(t, in, 5000,
		appMsg(t, event.SubjectDNSQuery, "udp", resolver, dnsSrv, -50, "t1a2b3c4", dnsPayload("udp")),
		batch(client, mirror, protoTCP, fullTCP),
		appMsg(t, event.SubjectWebTLSClientHello, "tcp", client, mirror, 25, "t1a2b3c4", tlsHelloPayload(clientHelloRaw(95))),
		appMsg(t, event.SubjectWebTLSHandshake, "tcp", client, mirror, 33, "", handshakePayload()),
		appMsg(t, event.SubjectWebHTTP1Request, "tcp", client, mirror, 40, "t1a2b3c4", http1Payload(0, "HTTP/1.1")))
	q := NewQueries(db, in.flows.live, 65535)
	p, err := q.Probe(context.Background(), "t1a2b3c4", ProbeWait{})
	if err != nil || len(p.Connections) != 1 || len(p.DNS) != 1 || !p.AllClosed {
		t.Fatalf("%+v %v", p, err)
	}
	var r connectionJSON
	_ = json.Unmarshal(p.Connections[0], &r)
	if r.Proto != "tls/http1.1" || r.TCP == nil || r.TCP.JA4T == nil || r.TLS == nil || len(r.HTTP) != 1 || r.Times.Syn == nil {
		t.Fatalf("%+v", r)
	}
	if pc, err := q.Pcap(context.Background(), r.ConnID); err != nil || len(pc) < 100 {
		t.Fatalf("pcap %d %v", len(pc), err)
	}
	if count(t, db, "SELECT count(*) FROM app_events WHERE conn_id = ?", r.ConnID) != 3 {
		t.Fatal("app events under the same conn_id")
	}
}
