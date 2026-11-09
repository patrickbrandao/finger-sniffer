//go:build e2e

package e2e

// Campos das specs 008–013 que cada caso da matriz (spec 017, caminho direto, ADR 0022) exige no registro
// (task 066). Cada caso chama requireConnFields/requireDNSFields/requireEventFields com a sua chave; a lista é
// explícita e fica toda aqui, para o PR de release citar o que foi conferido.
//
// Sintaxe dos caminhos: segmentos separados por ponto sobre o JSON do registro; um número indexa um array; "*"
// exige um array não vazio e aplica o resto a cada elemento; o sufixo "+" exige valor não vazio (string, array
// ou objeto). Sem sufixo, o campo tem de existir e não ser null.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// commonTCP são os campos da spec 013 (linha do tempo, fechamento, totais, IP, SYN, JA4T, p0f, RTT,
// comportamento, segmentação) que todo registro TCP encerrado traz.
var commonTCP = []string{
	"conn_id+", "proto+", "l4+", "family", "src.ip+", "src.port", "dst.ip+", "dst.port", "started+", "ended+",
	"times.syn+", "times.syn_ack+", "times.established+", "times.end+",
	"close.by+", "close.how+", "close.half_close",
	"totals.in.segments", "totals.in.app_bytes", "totals.in.data_segments", "totals.in.retransmits", "totals.in.out_of_order",
	"totals.out.segments", "totals.out.app_bytes",
	"ip.ttl", "ip.ttl_initial", "ip.hops", "ip.ip_id_pattern+", "ip.df", "ip.dscp", "ip.ecn+", "ip.fragmented",
	"tcp.syn.options+", "tcp.syn.isn", "tcp.syn.window", "tcp.syn.flags+", "tcp.syn.header_len", "tcp.syn.src_port",
	"tcp.ja4t+", "tcp.p0f+", "tcp.rtt_handshake_ms", "tcp.window_series+", "tcp.ack_pattern+", "tcp.psh_used",
	"tcp.zero_window", "tcp.rst_with_data", "tcp.segments_in+", "tcp.segments_out", "tcp.keepalive_probes",
	"tcp.syn_cookie_server", "tcp.retransmits_in",
}

// commonUDP são os campos de um registro QUIC (sem IP/TCP por pacote).
var commonUDP = []string{
	"conn_id+", "proto+", "l4+", "family", "src.ip+", "src.port", "dst.ip+", "dst.port", "started+", "ended+",
	"close.by+", "close.how+",
}

// h1Fields: spec 009 (bytes crus, campos sem normalizar, JA4H, resposta enviada) de cada requisição HTTP/1.
var h1Fields = []string{
	"times.first_data+", "requests",
	"http.*.index", "http.*.raw_head_b64+", "http.*.request_line.method+", "http.*.request_line.target+",
	"http.*.request_line.form+", "http.*.request_line.version+", "http.*.request_line.terminator+",
	"http.*.fields+", "http.*.field_count", "http.*.head_size", "http.*.duplicates", "http.*.body.framing+",
	"http.*.body.size", "http.*.pipelined", "http.0.t_first_byte_ms", "http.*.ja4h+", "http.*.status",
	"http.*.response_sent_b64+", "http.*.response_sent_size", "http.*.in_offset", "http.*.out_offset",
	"http.*.proxy_signals",
}

// tlsFields: spec 008 (ClientHello cru e analisado, impressões, negociação, handshake).
var tlsFields = []string{
	"times.tls_done+",
	"tls.client_hello_b64+", "tls.client_hello_records", "tls.client_hello_segments",
	"tls.record_version", "tls.handshake_version", "tls.random_hex+", "tls.session_id_len", "tls.cipher_suites+",
	"tls.compression_methods+", "tls.extensions+", "tls.sni+", "tls.alpn", "tls.supported_groups+",
	"tls.signature_algorithms+", "tls.supported_versions", "tls.ja3+", "tls.ja3_md5+", "tls.ja3n+", "tls.ja3n_md5+",
	"tls.ja4+", "tls.ja4_r+", "tls.ja4_o+", "tls.ja4_stable+", "tls.negotiated.version+", "tls.negotiated.cipher+",
	"tls.negotiated.resumed", "tls.handshake_ms",
}

// h2Fields: spec 010 (preface, SETTINGS, Akamai, HPACK por stream, JA4H, frames).
var h2Fields = []string{
	"requests",
	"http2.mode+", "http2.preface_ok", "http2.settings", "http2.akamai+", "http2.frames+",
	"http2.streams.*.stream_id", "http2.streams.*.pseudo_order+", "http2.streams.*.fields+",
	"http2.streams.*.fields.*.repr+", "http2.streams.*.ja4h+", "http2.streams.*.status",
}

// h3Fields: spec 011 (Initial, transport params na ordem, ClientHello do QUIC com JA4 q, h3, fim).
var h3Fields = []string{
	"http3.version+", "http3.dcid_hex+", "http3.scid_hex", "http3.token_len", "http3.initial_datagram_size",
	"http3.padded_to_1200", "http3.coalesced_packets", "http3.client_hello_datagrams", "http3.initial_frames+",
	"http3.transport_params+", "http3.client_hello.ja4+", "http3.client_hello.ja4_r+", "http3.client_hello.sni+",
	"http3.client_hello.alpn+", "http3.client_hello.cipher_suites+", "http3.client_hello.negotiated.version+",
	"http3.h3_settings", "http3.close.by+", "http3.close.how+",
	"http3.requests.*.stream_id", "http3.requests.*.pseudo_order+", "http3.requests.*.fields+",
	"http3.requests.*.fields.*.repr+", "http3.requests.*.ja4h+", "http3.requests.*.status",
}

// caseFields é a lista explícita por caso da matriz (a chave "n" ou "n/variante").
var caseFields = map[string][]string{
	// 1. HTTP/1.1 com cabeçalhos incomuns: bytes crus e campos sem normalizar
	"1": h1Fields,
	// 2. HTTP/1.0 com e sem keep-alive: versão e quem fechou
	"2": h1Fields,
	// 3. persistente, Connection: close e pipelining
	"3":       h1Fields,
	"3/multi": {"http.1.t_since_prev_response_ms", "http.1.index", "http.1.pipelined"},
	// 4. corpos
	"4":          h1Fields,
	"4/cl":       {"http.*.body.sha256+", "http.*.body.raw_b64+"},
	"4/chunked":  {"http.*.body.chunks+", "http.*.body.chunks.*.size", "http.*.body.chunks.*.size_literal+", "http.*.body.trailers"},
	"4/continue": {"http.*.expect_continue.waited"},
	// 5. controles de resposta
	"5": append([]string{"http.*.controls.params"}, h1Fields...),
	// 6. ociosidade: quem fechou, como e depois de quanto tempo ocioso
	"6":        {"close.by+", "close.how+", "times.end+"},
	"6/idle":   {"close.idle_before_close_ms"},
	"6/client": {"times.client_fin+"},
	"6/server": {"times.server_fin+"},
	"6/h1":     h1Fields,
	"6/h2":     append(append([]string{}, tlsFields...), h2Fields...),
	"6/raw":    {"raw.mode+", "raw.tls", "raw.probe_line+", "raw.reads_in+", "raw.writes_out+"},
	// 7. HTTPS: ClientHello byte a byte, JA3/JA4, Akamai h2
	"7":    tlsFields,
	"7/h1": h1Fields,
	"7/h2": h2Fields,
	// 8. portas cruas em banner/echo/source, com meio-fechamento
	"8":          {"raw.mode+", "raw.tls", "raw.probe_line+", "raw.reads_in", "raw.writes_out", "raw.reads_in_truncated", "raw.writes_out_truncated"},
	"8/banner":   {"raw.banner+"},
	"8/half":     {"raw.half_close.server_sent_after_client_fin", "raw.half_close.bytes", "times.client_fin+"},
	"8/tls":      append([]string{"raw.tls"}, tlsFields...),
	"8/tls-only": {"tls.client_hello_b64+", "tls.ja4+", "tls.ja3+", "tls.sni+", "raw.mode+", "raw.tls"},
	// 9. WebSocket
	"9": {
		"websocket.over+", "websocket.path+", "websocket.frames+", "websocket.frames.*.dir+",
		"websocket.frames.*.opcode", "websocket.frames.*.fin", "websocket.frames.*.rsv", "websocket.frames.*.masked",
		"websocket.frames.*.length", "websocket.close.by+",
	},
	"9/h1": {"http.0.upgrade+", "http.0.status", "http.0.raw_head_b64+"},
	"9/h2": {"http2.settings", "http2.streams.*.pseudo_order+"},
	// 10. DNS (no probe: cada consulta)
	"10": {
		"dns.*.ts+", "dns.*.resolver.ip+", "dns.*.resolver.port", "dns.*.proto+", "dns.*.id", "dns.*.opcode",
		"dns.*.flags.rd", "dns.*.qname+", "dns.*.qtype+", "dns.*.qclass+", "dns.*.edns", "dns.*.response.rcode+",
		"dns.*.response.answers", "dns.*.rate_limited", "dns.*.raw_b64+",
	},
	"10/conn": {"proto+"},
	// 11. TCP: relógio TSval e RTT (os campos comuns já trazem JA4T, p0f, TTL e RTT do handshake)
	"11": {"tcp.ts_initial", "tcp.ts_clock_hz", "tcp.ts_clock_group+", "tcp.os_guess"},
	// 12. HTTP/3
	"12": h3Fields,
	// 13. tempo real: cada evento do /ws com probe; conexões com o resumo
	"13":            {"kind+", "ts+", "probe_id+", "data+"},
	"13/connection": {"conn_id+", "data.conn_id+", "data.proto+", "data.l4+", "data.src.ip+", "data.dst.port", "data.started+"},
	"13/request":    {"conn_id+", "data.status"},
	"13/dns":        {"data.qname+", "data.qtype+", "data.resolver.ip+"},
}

// connRaw busca o JSON do registro completo da conexão.
func connRaw(t *testing.T, connID string) map[string]any {
	t.Helper()
	resp, err := http.Get(api + "/connections/" + connID) //nolint:gosec // URL do teste
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /connections/%s: %d %s", connID, resp.StatusCode, b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("registro %s: %v", connID, err)
	}
	return m
}

// requireConnFields confere os campos comuns (TCP ou UDP) e os das chaves dadas em cada registro.
func requireConnFields(t *testing.T, recs []record, keys ...string) {
	t.Helper()
	if len(recs) == 0 {
		t.Errorf("campos %v: nenhum registro para conferir", keys)
		return
	}
	for _, r := range recs {
		m := connRaw(t, r.ConnID)
		paths := commonTCP
		if m["l4"] == "udp" {
			paths = commonUDP
		}
		paths = append(append([]string{}, paths...), fieldsOf(t, keys)...)
		if miss := missingPaths(m, paths); len(miss) > 0 {
			t.Errorf("%s (%s, porta %d, caso %s): campos ausentes ou vazios: %s", r.ConnID, r.Proto, r.Dst.Port,
				strings.Join(keys, ","), strings.Join(miss, ", "))
		}
	}
}

// requireReqFields confere as chaves dadas só na requisição HTTP/1 de índice idx ("http.*" vira "http.idx").
func requireReqFields(t *testing.T, r record, idx int, keys ...string) {
	t.Helper()
	m := connRaw(t, r.ConnID)
	var paths []string
	for _, p := range fieldsOf(t, keys) {
		paths = append(paths, strings.Replace(p, "http.*.", "http."+strconv.Itoa(idx)+".", 1))
	}
	if miss := missingPaths(m, paths); len(miss) > 0 {
		t.Errorf("%s requisição %d (caso %s): campos ausentes ou vazios: %s", r.ConnID, idx, strings.Join(keys, ","),
			strings.Join(miss, ", "))
	}
}

// requireDNSFields confere os campos de cada consulta DNS do probe.
func requireDNSFields(t *testing.T, id string, keys ...string) {
	t.Helper()
	var m map[string]any
	get(t, "/probes/"+id, &m)
	if miss := missingPaths(m, fieldsOf(t, keys)); len(miss) > 0 {
		t.Errorf("probe %s (caso %s): campos DNS ausentes ou vazios: %s", id, strings.Join(keys, ","), strings.Join(miss, ", "))
	}
}

// requireEventFields confere os campos de cada evento de tempo real recebido.
func requireEventFields(t *testing.T, evs []liveEvent) {
	t.Helper()
	if len(evs) == 0 {
		t.Error("caso 13: nenhum evento para conferir")
		return
	}
	for _, e := range evs {
		b, _ := json.Marshal(struct {
			Kind    string          `json:"kind"`
			TS      string          `json:"ts"`
			ConnID  *string         `json:"conn_id"`
			ProbeID *string         `json:"probe_id"`
			Data    json.RawMessage `json:"data"`
		}{e.Kind, e.TS.Format("2006-01-02T15:04:05.000000000Z07:00"), e.ConnID, e.ProbeID, e.Data})
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		keys := []string{"13"}
		switch {
		case strings.HasPrefix(e.Kind, "connection."):
			keys = append(keys, "13/connection")
		case e.Kind == "http.request":
			keys = append(keys, "13/request")
		case e.Kind == "dns.query":
			keys = append(keys, "13/dns")
		}
		if miss := missingPaths(m, fieldsOf(t, keys)); len(miss) > 0 {
			t.Errorf("evento %s: campos ausentes ou vazios: %s", e.Kind, strings.Join(miss, ", "))
		}
	}
}

func fieldsOf(t *testing.T, keys []string) []string {
	t.Helper()
	var out []string
	for _, k := range keys {
		f, ok := caseFields[k]
		if !ok {
			t.Fatalf("caseFields: chave %q desconhecida", k)
		}
		out = append(out, f...)
	}
	return out
}

// missingPaths devolve os caminhos que não estão presentes (ou vazios, com "+") em doc, sem repetição.
func missingPaths(doc any, paths []string) []string {
	seen := map[string]bool{}
	for _, p := range paths {
		nonEmpty := strings.HasSuffix(p, "+")
		segs := strings.Split(strings.TrimSuffix(p, "+"), ".")
		for _, m := range walk(doc, segs, "", nonEmpty) {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// walk aplica os segmentos a v e devolve os caminhos concretos que faltam.
func walk(v any, segs []string, at string, nonEmpty bool) []string {
	join := func(s string) string {
		if at == "" {
			return s
		}
		return at + "." + s
	}
	if len(segs) == 0 {
		if v == nil || nonEmpty && empty(v) {
			return []string{at}
		}
		return nil
	}
	s := segs[0]
	switch x := v.(type) {
	case map[string]any:
		child, ok := x[s]
		if !ok || child == nil && len(segs) > 1 {
			return []string{join(s)}
		}
		return walk(child, segs[1:], join(s), nonEmpty)
	case []any:
		if s == "*" {
			if len(x) == 0 {
				return []string{join("*") + " (vazio)"}
			}
			var out []string
			for i, e := range x {
				out = append(out, walk(e, segs[1:], join(strconv.Itoa(i)), nonEmpty)...)
			}
			return out
		}
		i, err := strconv.Atoi(s)
		if err != nil || i >= len(x) {
			return []string{join(s)}
		}
		return walk(x[i], segs[1:], join(s), nonEmpty)
	}
	return []string{fmt.Sprintf("%s (não é objeto nem array)", join(s))}
}

func empty(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
