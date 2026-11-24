package bot

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Fuzz dos parsers do formato do traefix (task 308, adendo da ADR 0063 item 5): o registro
// traefix.fingerprint/v1 e os cabeçalhos X-Traefix-*/X-Fs-* do forwardAuth nunca entram em pânico, respeitam os
// tetos e nunca guardam valor fora da lista permitida nem fora dos padrões do openapi do bot.

// traefixSeedRecords devolve cada registro dos lotes de testdata/ingest (simulados e reais) como semente.
func traefixSeedRecords(f testing.TB) [][]byte {
	f.Helper()
	var out [][]byte
	for _, glob := range []string{"testdata/ingest/*.json", "testdata/ingest/real/*.json"} {
		paths, err := filepath.Glob(glob)
		if err != nil {
			f.Fatal(err)
		}
		for _, p := range paths {
			body, err := os.ReadFile(p)
			if err != nil {
				f.Fatal(err)
			}
			var b struct {
				Records []json.RawMessage `json:"records"`
			}
			if json.Unmarshal(body, &b) != nil {
				continue
			}
			for _, r := range b.Records {
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		f.Fatal("sem sementes em testdata/ingest")
	}
	return out
}

// checkTraefixRecord confere as invariantes do registro aceito: tetos de texto, lista permitida de campos e
// fingerprints prontas só nos formatos do esquema.
func checkTraefixRecord(t *testing.T, p parsedRecord) {
	t.Helper()
	r := &p.r
	for _, x := range []struct {
		name string
		v    string
		max  int
	}{
		{"method", r.Method, maxMethodBytes},
		{"httpVersion", r.HTTPVersion, maxHTTPVersionBytes},
		{"authority", r.Authority, maxSiteBytes},
		{"entryPoint", r.EntryPoint, maxRouteNameBytes},
		{"path", r.Path, maxPathBytes},
		{"sni", deref(r.SNI), maxSiteBytes},
		{"router", deref(r.Router), maxRouteNameBytes},
		{"service", deref(r.Service), maxRouteNameBytes},
		{"version", deref(r.TLSVersion), maxTLSTextBytes},
		{"cipher", deref(r.Cipher), maxTLSTextBytes},
		{"alpn", deref(r.ALPN), maxALPNBytes},
	} {
		if len(x.v) > x.max {
			t.Fatalf("%s acima do teto %d: %d bytes", x.name, x.max, len(x.v))
		}
	}
	if r.JA4H != nil && len(*r.JA4H) > maxJA4HBytes {
		t.Fatalf("ja4h acima do teto: %d", len(*r.JA4H))
	}
	for _, l := range []struct {
		name          string
		v             []string
		items, length int
	}{
		{"alpnOffered", r.ALPNOffered, maxALPNItems, maxALPNBytes},
		{"fieldNames", r.FieldNames, maxFieldNames, maxListNameBytes},
		{"cookieNames", r.CookieNames, maxFieldNames, maxListNameBytes},
	} {
		if len(l.v) > l.items {
			t.Fatalf("%s com %d itens", l.name, len(l.v))
		}
		for _, s := range l.v {
			if len(s) > l.length {
				t.Fatalf("%s com item de %d bytes", l.name, len(s))
			}
		}
	}
	for k, v := range r.Fields {
		if !allowedField(k) || len(k) > maxFieldNameBytes || len(v) > maxFieldValue {
			t.Fatalf("campo fora da lista ou do teto guardado: %q (%d bytes)", k, len(v))
		}
	}
	if tl := p.tls; tl != nil && tl.Ready {
		for _, x := range []struct {
			name string
			v    string
			re   *regexp.Regexp
		}{
			{"ja3", tl.JA3MD5, md5Pattern},
			{"ja3String", tl.JA3, ja3TextPattern},
			{"ja3n", tl.JA3NMD5, md5Pattern},
			{"ja3nString", tl.JA3N, ja3TextPattern},
			{"ja4", tl.JA4, ja4Pattern},
			{"ja4r", tl.JA4R, ja4rPattern},
			{"ja4o", tl.JA4O, ja4Pattern},
		} {
			if x.v != "" && (len(x.v) > maxReadyText || !x.re.MatchString(x.v)) {
				t.Fatalf("tls.%s pronto fora do padrão: %q", x.name, x.v)
			}
		}
	}
	if h := p.h2; h != nil && h.Ready {
		if len(h.Akamai) > maxReadyAkamai || !akamaiPattern.MatchString(h.Akamai) {
			t.Fatalf("http2.akamai pronto fora do padrão: %q", h.Akamai)
		}
		if len(h.Priorities) > maxForkPriorities {
			t.Fatalf("%d prioridades", len(h.Priorities))
		}
	}
	if h := p.h2; h != nil && h.HeadersPriority != "" && !h2PrioPattern.MatchString(h.HeadersPriority) {
		t.Fatalf("headersPriority fora do padrão: %q", h.HeadersPriority)
	}
	if v := p.tcp; v != nil {
		if v.TTL < 0 || v.TTL > 255 || v.TTLInitial < 0 || v.TTLInitial > 255 {
			t.Fatalf("TTL fora de 0..255: %+v", v)
		}
		if v.JA4T != "" && (len(v.JA4T) > maxTCPText || !ja4tPattern.MatchString(v.JA4T)) {
			t.Fatalf("ja4t fora do padrão: %q", v.JA4T)
		}
		if p.quic && !v.UDP {
			t.Fatal("visão TCP numa conexão h3")
		}
	}
	if tm := p.timing; tm != nil {
		for _, m := range []micros{tm.TCPRTT, tm.EstToFirst, tm.TLSRTT, tm.RTTGap, tm.QUICRTT, tm.QUICMinRTT} {
			if m.ok && (m.v > maxTimingMicros || m.v < -maxTimingMicros) {
				t.Fatalf("tempo fora do limite: %+v", tm)
			}
		}
	}
	if len(p.ignoredType) > 0 && !p.ignored {
		t.Fatal("ignoredType sem ignored")
	}
}

// runTraefixRecord passa o registro pelo parser e, aceito, pelas invariantes e pelo índice (apply).
func runTraefixRecord(t *testing.T, raw []byte, entryPoint string) {
	t.Helper()
	p, err := parseTraefixRecord(raw, entryPoint, ingestEnv{})
	if err != nil || p.ignored {
		return
	}
	checkTraefixRecord(t, p)
	var c ForkConn
	p.apply(&c)
	_ = c.ParseError()
}

// TestTraefixFuzzSeeds: as sementes do fuzz chegam aos caminhos conferidos (registro aceito com as visões TLS, h2 e
// TCP), para que as invariantes não passem em branco.
func TestTraefixFuzzSeeds(t *testing.T) {
	var accepted, tls, h2, tcp int
	for _, raw := range traefixSeedRecords(t) {
		p, err := parseTraefixRecord(raw, "websecure", ingestEnv{})
		if err != nil || p.ignored {
			continue
		}
		accepted++
		checkTraefixRecord(t, p)
		if p.tls != nil {
			tls++
		}
		if p.h2 != nil {
			h2++
		}
		if p.tcp != nil && !p.tcp.UDP {
			tcp++
		}
	}
	if accepted < 10 || tls == 0 || h2 == 0 || tcp == 0 {
		t.Fatalf("sementes sem cobertura: aceitos %d, tls %d, h2 %d, tcp %d", accepted, tls, h2, tcp)
	}
}

// FuzzParseTraefixRecord: critério 1 — o registro traefix.fingerprint/v1 arbitrário (JSON cru, sementes dos lotes
// de testdata/ingest) nunca derruba o parser e, aceito, respeita os tetos e a lista permitida.
func FuzzParseTraefixRecord(f *testing.F) {
	for _, r := range traefixSeedRecords(f) {
		f.Add(r, "websecure")
	}
	f.Add([]byte(`{"type":"connection","connId":"01JC0X3K8V2T7Q9F4M6P1R5T02","time":"2026-11-16T12:00:00Z","tcp":{"ttl":-1,"ja4t":"1_2_33_4"},"http2":{"akamai":"|0|0|"}}`), "")
	f.Add([]byte(`{"type":"request","connId":"01JC0X3K8V2T7Q9F4M6P1R5T02","start":"2026-11-16T12:00:00Z","fields":[{"name":"User-Agent","value":"x"},{"name":"user-agent","value":"y"},{"name":"Cookie","value":"z"}]}`), "web")
	f.Add([]byte(`{"type":"other"}`), "")
	f.Fuzz(func(t *testing.T, raw []byte, entryPoint string) {
		runTraefixRecord(t, raw, entryPoint)
	})
}

// FuzzParseTraefixRecordFields: critério 1, com a estrutura fixa — valores arbitrários nos campos que o bot lê
// (tcp.syn, tls.* prontos, http2.akamai, fields) e tipos trocados pelo seletor kind.
func FuzzParseTraefixRecordFields(f *testing.F) {
	syn, _ := base64.StdEncoding.DecodeString("RQAAPFebQACABl40rOkYVWgUF5qOGgBQ2krYYgAAAACgAvrwaPMAAAIEBbQEAggKnUvAxgAAAAABAwMM")
	f.Add("connection", "h2", "t13d1516h2_8daaf6152771_02713d6af862", "771,4865-4866,0-23,29-23,0",
		"1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "1:1:0:256", "64240_2-4-8-1-3_1460_12",
		syn, int64(128), "User-Agent", "curl/8.0", byte(0))
	f.Add("connection", "h3", "q13d0310h3_55b375c5d22e_cd85d2d88918", "", "", "", "", []byte{}, int64(64), "", "", byte(1))
	f.Add("request", "h1", "", "", "", "", "", []byte(nil), int64(-1), "Sec-Fetch-Mode", "navigate", byte(2))
	f.Add("connection", "h2", "d00?i0000zz_000000000000_000000000000", "1,,,,", "1:1|0|1:0:0:16|x", "0:0:0:0",
		"0_0-0_00_0", []byte{0x45}, int64(999), strings.Repeat("sec-ch-ua", 9), strings.Repeat("v", 600), byte(3))
	f.Fuzz(func(t *testing.T, typ, proto, ja4, ja3s, akamai, prio, ja4t string, synBytes []byte, ttl int64,
		fname, fvalue string, kind byte,
	) {
		tlsPart := map[string]any{
			"sni": fname, "alpnOffered": []string{fvalue, proto}, "ja3": ja4, "ja3String": ja3s, "ja3n": ja3s,
			"ja3nString": ja3s, "ja4": ja4, "ja4r": ja3s + ja4, "ja4o": ja4,
		}
		h2Part := map[string]any{"akamai": akamai, "headersPriority": prio}
		tcpPart := map[string]any{"syn": base64.StdEncoding.EncodeToString(synBytes), "ttl": ttl, "ja4t": ja4t, "p0f": ja3s}
		rec := map[string]any{
			"type": typ, "connId": "01JC0X3K8V2T7Q9F4M6P1R5T02", "time": "2026-11-16T12:00:00Z",
			"start": "2026-11-16T12:00:00Z", "src": map[string]any{"ip": "198.51.100.42", "port": 6523},
			"dst": map[string]any{"ip": "10.249.0.2", "port": 443}, "proto": proto, "tls": tlsPart, "http2": h2Part,
			"tcp": tcpPart, "udp": map[string]any{"ttl": ttl}, "timing": map[string]any{"tcpRttMicros": ttl},
			"method": fvalue, "authority": fname, "path": "/" + fvalue, "httpVersion": proto,
			"fieldNames": []string{fname, fname}, "cookieNames": []string{fvalue},
			"fields": []map[string]any{{"name": fname, "value": fvalue}, {"name": "User-Agent", "value": fvalue}},
			"ja4h":   ja4,
		}
		// kind troca o tipo de uma parte por outro JSON, para os caminhos de tipo errado
		switch kind % 8 {
		case 1:
			rec["tls"] = ja4
		case 2:
			rec["http2"] = []any{akamai}
		case 3:
			tcpPart["ttl"] = ja4t
			tcpPart["syn"] = ttl
		case 4:
			rec["fields"] = map[string]any{fname: fvalue}
		case 5:
			rec["udp"], rec["timing"] = ja4t, []int64{ttl}
		case 6:
			rec["src"] = map[string]any{"ip": fname, "port": ttl}
		case 7:
			delete(rec, "tcp")
			tlsPart["clientHello"] = base64.StdEncoding.EncodeToString(synBytes)
			h2Part["prefix"] = base64.StdEncoding.EncodeToString(synBytes)
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return
		}
		runTraefixRecord(t, raw, proto)
	})
}

// FuzzDecodeALPNHeader: critério 2 — X-Traefix-Alpn arbitrário nunca derruba o decodificador e, aceito, cabe nos
// limites da ADR 0063 item 6 (até 1024 bytes, 16 valores não vazios de até 255 bytes) e reencoda na mesma lista.
func FuzzDecodeALPNHeader(f *testing.F) {
	for _, s := range []string{"", "h2,http/1.1", "h3", "%2C,%25", "%zz", ",", "a,,b", strings.Repeat("a,", 16) + "a", "%FF%00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := decodeALPNHeader(s)
		if !ok {
			if got != nil {
				t.Fatalf("recusado com lista: %q", got)
			}
			return
		}
		if len(s) > maxALPNHeader || len(got) > maxALPNValues || got == nil {
			t.Fatalf("aceito fora dos limites: %q -> %q", s, got)
		}
		if s == "" {
			if len(got) != 0 {
				t.Fatalf("vazio com valores: %q", got)
			}
			return
		}
		for _, v := range got {
			if v == "" || len(v) > maxALPNValue {
				t.Fatalf("valor fora dos limites: %q", v)
			}
		}
		// cada valor decodificado, reencodado, decodifica de novo no mesmo valor
		enc := make([]string, len(got))
		for i, v := range got {
			enc[i] = url.PathEscape(v)
		}
		again, ok := decodeALPNHeader(strings.Join(enc, ","))
		if len(strings.Join(enc, ",")) <= maxALPNHeader && (!ok || strings.Join(again, "\x00") != strings.Join(got, "\x00")) {
			t.Fatalf("reencode diverge: %q -> %q -> %q", s, got, again)
		}
	})
}

// Valores bem formados de cada conjunto de cabeçalhos (diferentes entre si, para ver de qual veio o lido).
const (
	fuzzConnTraefix = "01JC0X3K8V2T7Q9F4M6P1R5T75"
	fuzzConnFs      = "01JC0X3K8V2T7Q9F4M6P1R5T76"
)

// forkHeaderNames são os cabeçalhos de fingerprint lidos por parseForkHeaders (sem o prefixo).
var forkHeaderNames = []string{"Ja4h", "Ja4", "Ja3", "H2", "Ja4t", "Alpn", "Ttl", "Timing", "Ja3n", "Ja4r", "Ja4o"}

// FuzzParseForkHeaders: critério 2 — cabeçalhos X-Traefix-*/X-Fs-* arbitrários (os dois conjuntos ao mesmo tempo,
// repetidos ou não) nunca derrubam o parser, nunca misturam os conjuntos e nunca aceitam valor fora dos padrões do
// openapi do bot (/bot/v1/auth).
func FuzzParseForkHeaders(f *testing.F) {
	f.Add(true, "h2", "t13d1516h2_8daaf6152771_02713d6af862", "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
		"h2,http/1.1", "64", "64240_2-4-8-1-3_1460_12", "tcp_rtt_us=2000", byte(0), "198.51.100.80", "50077")
	f.Add(false, "h1", "d8bbdd27a9b5_0ce0b37e1c7b_000000000000_000000000000", "8daaf6152771", "%zz", "-1", "", "", byte(1), "::ffff:10.0.0.1", "65536")
	f.Add(true, "h3", "q13d0310h3_55b375c5d22e_cd85d2d88918", "", "", "256", "1_2_3_4", "src=kernel", byte(2), "2001:db8::1%eth0", "0")
	f.Add(true, "h2", "t13d151600_8daaf6152771_02713d6af862", "|0|0|", "", "+5", "", "", byte(3), "", "1")
	f.Fuzz(func(t *testing.T, traefix bool, proto, v1, v2, alpn, ttl, ja4t, timing string, mode byte, srcIP, srcPort string) {
		h := http.Header{}
		base := func(prefix, connID string) {
			h[prefix+"Src-Ip"] = []string{srcIP}
			h[prefix+"Src-Port"] = []string{srcPort}
			h[prefix+"Dst-Port"] = []string{"443"}
			h[prefix+"Conn-Id"] = []string{connID}
			h[prefix+"Proto"] = []string{proto}
		}
		// valores: o conjunto principal leva os do fuzz; o outro, os mesmos em outra ordem (para pegar a mistura)
		vals := map[string]string{
			"Ja4h": v1, "Ja4": v1, "Ja3": v2, "H2": v2, "Ja4t": ja4t, "Alpn": alpn, "Ttl": ttl, "Timing": timing,
			"Ja3n": v2, "Ja4r": v1 + v2, "Ja4o": v1,
		}
		other := map[string]string{
			"Ja4h": v2, "Ja4": v2, "Ja3": v1, "H2": v1, "Ja4t": ttl, "Alpn": timing, "Ttl": ja4t, "Timing": alpn,
			"Ja3n": v1, "Ja4r": v2 + v1, "Ja4o": v2,
		}
		main, sec := prefixFs, prefixTraefix
		if traefix {
			main, sec = prefixTraefix, prefixFs
			base(prefixTraefix, fuzzConnTraefix)
		}
		if !traefix || mode&1 != 0 {
			base(prefixFs, fuzzConnFs)
		}
		for i, n := range forkHeaderNames {
			h[main+n] = []string{vals[n]}
			if mode&2 != 0 {
				h[sec+n] = []string{other[n]}
			}
			if mode&4 != 0 && i%3 == int(mode>>4)%3 {
				h[main+n] = append(h[main+n], vals[n]) // repetido é ausente
			}
		}
		fh, code, _ := parseForkHeaders(h)
		if code != "" {
			return
		}
		// conjunto escolhido: X-Traefix-* com X-Traefix-Conn-Id presente; senão X-Fs-*
		wantPrefix := prefixFs
		if traefix {
			wantPrefix = prefixTraefix
		}
		if fh.prefix != wantPrefix {
			t.Fatalf("conjunto %q, esperado %q", fh.prefix, wantPrefix)
		}
		if want := map[string]string{prefixTraefix: fuzzConnTraefix, prefixFs: fuzzConnFs}[wantPrefix]; fh.fsConnID != want {
			t.Fatalf("conn-id de outro conjunto: %q", fh.fsConnID)
		}
		if fh.proto != "h1" && fh.proto != "h2" && fh.proto != "h3" {
			t.Fatalf("proto %q", fh.proto)
		}
		if fh.srcPort < 0 || fh.srcPort > 65535 || fh.dstPort < 0 || fh.dstPort > 65535 || !fh.srcIP.IsValid() ||
			fh.srcIP.Zone() != "" || fh.srcIP.Is4In6() {
			t.Fatalf("origem fora do contrato: %v:%d", fh.srcIP, fh.srcPort)
		}
		// cada valor lido é o do próprio conjunto, bem formado; repetido é ausente
		got := func(n, v string) {
			t.Helper()
			if v == "" {
				return
			}
			hv := h.Values(wantPrefix + n)
			if len(hv) != 1 || hv[0] != v {
				t.Fatalf("%s lido %q, cabeçalho do conjunto %q", n, v, hv)
			}
		}
		for _, x := range []struct {
			n, v string
			re   *regexp.Regexp
			max  int
		}{
			{"Ja4h", fh.ja4h, ja4hPattern, 0},
			{"Ja4", fh.ja4, ja4HeaderPattern, 0},
			{"Ja3", fh.ja3, md5Pattern, 0},
			{"H2", fh.h2, akamaiPattern, maxReadyAkamai},
			{"Ja4t", fh.ja4t, ja4tHeaderPattern, maxTCPText},
			{"Ja3n", fh.ja3n, md5Pattern, 0},
			{"Ja4r", fh.ja4r, ja4rPattern, maxJA4RHeader},
			{"Ja4o", fh.ja4o, ja4HeaderPattern, 0},
		} {
			got(x.n, x.v)
			if x.v != "" && (!x.re.MatchString(x.v) || (x.max > 0 && len(x.v) > x.max)) {
				t.Fatalf("%s fora do padrão do openapi: %q", x.n, x.v)
			}
		}
		if fh.h2 != "" && fh.proto != "h2" {
			t.Fatalf("H2 fora de h2: %q", fh.h2)
		}
		if fh.ttl != -1 {
			hv := h.Values(wantPrefix + "Ttl")
			if fh.ttl < 0 || fh.ttl > 255 || len(hv) != 1 {
				t.Fatalf("ttl %d de %q", fh.ttl, hv)
			}
			if n, err := strconv.Atoi(hv[0]); err != nil || n != fh.ttl {
				t.Fatalf("ttl %d de %q", fh.ttl, hv[0])
			}
		}
		if fh.alpnKnown {
			if fh.alpn == nil || len(fh.alpn) > maxALPNValues {
				t.Fatalf("alpn conhecido fora dos limites: %q", fh.alpn)
			}
			if hv := h.Values(wantPrefix + "Alpn"); len(hv) > 1 {
				t.Fatalf("alpn de cabeçalho repetido: %q", hv)
			}
		} else if fh.alpn != nil {
			t.Fatalf("alpn sem alpnKnown: %q", fh.alpn)
		}
		// X-Fs-* não tem Ja4t, Alpn, Ttl, Timing nem os de detalhe: nada deles pode vir do conjunto novo
		if wantPrefix == prefixFs && (fh.ja4t != "" || fh.alpnKnown || fh.ttl != -1 || fh.timing != nil ||
			fh.ja3n != "" || fh.ja4r != "" || fh.ja4o != "") {
			t.Fatalf("conjunto X-Fs-* com campos do X-Traefix-*: %+v", fh)
		}
		if tm := fh.timing; tm != nil {
			for _, m := range []micros{tm.TCPRTT, tm.EstToFirst, tm.TLSRTT, tm.RTTGap, tm.QUICRTT, tm.QUICMinRTT} {
				if m.ok && (m.v > maxTimingMicros || m.v < -maxTimingMicros) {
					t.Fatalf("tempo fora do limite: %+v", tm)
				}
			}
		}
	})
}
