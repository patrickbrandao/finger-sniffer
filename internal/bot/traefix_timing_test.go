package bot

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// Tempos de exemplo do traefix (ADR 0065 item 3): cliente direto (volta TLS ≈ TCP, primeiro byte em 1 ms) e atrás de
// um relay (volta TCP de 2 ms com o relay, volta TLS e espera de 80 ms com o cliente).
const (
	timingDirect = "src=kernel,proto=tcp,tcp_rtt_us=12000,est_to_first_us=1000,ch_us=0,srv_us=410,tls_rtt_us=12400,tls_us=13900,rtt_gap_us=400,req_us=14200"
	timingRelay  = "src=kernel,proto=tcp,tcp_rtt_us=2000,est_to_first_us=80000,ch_us=35,srv_us=410,tls_rtt_us=82000,tls_us=83000,rtt_gap_us=80000,req_us=84000"
)

// uaChromeWindows é o Chrome de Windows (TTL inicial 128).
const uaChromeWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

func relayTimingRecord() map[string]any {
	return map[string]any{
		"source": "kernel", "tcpRttMicros": 2000, "estToFirstMicros": 80000, "tlsRttMicros": 82000, "rttGapMicros": 80000,
		"clientHelloMicros": 35, "serverMicros": 410, "handshakeMicros": 83000, "firstByte": "2026-11-16T12:00:00.090000000Z",
	}
}

// TestParseTimingHeader: X-Traefix-Timing com entrada hostil (ADR 0065 item 2) — chaves desconhecidas e pares sem
// `=` ignorados, valor fora de inteiro ou repetido = ausente, `src` fora de kernel|user = desconhecida, acima de
// 2 KiB nada.
func TestParseTimingHeader(t *testing.T) {
	tm := parseTimingHeader(timingRelay, false)
	if tm == nil || tm.Source != timingKernel || tm.QUIC || tm.TCPRTT != (micros{2000, true}) || tm.EstToFirst != (micros{80000, true}) ||
		tm.TLSRTT != (micros{82000, true}) || tm.RTTGap != (micros{80000, true}) {
		t.Fatalf("tempos: %+v", tm)
	}
	h3 := parseTimingHeader("src=user,proto=udp,initial_to_hs_us=48210,quic_rtt_us=23500,quic_min_rtt_us=23100,req_us=49800", false)
	if h3 == nil || !h3.QUIC || h3.Source != timingUser || h3.QUICRTT != (micros{23500, true}) || h3.QUICMinRTT != (micros{23100, true}) ||
		h3.rules() != nil {
		t.Fatalf("h3: %+v", h3)
	}
	cases := []struct {
		name, in string
		check    func(*ForkTiming) bool
	}{
		{"empty", "", func(t *ForkTiming) bool { return t == nil }},
		{"no times", "src=kernel,proto=tcp,ch_us=5,req_us=9", func(t *ForkTiming) bool { return t == nil }},
		{"garbage", ",,,=,==,a,=1,tcp_rtt_us", func(t *ForkTiming) bool { return t == nil }},
		{"too long", "tcp_rtt_us=1," + strings.Repeat("x", maxTimingHeader), func(t *ForkTiming) bool { return t == nil }},
		{"unknown keys", "future_us=5,tcp_rtt_us=7,flag=1", func(t *ForkTiming) bool { return t.TCPRTT == micros{7, true} && t.Source == "" }},
		{"spaces", " tcp_rtt_us=7 , src=user", func(t *ForkTiming) bool { return t.TCPRTT == micros{7, true} && t.Source == timingUser }},
		{"bad src", "src=gps,tcp_rtt_us=7", func(t *ForkTiming) bool { return t.Source == "" }},
		{"repeated src", "src=kernel,src=user,tcp_rtt_us=7", func(t *ForkTiming) bool { return t.Source == "" }},
		{"repeated key", "tcp_rtt_us=7,tcp_rtt_us=9,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok && t.TLSRTT.ok }},
		{"float", "tcp_rtt_us=1.5,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"exponent", "tcp_rtt_us=1e3,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"hex", "tcp_rtt_us=0x10,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"plus", "tcp_rtt_us=+5,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"empty value", "tcp_rtt_us=,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"negative rtt", "tcp_rtt_us=-5,est_to_first_us=-40", func(t *ForkTiming) bool { return !t.TCPRTT.ok && t.EstToFirst == micros{-40, true} }},
		{
			"huge", "tcp_rtt_us=99999999999999999999,tls_rtt_us=3600000001,rtt_gap_us=-3600000001,est_to_first_us=3600000000",
			func(t *ForkTiming) bool {
				return !t.TCPRTT.ok && !t.TLSRTT.ok && !t.RTTGap.ok && t.EstToFirst == micros{3600000000, true}
			},
		},
		{"percent", "tcp_rtt_us=%31,tls_rtt_us=3", func(t *ForkTiming) bool { return !t.TCPRTT.ok }},
		{"quic arg", "tcp_rtt_us=7", func(t *ForkTiming) bool { return t.TCPRTT.ok }},
	}
	for _, c := range cases {
		if got := parseTimingHeader(c.in, false); !c.check(got) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if tm := parseTimingHeader("tcp_rtt_us=7", true); tm == nil || !tm.QUIC || tm.rules() != nil {
		t.Errorf("h3 pelo X-Traefix-Proto: %+v", tm)
	}
	// o gap é calculado sem rtt_gap_us
	if tm := parseTimingHeader("tcp_rtt_us=2000,tls_rtt_us=82000,est_to_first_us=80000", false); tm.gap() != (micros{80000, true}) {
		t.Errorf("gap calculado: %+v", tm.gap())
	}
}

// FuzzParseTimingHeader: o parser nunca entra em pânico e só devolve tempos dentro dos limites.
func FuzzParseTimingHeader(f *testing.F) {
	for _, s := range []string{timingDirect, timingRelay, "src=user,proto=udp,quic_rtt_us=1", "a=b=c,,=", "tcp_rtt_us=-0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tm := parseTimingHeader(s, false)
		if tm == nil {
			return
		}
		for _, m := range []micros{tm.TCPRTT, tm.EstToFirst, tm.TLSRTT, tm.RTTGap, tm.QUICRTT, tm.QUICMinRTT} {
			if m.ok && (m.v > maxTimingMicros || m.v < -maxTimingMicros) {
				t.Fatalf("fora do limite: %+v", tm)
			}
		}
		if (tm.TCPRTT.ok && tm.TCPRTT.v < 0) || (tm.QUICRTT.ok && tm.QUICRTT.v < 0) {
			t.Fatalf("volta negativa: %+v", tm)
		}
	})
}

// TestTraefixTimingRecord: o timing do registro de conexão (ADR 0065 item 2) — campo fora de inteiro é ausente sem
// recusar o registro, timing que não é objeto é ignorado, e o custo entra no do índice.
func TestTraefixTimingRecord(t *testing.T) {
	for _, c := range []struct {
		name, raw string
		ok        bool
	}{
		{"object", `{"source":"kernel","tcpRttMicros":2000,"tlsRttMicros":"82000","rttGapMicros":1.5,"estToFirstMicros":-40}`, true},
		{"not object", `"fast"`, false},
		{"array", `[1,2]`, false},
		{"empty object", `{}`, false},
		{"bad source", `{"source":5,"tcpRttMicros":2000}`, true},
	} {
		tm := traefixTiming([]byte(c.raw), false)
		if (tm != nil) != c.ok {
			t.Errorf("%s: %+v", c.name, tm)
		}
		if c.name == "object" && (tm.Source != timingKernel || tm.TCPRTT != (micros{2000, true}) || tm.TLSRTT.ok || tm.RTTGap.ok ||
			tm.EstToFirst != (micros{-40, true})) {
			t.Errorf("campos: %+v", tm)
		}
		if c.name == "bad source" && tm.Source != "" {
			t.Errorf("source: %+v", tm)
		}
	}
	f := newFixture(t)
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T60"
	conn := chromeConn(nil)
	conn["timing"] = map[string]any{"source": "kernel", "tcpRttMicros": "x", "tlsRttMicros": []int{1}, "estToFirstMicros": 1000}
	conn["udp"] = "nope"
	if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.70", 50060, conn, chromeRequest())); c != 202 || got["accepted"] != 2 {
		t.Fatalf("timing malformado recusou o registro: %d %v", c, got)
	}
	fc, _ := f.srv.Index().Fork(id, f.clock.Now())
	if fc.Timing == nil || fc.Timing.TCPRTT.ok || fc.Timing.EstToFirst != (micros{1000, true}) {
		t.Fatalf("timing: %+v", fc.Timing)
	}
	without := fc
	without.Timing, without.connCost = nil, fc.connCost-forkTimingBytes
	if forkBytes(&fc)-forkBytes(&without) != forkTimingBytes || forkTimingBytes <= 0 {
		t.Errorf("custo dos tempos no índice: %d", forkBytes(&fc)-forkBytes(&without))
	}
}

// TestTraefixRelayRTTGap: critério 1 da task 312 — tempos no veredito pelos dois caminhos (registro do ingest e
// X-Traefix-Timing, o registro vence), relay_rtt_gap com os limiares da ADR 0065 e a métrica
// bot_auth_fingerprint_total{kind="timing"}.
func TestTraefixRelayRTTGap(t *testing.T) {
	chrome := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	chromeH2 := analyzeH2Prefix(goldenBytes("h2/chrome.prefix"), false).Akamai
	ids := func(v Verdict) []string { return signalIDList(v.Signals) }
	chromeHeaders := func(id string, port int) map[string]string {
		h := traefixAuthHeaders(id, port, "h2", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-H2"], h["X-Traefix-Alpn"] = chrome.JA4, chromeH2, "h2,http/1.1"
		h["X-Traefix-Ja4h"] = "ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000"
		h["X-Traefix-Ja4t"] = ja4tFull
		return h
	}

	t.Run("ingest relay", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T61"
		conn := chromeConn(map[string]any{"ja4t": ja4tFull, "ttl": 52})
		conn["timing"] = relayTimingRecord()
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.71", 50061, conn, chromeRequest()))
		v := f.verdictOf(id)
		if v.Class != ClassHuman || !slices.Equal(ids(v), []string{"relay_rtt_gap", "known_client"}) {
			t.Fatalf("veredito: %s %d %v", v.Class, v.Score, ids(v))
		}
		if v.Signals[0].Detail != "rtt gap 80.0 ms, tcp rtt 2.0 ms, first byte after 80.0 ms" || v.Signals[0].Weight != 15 {
			t.Errorf("sinal: %+v", v.Signals[0])
		}
		fp := v.Fingerprints
		if val(fp.TCPRTTMicros) != 2000 || val(fp.TLSRTTMicros) != 82000 || val(fp.RTTGapMicros) != 80000 ||
			val(fp.EstToFirstMicros) != 80000 || deref(fp.TimingSource) != timingKernel {
			t.Errorf("fingerprints: %+v", fp)
		}
	})
	t.Run("ingest direct", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T62"
		conn := chromeConn(map[string]any{"ja4t": ja4tFull, "ttl": 52})
		conn["timing"] = map[string]any{"source": "user", "tcpRttMicros": 12000, "estToFirstMicros": 1000, "tlsRttMicros": 12400}
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.72", 50062, conn, chromeRequest()))
		v := f.verdictOf(id)
		if !slices.Equal(ids(v), []string{"known_client"}) || val(v.Fingerprints.RTTGapMicros) != 400 ||
			deref(v.Fingerprints.TimingSource) != timingUser {
			t.Fatalf("direto: %v %+v", ids(v), v.Fingerprints)
		}
	})
	t.Run("ingest private origin", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T63"
		conn := chromeConn(nil)
		conn["timing"] = relayTimingRecord()
		f.postIngest(traefixBatchJSON(t, id, "172.17.0.1", 50063, conn, chromeRequest()))
		v := f.verdictOf(id)
		// o par da conexão TCP é um proxy local: o sinal não avalia, os tempos seguem no Fingerprints
		if slices.Contains(ids(v), "relay_rtt_gap") || val(v.Fingerprints.TCPRTTMicros) != 2000 {
			t.Fatalf("origem privada: %v %+v", ids(v), v.Fingerprints)
		}
	})
	t.Run("header relay", func(t *testing.T) {
		f := newFixture(t)
		h := chromeHeaders("01JC0X3K8V2T7Q9F4M6P1R5T64", 50064)
		h["X-Traefix-Timing"] = timingRelay
		_, _, v, b := f.authVerdict("internal", "", h)
		if v.Class != ClassHuman || !slices.Equal(ids(v), []string{"relay_rtt_gap", "known_client"}) ||
			val(v.Fingerprints.RTTGapMicros) != 80000 || deref(v.Fingerprints.TimingSource) != timingKernel {
			t.Fatalf("relay pelo cabeçalho: %s", b)
		}
		if n := f.metrics.Get(authFPMetric("timing", fpFromHeader)); n != 1 {
			t.Errorf("timing/header = %v", n)
		}
		// curl pelo relay: bot
		h = traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T65", 50065, "h1", "curl/8.7.1")
		h["X-Traefix-Ja4h"], h["X-Traefix-Timing"] = ja4hCurl, timingRelay
		delete(h, "Accept-Language")
		if _, _, v, b := f.authVerdict("internal", "", h); v.Class != ClassBot || !slices.Contains(ids(v), "relay_rtt_gap") {
			t.Fatalf("curl pelo relay: %s", b)
		}
	})
	t.Run("header direct and absent", func(t *testing.T) {
		f := newFixture(t)
		h := chromeHeaders("01JC0X3K8V2T7Q9F4M6P1R5T66", 50066)
		h["X-Traefix-Timing"] = timingDirect
		if _, _, v, b := f.authVerdict("internal", "", h); !slices.Equal(ids(v), []string{"known_client"}) {
			t.Fatalf("direto pelo cabeçalho: %s", b)
		}
		h = chromeHeaders("01JC0X3K8V2T7Q9F4M6P1R5T67", 50067)
		_, _, v, b := f.authVerdict("internal", "", h)
		if v.Fingerprints.TCPRTTMicros != nil || v.Fingerprints.TimingSource != nil || !strings.Contains(string(b), `"tcp_rtt_us":null`) {
			t.Fatalf("sem tempos: %s", b)
		}
		if n := f.metrics.Get(authFPMetric("timing", fpNone)); n != 1 {
			t.Errorf("timing/none = %v", n)
		}
	})
	t.Run("header h3", func(t *testing.T) {
		f := newFixture(t)
		// tempos de TCP num h3 não avaliam o sinal (o cabeçalho de h3 nem os traz)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T68", 50068, "h3", uaChrome)
		h["X-Traefix-Timing"] = timingRelay
		if _, _, v, b := f.authVerdict("internal", "", h); slices.Contains(ids(v), "relay_rtt_gap") {
			t.Fatalf("relay_rtt_gap em h3: %s", b)
		}
	})
	t.Run("ingest wins over header", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T69"
		conn := chromeConn(map[string]any{"ja4t": ja4tFull, "ttl": 52})
		conn["timing"] = map[string]any{"source": "user", "tcpRttMicros": 12000, "estToFirstMicros": 1000, "tlsRttMicros": 12400}
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.80", 50069, conn, nil))
		h := chromeHeaders(id, 50069)
		h["X-Traefix-Timing"] = timingRelay
		_, _, v, b := f.authVerdict("internal", "", h)
		if slices.Contains(ids(v), "relay_rtt_gap") || val(v.Fingerprints.TCPRTTMicros) != 12000 {
			t.Fatalf("registro não venceu o cabeçalho: %s", b)
		}
		if n := f.metrics.Get(authFPMetric("timing", fpFromIngest)); n != 1 {
			t.Errorf("timing/ingest = %v", n)
		}
	})
}

// TestTraefixTTLTransport: critério 2 da task 312 — TTL inicial em h3 (udp.ttl e X-Traefix-Ttl) e por X-Traefix-Ttl
// em TCP, com o descarte por origem privada; ua_os_tcp_mismatch avalia a parte de TTL.
func TestTraefixTTLTransport(t *testing.T) {
	ids := func(v Verdict) []string { return signalIDList(v.Signals) }
	h3Conn := func(udp map[string]any) map[string]any {
		conn := chromeConn(nil)
		conn["proto"] = "h3"
		delete(conn, "http2")
		conn["tls"].(map[string]any)["clientHello"] = base64.StdEncoding.EncodeToString(loadGoldenInitials(t)[0].message) //nolint:forcetypeassert // montado acima
		if udp != nil {
			conn["udp"] = udp
		}
		return conn
	}
	h3Req := func() map[string]any {
		r := chromeRequest()
		r["proto"], r["httpVersion"] = "h3", "3"
		return r
	}

	t.Run("ingest h3 windows ttl with macos ua", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T70"
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.81", 50070, h3Conn(map[string]any{"ttl": 116, "ecn": 0}), h3Req()))
		v := f.verdictOf(id)
		if !slices.Contains(ids(v), "ua_os_tcp_mismatch") || v.View.TCP || !v.View.H3 || val(v.Fingerprints.TTLInitial) != 128 ||
			v.Fingerprints.JA4T != nil {
			t.Fatalf("h3 com TTL de Windows: %v %+v %+v", ids(v), v.View, v.Fingerprints)
		}
		if v.Signals[0].Detail != "ua os macos, initial ttl 128" {
			t.Errorf("detalhe: %q", v.Signals[0].Detail)
		}
	})
	t.Run("ingest h3 coherent and private", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T71"
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.82", 50071, h3Conn(map[string]any{"ttl": 52}), h3Req()))
		if v := f.verdictOf(id); slices.Contains(ids(v), "ua_os_tcp_mismatch") || val(v.Fingerprints.TTLInitial) != 64 {
			t.Fatalf("h3 com TTL 64: %v %+v", ids(v), v.Fingerprints)
		}
		for _, ip := range []string{"172.17.0.1", "::1", "fe80::1"} {
			f.postIngest(traefixBatchJSON(t, id, ip, 50072, h3Conn(map[string]any{"ttl": 116}), h3Req()))
			if fc, _ := f.srv.Index().Fork(id, f.clock.Now()); fc.TCP != nil {
				t.Errorf("%s: visão de transporte com origem privada: %+v", ip, fc.TCP)
			}
		}
		for _, bad := range []any{300, -1, "64", 64.5} {
			f.postIngest(traefixBatchJSON(t, id, "198.51.100.82", 50073, h3Conn(map[string]any{"ttl": bad}), h3Req()))
			if fc, _ := f.srv.Index().Fork(id, f.clock.Now()); fc.TCP != nil {
				t.Errorf("udp.ttl %v aceito: %+v", bad, fc.TCP)
			}
		}
	})
	t.Run("header h3 ttl", func(t *testing.T) {
		f := newFixture(t)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T72", 50074, "h3", uaChrome)
		h["X-Traefix-Ttl"] = "116"
		h["X-Traefix-Ja4t"] = ja4tFull // JA4T não existe em h3: ignorado
		_, _, v, b := f.authVerdict("internal", "", h)
		if !slices.Contains(ids(v), "ua_os_tcp_mismatch") || v.View.TCP || val(v.Fingerprints.TTLInitial) != 128 || v.Fingerprints.JA4T != nil {
			t.Fatalf("X-Traefix-Ttl em h3: %s", b)
		}
		if n := f.metrics.Get(authFPMetric("tcp", fpFromHeader)); n != 1 {
			t.Errorf("tcp/header = %v", n)
		}
	})
	t.Run("header tcp ttl completes ja4t", func(t *testing.T) {
		f := newFixture(t)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T73", 50075, "h2", uaChromeWindows)
		h["X-Traefix-Ja4t"], h["X-Traefix-Ttl"] = ja4tFull, "52"
		_, _, v, b := f.authVerdict("internal", "", h)
		if !v.View.TCP || !slices.Contains(ids(v), "ua_os_tcp_mismatch") || val(v.Fingerprints.TTLInitial) != 64 ||
			deref(v.Fingerprints.JA4T) != ja4tFull {
			t.Fatalf("X-Traefix-Ttl em TCP: %s", b)
		}
		// origem privada: nem JA4T nem TTL
		h = traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T74", 50076, "h2", uaChromeWindows)
		h["X-Traefix-Src-Ip"], h["X-Traefix-Ja4t"], h["X-Traefix-Ttl"] = "10.0.0.9", ja4tFull, "52"
		if _, _, v, b := f.authVerdict("internal", "", h); v.View.TCP || v.Fingerprints.TTLInitial != nil {
			t.Fatalf("TTL do cabeçalho com origem privada: %s", b)
		}
	})
	t.Run("header ttl malformed", func(t *testing.T) {
		for _, bad := range []string{"256", "-1", "6 4", "64.0", "0x40", "+64", "", "1234"} {
			f, _, _ := parseForkHeaders(headerOf(traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T75", 50077, "h2", uaChrome), "X-Traefix-Ttl", bad))
			if f.ttl != -1 {
				t.Errorf("X-Traefix-Ttl %q = %d", bad, f.ttl)
			}
		}
		h := headerOf(traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T75", 50077, "h2", uaChrome), "X-Traefix-Ttl", "64")
		h.Add("X-Traefix-Ttl", "64")
		if f, _, _ := parseForkHeaders(h); f.ttl != -1 {
			t.Errorf("X-Traefix-Ttl repetido = %d", f.ttl)
		}
		if f, _, _ := parseForkHeaders(headerOf(traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T75", 50077, "h2", uaChrome), "X-Traefix-Ttl", "0")); f.ttl != 0 {
			t.Errorf("X-Traefix-Ttl 0 = %d", f.ttl)
		}
	})
}

// val devolve o valor apontado (o zero para nil).
func val[T any](p *T) T {
	var z T
	if p != nil {
		z = *p
	}
	return z
}

// headerOf monta o http.Header dos cabeçalhos com mais um valor (vazio também conta como presente).
func headerOf(m map[string]string, name, value string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	h[http.CanonicalHeaderKey(name)] = []string{value}
	return h
}

// withHeader copia o http.Header trocando um cabeçalho.
func withHeader(h http.Header, name, value string) http.Header {
	out := h.Clone()
	out[http.CanonicalHeaderKey(name)] = []string{value}
	return out
}

// TestAuthALPNFromJA4: critério 2 da task 312 (ADR 0065 item 5) — sem X-Traefix-Alpn, o `00` do ALPN na parte a do
// X-Traefix-Ja4 é o ClientHello sem ALPN (lista vazia conhecida) e um UA de Chrome dá ua_alpn_mismatch; outro valor
// segue desconhecido; X-Traefix-Alpn malformado não vira lista vazia.
func TestAuthALPNFromJA4(t *testing.T) {
	chrome := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	noALPN := chrome.JA4[:8] + "00" + chrome.JA4[10:]
	ids := func(v Verdict) []string { return signalIDList(v.Signals) }
	f := newFixture(t)
	h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T80", 50080, "h1", uaChrome)
	h["X-Traefix-Ja4"] = noALPN
	if _, _, v, b := f.authVerdict("internal", "", h); !slices.Contains(ids(v), "ua_alpn_mismatch") || !slices.Contains(ids(v), "ua_h2_mismatch") {
		t.Fatalf("JA4 com ALPN 00 sem ua_alpn_mismatch: %s", b)
	}
	hd := headerOf(h, "X-Traefix-Ja4", noALPN)
	if fh, _, _ := parseForkHeaders(hd); !fh.alpnKnown || fh.alpn == nil || len(fh.alpn) != 0 {
		t.Errorf("ALPN pelo JA4: %+v", fh)
	}
	// ALPN h2 no JA4 sem X-Traefix-Alpn: desconhecido
	if fh, _, _ := parseForkHeaders(headerOf(h, "X-Traefix-Ja4", chrome.JA4)); fh.alpnKnown {
		t.Errorf("JA4 com h2 deu ALPN conhecido: %+v", fh)
	}
	// X-Traefix-Alpn malformado ou repetido continua ausente (não vira lista vazia pelo JA4)
	if fh, _, _ := parseForkHeaders(withHeader(hd, "X-Traefix-Alpn", "%zz")); fh.alpnKnown {
		t.Errorf("Alpn malformado com JA4 00: %+v", fh)
	}
	rep := withHeader(hd, "X-Traefix-Alpn", "h2")
	rep.Add("X-Traefix-Alpn", "h2")
	if fh, _, _ := parseForkHeaders(rep); fh.alpnKnown {
		t.Errorf("Alpn repetido com JA4 00: %+v", fh)
	}
	// X-Traefix-Alpn presente vale sobre o JA4
	if fh, _, _ := parseForkHeaders(withHeader(hd, "X-Traefix-Alpn", "h2,http/1.1")); !fh.alpnKnown || !slices.Equal(fh.alpn, []string{"h2", "http/1.1"}) {
		t.Errorf("Alpn com JA4 00: %+v", fh)
	}
	// o conjunto antigo (X-Fs-*) não tem a regra
	old := http.Header{}
	for k, v := range forkHeadersFor() {
		old.Set(k, v)
	}
	old.Set("X-Fs-Ja4", noALPN)
	if fh, _, _ := parseForkHeaders(old); fh.alpnKnown {
		t.Errorf("X-Fs-Ja4 com ALPN 00: %+v", fh)
	}
}

// TestAuthDetailHeaders: critério da task 312 (ADR 0065 item 6) — X-Traefix-Ja3n, -Ja4r e -Ja4o entram no
// Fingerprints com a visão TLS do cabeçalho; malformados ou repetidos são ausentes; com o registro do ingest valem os
// dele; os outros cabeçalhos de detalhe não aparecem em lugar nenhum do veredito.
func TestAuthDetailHeaders(t *testing.T) {
	chrome := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	f := newFixture(t)
	h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T81", 50081, "h1", uaChrome)
	h["X-Traefix-Ja4"], h["X-Traefix-Ja3n"], h["X-Traefix-Ja4r"], h["X-Traefix-Ja4o"] = chrome.JA4, chrome.JA3NMD5, chrome.JA4R, chrome.JA4O
	h["X-Traefix-Cookie-Names"], h["X-Traefix-Header-Order"] = "session-secret-name", "host,x-leak-order"
	_, _, v, b := f.authVerdict("internal", "", h)
	fp := v.Fingerprints
	if deref(fp.JA3N) != chrome.JA3NMD5 || deref(fp.JA4R) != chrome.JA4R || deref(fp.JA4O) != chrome.JA4O {
		t.Fatalf("detalhe no Fingerprints: %s", b)
	}
	if strings.Contains(string(b), "session-secret-name") || strings.Contains(string(b), "x-leak-order") {
		t.Errorf("cabeçalho de detalhe ignorado foi ao veredito: %s", b)
	}
	if !testing.Short() {
		validateContract(t, refVerdict, b)
	}
	for name, bad := range map[string]string{
		"X-Traefix-Ja3n": "XYZ", "X-Traefix-Ja4r": "t13d1517h2" + strings.Repeat("a", maxJA4RHeader), "X-Traefix-Ja4o": "nope",
	} {
		if fh, _, _ := parseForkHeaders(headerOf(h, name, bad)); fh.ja3n == bad || fh.ja4r == bad || fh.ja4o == bad {
			t.Errorf("%s malformado aceito: %+v", name, fh)
		}
	}
	rep := headerOf(h, "X-Traefix-Ja3n", chrome.JA3NMD5)
	rep.Add("X-Traefix-Ja3n", chrome.JA3NMD5)
	if fh, _, _ := parseForkHeaders(rep); fh.ja3n != "" {
		t.Errorf("X-Traefix-Ja3n repetido aceito: %q", fh.ja3n)
	}
	// com o registro de conexão do ingest, as fingerprints dele valem
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T82"
	f.postIngest(traefixBatchJSON(t, id, "198.51.100.83", 50082, chromeConn(nil), nil))
	h = traefixAuthHeaders(id, 50082, "h2", uaChrome)
	h["X-Traefix-Ja3n"], h["X-Traefix-Ja4o"] = strings.Repeat("0", 32), "t13d1517h2_000000000000_000000000000"
	if _, _, v, b := f.authVerdict("internal", "", h); deref(v.Fingerprints.JA3N) != chrome.JA3NMD5 || deref(v.Fingerprints.JA4O) != chrome.JA4O {
		t.Fatalf("detalhe do cabeçalho venceu o ingest: %s", b)
	}
}
