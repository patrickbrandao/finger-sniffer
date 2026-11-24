package bot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/akamai"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/p0f"
)

const refTraefixBatch = "#/components/schemas/TraefixFingerprintBatch"

// ingestSample lê um lote de exemplo de testdata/ingest.
func ingestSample(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ingest", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ingestSamples são os lotes de exemplo traefix.fingerprint/v1 válidos e o que o ingest conta de cada um.
var ingestSamples = []struct {
	file                       string
	connID                     string
	accepted, rejected, ignore int
}{
	{"h1-tcp.json", "01JC0X3K8V2T7Q9F4M6P1R5T01", 2, 0, 0},
	{"h2-tcp.json", "01JC0X3K8V2T7Q9F4M6P1R5T02", 2, 0, 0},
	{"h3-quic.json", "01JC0X3K8V2T7Q9F4M6P1R5T03", 2, 0, 0},
	{"conn-only.json", "01JC0X3K8V2T7Q9F4M6P1R5T04", 1, 0, 0},
	{"ready-only.json", "01JC0X3K8V2T7Q9F4M6P1R5T05", 2, 0, 0},
	{"fields-repeated.json", "01JC0X3K8V2T7Q9F4M6P1R5T06", 2, 0, 0},
	{"unknown.json", "01JC0X3K8V2T7Q9F4M6P1R5T07", 2, 0, 1},
	{"private-origin.json", "01JC0X3K8V2T7Q9F4M6P1R5T09", 2, 0, 0},
}

// postIngest manda o lote pela 9003 e devolve status e a contagem.
func (f *fixture) postIngest(body string) (int, map[string]int) {
	f.t.Helper()
	c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, body)
	var out map[string]int
	_ = json.Unmarshal(b, &out)
	return c, out
}

// TestTraefixSchemaSamples: critério 1 da task 302 — os lotes traefix.fingerprint/v1 de exemplo entram pela mesma
// rota do formato anterior, com campo e tipo de registro desconhecidos ignorados, e cada visão sai como o RF-07
// da spec 019 lê.
func TestTraefixSchemaSamples(t *testing.T) {
	for _, s := range ingestSamples {
		t.Run(s.file, func(t *testing.T) {
			f := newFixture(t)
			c, got := f.postIngest(string(ingestSample(t, s.file)))
			if c != 202 || got["accepted"] != s.accepted || got["rejected"] != s.rejected {
				t.Fatalf("ingest: %d %v", c, got)
			}
			if n := f.metrics.Get(metricIngestIgnored + `{type="tls-alert"}`); int(n) != s.ignore {
				t.Errorf("ignored = %v, quer %d", n, s.ignore)
			}
			for _, k := range mismatchKinds {
				if n := f.metrics.Get(mismatchMetric(k)); n != 0 {
					t.Errorf("divergência %s = %v", k, n)
				}
			}
			for _, part := range []string{PartClientHello, PartH2Prefix} {
				if n := f.metrics.Get(metricIngestParseErrors + `{part="` + part + `"}`); n != 0 {
					t.Errorf("parse_errors{%s} = %v", part, n)
				}
			}
			fc, ok := f.srv.Index().Fork(s.connID, f.clock.Now())
			if !ok || !fc.HasConnRecord || fc.EntryPoint != "websecure" || !fc.HasSrc {
				t.Fatalf("conexão: %+v", fc)
			}
			checkSample(t, s.file, &fc)
		})
	}
	// schema desconhecido: 400 com o lote inteiro recusado
	f := newFixture(t)
	if c, got := f.postIngest(string(ingestSample(t, "bad-schema.json"))); c != 400 {
		t.Fatalf("schema desconhecido: %d %v", c, got)
	}
	if _, ok := f.srv.Index().Fork("01JC0X3K8V2T7Q9F4M6P1R5T08", f.clock.Now()); ok {
		t.Error("registro de lote recusado entrou no índice")
	}
}

// checkSample confere a visão de cada lote de exemplo.
func checkSample(t *testing.T, file string, fc *ForkConn) {
	t.Helper()
	switch file {
	case "h1-tcp.json":
		g := loadGoldenSYNs(t, "curl-linux-v4")[0]
		if fc.TLS == nil || fc.TLS.Ready || fc.TLS.ParseError || !strings.HasPrefix(fc.TLS.JA4, "t") {
			t.Errorf("tls: %+v", fc.TLS)
		}
		tc := fc.TCP
		if tc == nil || tc.JA4T != g.ja4t || tc.P0f != g.p0fSig || tc.TTLInitial != 128 || tc.RTTMicros == nil ||
			*tc.RTTMicros != 1834 || deref2(tc.SynMSS) != 1460 || deref2(tc.MTUImplied) != 1500 || deref2(tc.MSSReduction) != 0 {
			t.Errorf("tcp: %+v", tc)
		}
		if len(fc.Requests) != 1 || fc.Requests[0].Fields["User-Agent"] != "curl/8.5.0" || fc.Requests[0].HTTPVersion != "1.1" {
			t.Errorf("requisição: %+v", fc.Requests)
		}
		// timing (ADR 0065 item 2): só os campos que o bot usa
		tm := fc.Timing
		if tm == nil || tm.Source != timingKernel || tm.QUIC || tm.TCPRTT != (micros{1834, true}) ||
			tm.EstToFirst != (micros{1210, true}) || tm.TLSRTT != (micros{2240, true}) || tm.RTTGap != (micros{406, true}) ||
			tm.QUICRTT.ok || tm.cost != forkTimingBytes {
			t.Errorf("timing: %+v", tm)
		}
	case "h2-tcp.json":
		if fc.H2 == nil || fc.H2.Ready || fc.H2.Akamai == "" || fc.H2.HeadersPriority != "1:1:0:256" {
			t.Errorf("h2: %+v", fc.H2)
		}
		if fc.TCP == nil || fc.TCP.JA4T != "64240_2-4-8-1-3_1460_12" || deref2(fc.TCP.MSSReduction) != 0 {
			t.Errorf("tcp: %+v", fc.TCP)
		}
	case "h3-quic.json":
		if fc.TLS == nil || fc.TLS.ParseError || !strings.HasPrefix(fc.TLS.JA4, "q") {
			t.Errorf("tls do QUIC: %+v", fc.TLS)
		}
		// em h3, a visão de transporte só com o TTL do udp (ADR 0065 item 4)
		if fc.TCP == nil || !fc.TCP.UDP || fc.TCP.TTL != 50 || fc.TCP.TTLInitial != 64 || fc.TCP.JA4T != "" || fc.TCP.SynMSS != nil {
			t.Errorf("visão de transporte em h3: %+v", fc.TCP)
		}
		if tm := fc.Timing; tm == nil || !tm.QUIC || tm.Source != timingUser || tm.QUICRTT != (micros{23500, true}) ||
			tm.QUICMinRTT != (micros{23100, true}) || tm.TCPRTT.ok || tm.rules() != nil {
			t.Errorf("timing do h3: %+v", tm)
		}
	case "conn-only.json":
		if len(fc.Requests) != 0 || fc.SNI != "www.example.com" || fc.TLS != nil || fc.TCP != nil || fc.Timing != nil {
			t.Errorf("conexão sem requisição: %+v", fc)
		}
	case "ready-only.json":
		calc := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
		v := fc.TLS
		if v == nil || !v.Ready || v.JA3 != calc.JA3 || v.JA3MD5 != calc.JA3MD5 || v.JA3N != calc.JA3N ||
			v.JA3NMD5 != calc.JA3NMD5 || v.JA4 != calc.JA4 || v.JA4R != calc.JA4R || v.JA4O != calc.JA4O ||
			!slices.Equal(v.ALPN, []string{"h2", "http/1.1"}) {
			t.Errorf("tls pronta: %+v", v)
		}
		h := fc.H2
		want := analyzeH2Prefix(goldenBytes("h2/chrome.prefix"), false)
		if h == nil || !h.Ready || h.Akamai != want.Akamai || !slices.Equal(h.Settings, want.Settings) ||
			h.WindowUpdate == nil || *h.WindowUpdate != *want.WindowUpdate || !slices.Equal(h.PseudoOrder, want.PseudoOrder) ||
			!h.HeadersSeen || h.HeadersPriority != "1:1:0:256" {
			t.Errorf("h2 pronta: %+v", h)
		}
		if fc.TCP == nil || fc.TCP.JA4T != "64240_2-4-8-1-3_1460_12" || fc.TCP.TTLInitial != 128 || fc.TCP.OSGuess != "" ||
			deref2(fc.TCP.SynMSS) != 1460 {
			t.Errorf("tcp sem SYN: %+v", fc.TCP)
		}
	case "fields-repeated.json":
		r := fc.Requests[0]
		if len(r.Fields) != 2 || r.Fields["User-Agent"] != "First/1.0" || r.Fields["Accept"] != "text/html" {
			t.Errorf("fields: %v", r.Fields)
		}
		if !slices.Equal(r.FieldNames, []string{"User-Agent", "user-agent", "X-Custom", "Accept"}) {
			t.Errorf("field_names: %v", r.FieldNames)
		}
	case "unknown.json":
		if len(fc.Requests) != 1 || fc.SNI != "www.example.com" {
			t.Errorf("registros conhecidos: %+v", fc)
		}
	case "private-origin.json":
		if fc.TCP != nil {
			t.Errorf("visão TCP com origem privada: %+v", fc.TCP)
		}
	}
}

func deref2(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// TestTraefixSamplesContract: critério 5 da task 302 — os lotes de exemplo validam contra o TraefixFingerprintBatch
// do openapi 0.4.0 e contra a cópia do esquema do traefix; o de schema inválido é reprovado pelas duas.
func TestTraefixSamplesContract(t *testing.T) {
	if testing.Short() {
		t.Skip("contrato via Redocly pulado com -short")
	}
	var vals [][]byte
	for _, s := range ingestSamples {
		vals = append(vals, ingestSample(t, s.file))
	}
	for _, ref := range []string{refTraefixBatch, refTraefixIngestBody} {
		if out, err := lintContractWith(t, ref, true, nil, vals...); err != nil {
			t.Fatalf("lotes não validam contra %s: %v\n%s", ref, err, out)
		}
	}
	if out, err := lintTraefixCopy(t, vals...); err != nil {
		t.Fatalf("lotes não validam contra a cópia do esquema do traefix: %v\n%s", err, out)
	}
	bad := ingestSample(t, "bad-schema.json")
	if out, err := lintContractWith(t, refTraefixBatch, true, nil, bad); err == nil {
		t.Errorf("schema inválido aceito pelo openapi:\n%s", out)
	}
	if out, err := lintTraefixCopy(t, bad); err == nil {
		t.Errorf("schema inválido aceito pela cópia:\n%s", out)
	}
	// e a cópia reprova um registro de conexão fora do esquema (o teste não passa vazio)
	if out, err := lintTraefixCopy(t, []byte(`{"schema":"traefix.fingerprint/v1","sender":"traefix/x","entryPoint":"e",`+
		`"sentAt":"2026-11-16T12:00:00Z","records":[{"type":"connection","connId":"bad"}]}`)); err == nil {
		t.Errorf("registro inválido aceito pela cópia:\n%s", out)
	}
}

// TestTraefixQUICClientHello: critério 2 da task 302 — o ClientHello do QUIC como mensagem de handshake pura (a
// forma do traefix) sai sem parse_error e com o JA4 `q` igual ao do pkg/quicparse (o web) e ao do ja4 da FoxIO,
// pela detecção dos bytes e com proto h3.
func TestTraefixQUICClientHello(t *testing.T) {
	for _, g := range loadGoldenInitials(t) {
		t.Run(g.name, func(t *testing.T) {
			for _, quic := range []bool{false, true} {
				got := analyzeClientHelloAs(g.message, false, quic)
				if got.ParseError || got.JA4 != g.webJA4 || got.JA4 != g.toolJA4 || !strings.HasPrefix(got.JA4, "q") {
					t.Errorf("quic=%v: ja4 %q (parse_error %v), web %q, ja4 %q", quic, got.JA4, got.ParseError, g.webJA4, g.toolJA4)
				}
			}
			// pelo formato anterior também (proto h3), sem parse_error
			f := newFixture(t)
			rec := `{"records":[{"type":"connection","fs_conn_id":"` + testForkConnID + `","ts":"2026-11-16T12:00:00Z",` +
				`"proto":"h3","client_hello":"` + base64.StdEncoding.EncodeToString(g.message) + `"}]}`
			if c, got := f.postIngest(rec); c != 202 || got["accepted"] != 1 {
				t.Fatalf("ingest: %d %v", c, got)
			}
			if n := f.metrics.Get(metricIngestParseErrors + `{part="client_hello"}`); n != 0 {
				t.Errorf("parse_error do QUIC: %v", n)
			}
		})
	}
	// QUIC cortado continua parse_error
	g := loadGoldenInitials(t)[0]
	if got := analyzeClientHelloAs(g.message[:len(g.message)/2], false, true); !got.ParseError {
		t.Errorf("mensagem cortada sem parse_error: %+v", got)
	}
}

// goldenP0FDB carrega o p0f.fp real (FS_P0F_DB ou o do deploy), como o teste golden do store; nil sem ele (o
// p0f.fp é LGPL e não vai para o repositório).
func goldenP0FDB() *p0f.DB {
	path := os.Getenv("FS_P0F_DB")
	if path == "" {
		path = "/finger-sniffer/etc/p0f.fp"
	}
	db, err := p0f.LoadDB(path)
	if err != nil {
		return nil
	}
	return db
}

// TestTraefixTCPViewGoldenSYNs: critério da task 302 — do SYN cru do traefix (desde o cabeçalho IP), o JA4T, o
// raw_sig e o SO do p0f são os mesmos que o store calcula dos mesmos SYNs de test/golden/pcaps (as referências do
// ja4 da FoxIO e do p0f -r que o teste golden do store confere); o SO só com o p0f.fp real.
func TestTraefixTCPViewGoldenSYNs(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(goldenPcapDir, "*.pcap"))
	if len(files) < 8 {
		t.Fatalf("só %d golden pcaps", len(files))
	}
	db := goldenP0FDB()
	n := 0
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".pcap")
		t.Run(name, func(t *testing.T) {
			for _, g := range loadGoldenSYNs(t, name) {
				if g.ja4t == "" {
					continue
				}
				n++
				syn := base64.StdEncoding.EncodeToString(g.ip)
				res := buildTCPView(&traefixTCP{SYN: &syn}, mustAddr("198.51.100.50"), db)
				v := res.view
				if v == nil || v.JA4T != g.ja4t {
					t.Errorf("porta %d: ja4t %+v, ja4 = %s", g.port, v, g.ja4t)
					continue
				}
				// o mesmo pacote que o store passa ao p0f: o raw_sig bate com o p0f -r
				pk, err := p0f.Parse(g.ip)
				if err != nil {
					t.Fatal(err)
				}
				if obs, err := (&p0f.DB{}).Fingerprint(pk, 0); err != nil || (g.p0fSig != "" && obs.RawSig != g.p0fSig) {
					t.Errorf("porta %d: raw_sig %q, p0f -r %q", g.port, obs.RawSig, g.p0fSig)
				}
				if db != nil && g.p0fOS != "" {
					want := g.p0fOS
					if want == "???" {
						want = ""
					}
					if v.OSGuess != want {
						t.Errorf("porta %d: os %q, p0f -r %q", g.port, v.OSGuess, g.p0fOS)
					}
				}
				// MSS e derivados pelas regras do store (spec 013 RF-06a)
				mss, ok := ja4tMSS(g.ja4t)
				if !ok || deref2(v.SynMSS) != mss {
					t.Errorf("porta %d: syn_mss %v, ja4t %s", g.port, v.SynMSS, g.ja4t)
				}
				if v.TTLInitial == 0 {
					t.Errorf("porta %d: sem ttl inicial", g.port)
				}
			}
		})
	}
	if n < 8 {
		t.Fatalf("só %d SYNs conferidos", n)
	}
	if db == nil {
		t.Log("p0f.fp ausente: SO do p0f conferido só no SYN do Windows, com o p0f.fp mínimo")
	}
	// Sem o p0f.fp real: o SYN do Windows contra o p0f.fp mínimo dá o mesmo SO do p0f -r.
	fx, err := p0f.ParseDB(strings.NewReader(fixtureP0F))
	if err != nil {
		t.Fatal(err)
	}
	g := loadGoldenSYNs(t, "windows-foxio")[0]
	syn := base64.StdEncoding.EncodeToString(g.ip)
	if v := buildTCPView(&traefixTCP{SYN: &syn}, mustAddr("198.51.100.50"), fx).view; v == nil || v.OSGuess != g.p0fOS {
		t.Errorf("windows-foxio: os %+v, p0f -r %q", v, g.p0fOS)
	}
}

// fixtureP0F é um p0f.fp mínimo com a assinatura do SYN do Windows de windows-foxio (o p0f.fp real é LGPL e não
// vai para o repositório).
const fixtureP0F = `classes = win,unix,other

[tcp:request]
label = s:win:Windows:NT kernel
sig   = *:128:0:*:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
`

// withP0F põe no serviço do fixture o p0f.fp mínimo.
func (f *fixture) withP0F() {
	f.t.Helper()
	path := filepath.Join(f.t.TempDir(), "p0f.fp")
	if err := os.WriteFile(path, []byte(fixtureP0F), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.srv.judge.p0f = newP0FSource(path, nil)
}

// traefixBatchJSON monta um lote traefix.fingerprint/v1 com uma conexão e uma requisição.
func traefixBatchJSON(t *testing.T, id, srcIP string, srcPort int, conn, req map[string]any) string {
	t.Helper()
	c := map[string]any{
		"type": "connection", "connId": id, "time": "2026-11-16T12:00:00.010000000Z",
		"src": map[string]any{"ip": srcIP, "port": srcPort}, "dst": map[string]any{"ip": "10.249.0.2", "port": 443},
	}
	for k, v := range conn {
		c[k] = v
	}
	recs := []any{c}
	if req != nil {
		r := map[string]any{
			"type": "request", "connId": id, "start": "2026-11-16T12:00:00.020000000Z", "end": "2026-11-16T12:00:00.030000000Z",
			"proto": "h2", "method": "GET", "authority": "www.example.com", "path": "/", "httpVersion": "2.0", "status": 200,
		}
		for k, v := range req {
			r[k] = v
		}
		recs = append(recs, r)
	}
	b, err := json.Marshal(map[string]any{
		"schema": SchemaTraefixV1, "sender": "traefix/test", "entryPoint": "websecure",
		"sentAt": "2026-11-16T12:00:01Z", "records": recs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// chromeRequest é o resumo de uma requisição de Chrome (UA de macOS, Accept-Language, JA4H medido).
func chromeRequest() map[string]any {
	return map[string]any{
		"fieldNames": chromeFields, "ja4h": "ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000",
		"fields": []map[string]string{{"name": "user-agent", "value": uaChrome}, {"name": "accept-language", "value": "pt-BR"}},
	}
}

// chromeConn é o registro de conexão de Chrome com os bytes crus (TLS e h2) e o tcp dado.
func chromeConn(tcp map[string]any) map[string]any {
	b64 := base64.StdEncoding.EncodeToString
	c := map[string]any{
		"proto": "h2",
		"tls": map[string]any{
			"sni": "www.example.com", "alpnOffered": []string{"h2", "http/1.1"}, "alpn": "h2",
			"clientHello": b64(goldenBytes("tls/chrome.bin")),
		},
		"http2": map[string]any{"prefix": b64(goldenBytes("h2/chrome.prefix"))},
	}
	if tcp != nil {
		c["tcp"] = tcp
	}
	return c
}

// verdictOf consulta o veredito da conexão do traefix.
func (f *fixture) verdictOf(id string) Verdict {
	f.t.Helper()
	c, _, b := f.do(f.internal, "GET", "/bot/v1/verdict/conn/"+id, "", nil, "")
	if c != 200 {
		f.t.Fatalf("consulta: %d %s", c, b)
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		f.t.Fatal(err)
	}
	return v
}

// TestTraefixTCPViewRules: critério 4 da task 302 — sem o store, a visão TCP do traefix alimenta as regras de TCP
// (ua_os_tcp_mismatch pelo SO do p0f do SYN, known_client pelo JA4T, tunnel_mss pelo MSS) com view.tcp=true; com
// origem privada ela é descartada; com o store casado, a visão do store vence e a divergência do JA4T é contada.
func TestTraefixTCPViewRules(t *testing.T) {
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T20"
	win := loadGoldenSYNs(t, "windows-foxio")[0]
	winSYN := base64.StdEncoding.EncodeToString(win.ip)
	winTCP := map[string]any{"syn": winSYN, "ttl": 128}

	t.Run("ua_os_tcp_mismatch", func(t *testing.T) {
		f := newFixture(t)
		f.withP0F()
		if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.60", 50001, chromeConn(winTCP), chromeRequest())); c != 202 ||
			got["accepted"] != 2 {
			t.Fatalf("ingest: %d %v", c, got)
		}
		v := f.verdictOf(id)
		if !v.View.TCP || !slices.Contains(signalIDList(v.Signals), "ua_os_tcp_mismatch") {
			t.Fatalf("veredito: %+v %v", v.View, signalIDList(v.Signals))
		}
		if v.Fingerprints.P0fOS == nil || *v.Fingerprints.P0fOS != "Windows NT kernel" || v.Fingerprints.JA4T == nil ||
			*v.Fingerprints.JA4T != win.ja4t || v.Fingerprints.TTLInitial == nil || *v.Fingerprints.TTLInitial != 128 {
			t.Errorf("fingerprints: %+v", v.Fingerprints)
		}
	})
	t.Run("private_origin", func(t *testing.T) {
		f := newFixture(t)
		f.withP0F()
		for _, ip := range []string{"172.17.0.1", "10.0.0.5", "192.168.1.2", "127.0.0.1", "169.254.1.1", "fd00::1", "::1", "fe80::1"} {
			if c, got := f.postIngest(traefixBatchJSON(t, id, ip, 50002, chromeConn(winTCP), chromeRequest())); c != 202 ||
				got["accepted"] != 2 {
				t.Fatalf("ingest %s: %d %v", ip, c, got)
			}
			v := f.verdictOf(id)
			if v.View.TCP || slices.Contains(signalIDList(v.Signals), "ua_os_tcp_mismatch") {
				t.Errorf("%s: visão TCP usada: %+v %v", ip, v.View, signalIDList(v.Signals))
			}
		}
	})
	t.Run("known_client", func(t *testing.T) {
		f := newFixture(t)
		tcp := map[string]any{"ja4t": ja4tFull, "ttl": 52}
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.61", 50003, chromeConn(tcp), chromeRequest()))
		v := f.verdictOf(id)
		if !v.View.TCP || v.Class != ClassHuman || !slices.Equal(signalIDList(v.Signals), []string{"known_client"}) {
			t.Fatalf("veredito: %s %+v %v", v.Class, v.View, signalIDList(v.Signals))
		}
	})
	t.Run("tunnel_mss", func(t *testing.T) {
		f := newFixture(t)
		tcp := map[string]any{"ja4t": "65535_2-1-3-1-1-8-4-0-0_1400_6", "ttl": 52}
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.62", 50004, chromeConn(tcp), chromeRequest()))
		v := f.verdictOf(id)
		if !v.View.TCP || !slices.Contains(signalIDList(v.Signals), "tunnel_mss") {
			t.Fatalf("veredito: %+v %v", v.View, signalIDList(v.Signals))
		}
	})
	t.Run("h3_without_tcp", func(t *testing.T) {
		f := newFixture(t)
		conn := chromeConn(winTCP)
		conn["proto"] = "h3"
		delete(conn, "http2")
		conn["tls"].(map[string]any)["clientHello"] = base64.StdEncoding.EncodeToString(loadGoldenInitials(t)[0].message)
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.63", 50005, conn, map[string]any{"proto": "h3", "httpVersion": "3"}))
		if fc, _ := f.srv.Index().Fork(id, f.clock.Now()); fc.TCP != nil {
			t.Errorf("visão TCP em h3: %+v", fc.TCP)
		}
	})
	t.Run("store_wins", func(t *testing.T) {
		f := newFixture(t)
		f.withP0F()
		f.srv.Index().PutStore(&StoreConn{
			ConnID: testStoreConnID, Stage: StageOpened, L4: "tcp", SrcIP: mustAddr("198.51.100.64"), SrcPort: 50006,
			DstIP: mustAddr("203.0.113.10"), DstPort: 443, Started: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC),
			Record: json.RawMessage(`{"ip":{"ttl_initial":64},"tcp":{"ja4t":"` + ja4tFull + `","os_guess":"Mac OS X"}}`),
		}, f.clock.Now())
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.64", 50006, chromeConn(winTCP), chromeRequest()))
		v := f.verdictOf(id)
		if v.Fingerprints.JA4T == nil || *v.Fingerprints.JA4T != ja4tFull || slices.Contains(signalIDList(v.Signals), "ua_os_tcp_mismatch") {
			t.Errorf("visão do store não venceu: %+v %v", v.Fingerprints, signalIDList(v.Signals))
		}
		if n := f.metrics.Get(mismatchMetric(mismatchJA4T)); n != 1 {
			t.Errorf("mismatch{ja4t} = %v", n)
		}
		// uma vez por conexão: a segunda requisição não conta de novo
		f.postIngest(`{"schema":"traefix.fingerprint/v1","records":[{"type":"request","connId":"` + id +
			`","start":"2026-11-16T12:00:00.040000000Z","proto":"h2","authority":"www.example.com"}]}`)
		if n := f.metrics.Get(mismatchMetric(mismatchJA4T)); n != 1 {
			t.Errorf("mismatch{ja4t} depois da segunda requisição = %v", n)
		}
	})
}

// TestTraefixReadyMismatch: critério 3 da task 302 — com os bytes crus e as prontas, vale a calculada e cada
// divergência conta no seu kind; pronta malformada é ausente (sem divergência e, sem bytes, sem visão).
func TestTraefixReadyMismatch(t *testing.T) {
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T21"
	f := newFixture(t)
	conn := chromeConn(nil)
	tl := conn["tls"].(map[string]any)
	tl["ja3"], tl["ja3n"] = strings.Repeat("0", 32), strings.Repeat("1", 32)
	tl["ja4"], tl["ja4r"], tl["ja4o"] = "t13d1517h2_000000000000_000000000000", "t13d1517h2_0000", "t13d1517h2_111111111111_111111111111"
	conn["http2"].(map[string]any)["akamai"] = "1:1|00|0|m,a,s,p"
	if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.70", 50010, conn, nil)); c != 202 || got["accepted"] != 1 {
		t.Fatalf("ingest: %d %v", c, got)
	}
	for _, k := range []string{mismatchJA3, mismatchJA3N, mismatchJA4, mismatchJA4R, mismatchJA4O, mismatchAkamai} {
		if n := f.metrics.Get(mismatchMetric(k)); n != 1 {
			t.Errorf("mismatch{%s} = %v", k, n)
		}
	}
	fc, _ := f.srv.Index().Fork(id, f.clock.Now())
	calc := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	if fc.TLS == nil || fc.TLS.Ready || fc.TLS.JA4 != calc.JA4 || fc.H2 == nil || fc.H2.Ready {
		t.Errorf("a calculada não venceu: %+v %+v", fc.TLS, fc.H2)
	}

	// malformadas: nem divergência nem visão pronta
	g := newFixture(t)
	bad := map[string]any{
		"tls":   map[string]any{"ja3": "XYZ", "ja4": "not-a-ja4", "ja4o": strings.Repeat("a", 40)},
		"http2": map[string]any{"akamai": "a|b|c|d"}, "tcp": map[string]any{"ja4t": "bogus", "ttl": 300},
	}
	if c, got := g.postIngest(traefixBatchJSON(t, id, "198.51.100.71", 50011, bad, nil)); c != 202 || got["accepted"] != 1 {
		t.Fatalf("ingest: %d %v", c, got)
	}
	fc, _ = g.srv.Index().Fork(id, g.clock.Now())
	if fc.TLS != nil || fc.H2 != nil || fc.TCP != nil {
		t.Errorf("pronta malformada virou visão: %+v %+v %+v", fc.TLS, fc.H2, fc.TCP)
	}
	g.postIngest(traefixBatchJSON(t, id, "198.51.100.71", 50011, map[string]any{"tls": map[string]any{
		"clientHello": base64.StdEncoding.EncodeToString(goldenBytes("tls/chrome.bin")), "ja4": "bogus",
	}}, nil))
	for _, k := range mismatchKinds {
		if n := g.metrics.Get(mismatchMetric(k)); n != 0 {
			t.Errorf("malformada contou divergência %s", k)
		}
	}
}

// TestTraefixRecordTolerance: ADR 0063 item 2 — tipo desconhecido fora de rejected (rótulo saneado, cortado em 32
// bytes, no máximo 16 valores e o resto em other); registro sem o que o bot lê (connId, time/start) recusado;
// entryPoint do lote nos registros sem ele; status 0 aceito; schema null é o formato anterior.
func TestTraefixRecordTolerance(t *testing.T) {
	f := newFixture(t)
	var recs []string
	for i := range 20 {
		recs = append(recs, `{"type":"future-`+string(rune('a'+i))+`"}`)
	}
	recs = append(recs, `{"type":"`+strings.Repeat("x", 40)+`"}`, `{"type":"a b\"c"}`, `{"type":""}`, `{"type":7}`, `{"connId":"x"}`,
		`{"type":"request","start":"2026-11-16T12:00:00Z"}`,
		`{"type":"connection","connId":"01JC0X3K8V2T7Q9F4M6P1R5T30"}`,
		`{"type":"request","connId":"01JC0X3K8V2T7Q9F4M6P1R5T31","start":"2026-11-16T12:00:00Z","status":0,"proto":"h1"}`,
		`{"type":"connection","connId":"01JC0X3K8V2T7Q9F4M6P1R5T31","time":"2026-11-16T12:00:00Z"}`)
	body := `{"schema":"traefix.fingerprint/v1","entryPoint":"web","records":[` + strings.Join(recs, ",") + `]}`
	c, got := f.postIngest(body)
	// 2 aceitos; recusados: type 7, sem type, request sem connId, connection sem time
	if c != 202 || got["accepted"] != 2 || got["rejected"] != 4 {
		t.Fatalf("ingest: %d %v", c, got)
	}
	labels := 0
	for k := range f.metrics.Snapshot() {
		if !strings.HasPrefix(k, metricIngestIgnored+"{") {
			continue
		}
		labels++
		if _, l, ok := parseMetricKey(k); !ok || len(l["type"]) > 32 {
			t.Errorf("rótulo fora do formato: %s", k)
		}
	}
	if labels != maxIgnoredTypes+1 {
		t.Errorf("%d rótulos de ignored, quer %d (16 + other)", labels, maxIgnoredTypes+1)
	}
	// 4 futuros além dos 16, o de 40 bytes, o de aspas e o vazio
	if n := f.metrics.Get(metricIngestIgnored + `{type="other"}`); n != 7 {
		t.Errorf("ignored{other} = %v", n)
	}
	var g ignoredTypes
	if l := g.label(strings.Repeat("x", 40)); l != strings.Repeat("x", 32) {
		t.Errorf("rótulo cortado: %q", l)
	}
	if l := g.label(`a b"c`); l != "a_b_c" {
		t.Errorf("rótulo saneado: %q", l)
	}
	fc, ok := f.srv.Index().Fork("01JC0X3K8V2T7Q9F4M6P1R5T31", f.clock.Now())
	if !ok || fc.EntryPoint != "web" || len(fc.Requests) != 1 || fc.Requests[0].Status == nil || *fc.Requests[0].Status != 0 {
		t.Errorf("conexão: %+v", fc)
	}
	// schema null = formato anterior
	if c, got := f.postIngest(`{"schema":null,"records":[]}`); c != 202 || got["accepted"] != 0 {
		t.Errorf("schema null: %d %v", c, got)
	}
	// formato anterior: tipo desconhecido segue recusado
	if c, got := f.postIngest(`{"records":[{"type":"future","fs_conn_id":"` + testForkConnID + `","ts":"2026-11-16T12:00:00Z"}]}`); c != 202 ||
		got["rejected"] != 1 {
		t.Errorf("formato anterior: %d %v", c, got)
	}
	for _, body := range []string{`{"schema":"","records":[]}`, `{"schema":"traefix.fingerprint/v2","records":[]}`, `{"schema":1,"records":[]}`} {
		if c, _ := f.postIngest(body); c != 400 {
			t.Errorf("%s: %d", body, c)
		}
	}
}

// TestTraefixIngestKeyDomains: a conferência de sni/authority contra os domínios da chave vale no esquema novo.
func TestTraefixIngestKeyDomains(t *testing.T) {
	f := newFixture(t)
	_, key := f.createKey(KeyOptions{Name: "site", Domains: []string{"other.org"}, RatePerS: 1000, Burst: 1000})
	c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", key, nil, string(ingestSample(t, "h1-tcp.json")))
	if c != 202 || !strings.Contains(string(b), `"accepted":0,"rejected":2`) {
		t.Fatalf("chave de outro domínio: %d %s", c, b)
	}
}

// TestParseAkamaiRoundTrip: as partes do Akamai pronto refazem o mesmo Akamai pelo pkg/fingerprint/akamai.
func TestParseAkamaiRoundTrip(t *testing.T) {
	for _, name := range []string{"chrome", "firefox", "go", "curl-openssl", "curl-libressl"} {
		want := analyzeH2Prefix(goldenBytes("h2/"+name+".prefix"), false).Akamai
		p, ok := parseAkamai(want)
		if !ok {
			t.Fatalf("%s: %q não analisado", name, want)
		}
		if got := akamai.Fingerprint(akamai.Input{
			Settings: p.settings, WindowUpdate: p.windowUpdate, Priorities: p.priorities,
			PseudoOrder: p.pseudo,
		}); got != want {
			t.Errorf("%s: %q ≠ %q", name, got, want)
		}
	}
	for _, bad := range []string{"", "a|b|c", "1:x|00|0|m", "1:1|x|0|m", "1:1|00|1:2|m", "1:1|00|0|mm"} {
		if _, ok := parseAkamai(bad); ok {
			t.Errorf("%q aceito", bad)
		}
	}
}

// TestTraefixRequestWithoutHeaders: achado da task 313 (adendo da ADR 0065) — o traefix manda o resumo de uma
// requisição sem router (ex.: /favicon.ico do Chrome) ou de h3 sem http3HeaderOrder sem `fieldNames`, `fields` nem
// `ja4h`; isso é cabeçalho desconhecido, não "sem User-Agent": a conexão segue pela última requisição com os
// cabeçalhos e, sem nenhuma, fica sem visão HTTP (nunca ua_missing).
func TestTraefixRequestWithoutHeaders(t *testing.T) {
	bare := map[string]any{"path": "/favicon.ico", "status": 404}
	t.Run("after a request with headers", func(t *testing.T) {
		f := newFixture(t)
		id := "01JC0X3K8V2T7Q9F4M6P1R5T60"
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.60", 50060, chromeConn(nil), chromeRequest()))
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.60", 50060, nil, bare))
		v := f.verdictOf(id)
		if slices.Contains(signalIDList(v.Signals), "ua_missing") || !v.View.HTTP {
			t.Fatalf("requisição sem cabeçalhos virou ua_missing: %+v", v)
		}
	})
	t.Run("only requests without headers", func(t *testing.T) {
		f := newFixture(t)
		id := "01JC0X3K8V2T7Q9F4M6P1R5T61"
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.61", 50061, chromeConn(nil), bare))
		v := f.verdictOf(id)
		if slices.Contains(signalIDList(v.Signals), "ua_missing") || v.View.HTTP {
			t.Fatalf("sem cabeçalhos conhecidos: %+v", v)
		}
	})
}

// TestIngestClipsLongTexts: critério 1 da task 332 (ADR 0073 item 6) — nos dois esquemas, cada texto de 64 KiB é
// cortado no teto (não recusa o registro), na fronteira de UTF-8, e conta uma vez em
// bot_ingest_clipped_total{field}; JA4H longo vira ausente e nome de campo permitido longo sai com o valor.
func TestIngestClipsLongTexts(t *testing.T) {
	const id = "01JC0X3K8V2T7Q9F4M6P1R5T40"
	big := func(c string) string { return strings.Repeat(c, 64<<10) } // o lote inteiro cabe nos 4 MiB
	// "é" tem 2 bytes: o corte de 32 bytes em "a" + "é"... cai no meio de uma runa e recua um byte.
	method := "a" + strings.Repeat("é", 32<<10)
	f := newFixture(t)
	conn := chromeConn(nil)
	conn["entryPoint"], conn["proto"] = big("e"), "h2"
	tl := conn["tls"].(map[string]any)
	tl["sni"], tl["alpn"], tl["version"], tl["cipher"] = big("s"), big("p"), big("v"), big("c")
	offered := []string{big("o")}
	for range 20 {
		offered = append(offered, "h2")
	}
	tl["alpnOffered"] = offered
	names := []string{big("n")}
	for i := range 200 {
		names = append(names, "x-"+strconv.Itoa(i))
	}
	req := map[string]any{
		"method": method, "authority": big("w"), "httpVersion": big("h"), "fieldNames": names,
		"cookieNames": []string{big("k"), "sid"}, "ja4h": big("j"), "router": big("r"), "service": big("v"),
		"fields": []map[string]string{
			{"name": "user-agent", "value": big("u")},
			{"name": "sec-fetch-" + big("x"), "value": "1"},
			{"name": "accept", "value": "*/*"},
		},
	}
	if c, got := f.postIngest(traefixBatchJSON(t, id, "198.51.100.80", 50020, conn, req)); c != 202 || got["accepted"] != 2 {
		t.Fatalf("ingest: %d %v", c, got)
	}
	for _, field := range clippedFields {
		if n := f.metrics.Get(clippedMetric(field)); n != 1 {
			t.Errorf("clipped{%s} = %v, quer 1", field, n)
		}
	}
	fc, ok := f.srv.Index().Fork(id, f.clock.Now())
	if !ok || len(fc.Requests) != 1 {
		t.Fatalf("conexão: %v %+v", ok, fc)
	}
	r := fc.Requests[0]
	for _, x := range []struct {
		name string
		got  string
		max  int
	}{
		{"entry_point", fc.EntryPoint, maxRouteNameBytes},
		{"sni", fc.SNI, maxSiteBytes},
		{"alpn", fc.ALPN, maxALPNBytes},
		{"tls_version", fc.TLSVersion, maxTLSTextBytes},
		{"cipher", fc.Cipher, maxTLSTextBytes},
		{"method", r.Method, maxMethodBytes - 1},
		{"authority", r.Authority, maxSiteBytes},
		{"http_version", r.HTTPVersion, maxHTTPVersionBytes},
		{"router", r.Router, maxRouteNameBytes},
		{"service", r.Service, maxRouteNameBytes},
		{"field_names[0]", r.FieldNames[0], maxListNameBytes},
		{"cookie_names[0]", r.CookieNames[0], maxListNameBytes},
		{"user-agent", r.Fields["user-agent"], maxFieldValue},
	} {
		if len(x.got) != x.max || !utf8.ValidString(x.got) {
			t.Errorf("%s: %d bytes, quer %d", x.name, len(x.got), x.max)
		}
	}
	if len(fc.ALPNOffered) != maxALPNItems || len(r.FieldNames) != maxFieldNames || len(r.CookieNames) != 2 {
		t.Errorf("listas: alpn %d, field_names %d, cookie_names %d", len(fc.ALPNOffered), len(r.FieldNames), len(r.CookieNames))
	}
	if r.JA4H != "" || len(r.Fields) != 2 || r.Fields["accept"] != "*/*" {
		t.Errorf("ja4h %q, fields %v", clip(r.JA4H, 16), len(r.Fields))
	}

	// formato anterior: os mesmos cortes; valor de 513 bytes era recusado e agora é cortado
	g := newFixture(t)
	rec := map[string]any{
		"type": "request", "fs_conn_id": testForkConnID, "ts": "2026-11-16T12:00:00Z", "method": big("m"),
		"router": big("r"), "field_names": []string{big("n")}, "cookie_names": []string{big("k")},
		"fields": map[string]string{"user-agent": strings.Repeat("u", maxFieldValue+1), "sec-fetch-" + big("x"): "1"},
	}
	body, _ := json.Marshal(map[string]any{"records": []any{rec}})
	if c, got := g.postIngest(string(body)); c != 202 || got["accepted"] != 1 || got["rejected"] != 0 {
		t.Fatalf("formato anterior: %d %v", c, got)
	}
	for _, field := range []string{clipMethod, clipRouter, clipFieldNames, clipCookieNames, clipFieldName, clipFieldValue} {
		if n := g.metrics.Get(clippedMetric(field)); n != 1 {
			t.Errorf("formato anterior: clipped{%s} = %v", field, n)
		}
	}
	fc, _ = g.srv.Index().Fork(testForkConnID, g.clock.Now())
	if r := fc.Requests[0]; len(r.Method) != maxMethodBytes || len(r.Fields["user-agent"]) != maxFieldValue || len(r.Fields) != 1 {
		t.Errorf("formato anterior: método %d, UA %d, campos %d", len(r.Method), len(r.Fields["user-agent"]), len(r.Fields))
	}
}

// TestInternerKeepsNoLongIngestText: critério 1 da task 332 — depois de N registros com um texto único de 1 MiB
// (método, router, field_names[0], cookie_names[0] ou nome Sec-Fetch-), o interner guarda menos de N × 256 bytes
// de texto (antes, os N MiB ficavam nele depois de a conexão sair do índice). Textos acima de 1 KiB não são
// compartilhados.
func TestInternerKeepsNoLongIngestText(t *testing.T) {
	saved := shared
	t.Cleanup(func() { shared = saved })
	const n = 64
	for _, tc := range []struct {
		name string
		set  func(r map[string]any, long string)
	}{
		{"method", func(r map[string]any, long string) { r["method"] = long }},
		{"router", func(r map[string]any, long string) { r["router"] = long }},
		{"field_names", func(r map[string]any, long string) { r["field_names"] = []string{long, "accept"} }},
		{"cookie_names", func(r map[string]any, long string) { r["cookie_names"] = []string{long} }},
		{"sec_fetch_name", func(r map[string]any, long string) { r["fields"] = map[string]string{"sec-fetch-" + long: "1"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared = &interner{max: maxInterned}
			ix := NewIndex(time.Minute, 1, 0, nil) // uma conexão: cada registro novo despeja a anterior
			now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			for i := range n {
				r := map[string]any{
					"type": "request", "fs_conn_id": fmt.Sprintf("01JC0X3K8V2T7Q9F4M6P1R%04d", i), "ts": "2026-11-16T12:00:00Z",
					"method": "GET",
				}
				tc.set(r, fmt.Sprintf("%04d", i)+strings.Repeat("z", 1<<20))
				raw, _ := json.Marshal(r)
				p, err := parseRecord(raw)
				if err != nil {
					t.Fatal(err)
				}
				ix.UpdateFork(p.r.FsConnID, now, p.apply)
			}
			if got := internerTextBytes(shared); got >= n*256 {
				t.Errorf("interner com %d bytes de texto depois de %d registros (teto %d)", got, n, n*256)
			}
		})
	}
	shared = &interner{max: maxInterned}
	long := strings.Repeat("q", maxSharedText+1)
	var c int64
	if a, b := shared.str(long, &c), shared.str(long, &c); unsafe.StringData(a) == unsafe.StringData(b) || c != 2*strBytes(len(long)) {
		t.Errorf("texto acima de 1 KiB compartilhado (custo %d)", c)
	}
	if got := internerTextBytes(shared); got != 0 {
		t.Errorf("interner guardou %d bytes do texto grande", got)
	}
}

// internerTextBytes soma os textos que o interner segura (textos, chaves de listas e de mapas e os do resumo).
func internerTextBytes(in *interner) int {
	in.mu.Lock()
	defer in.mu.Unlock()
	total := 0
	for k := range in.strs {
		total += len(k)
	}
	for k := range in.lists {
		total += len(k)
	}
	for k := range in.maps {
		total += len(k)
	}
	for k := range in.reqs {
		total += k.textBytes()
	}
	return total
}
