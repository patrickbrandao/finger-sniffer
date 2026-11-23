package bot

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/akamai"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/h2passive"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// goldenBytes lê um arquivo de testdata/fingerprints (pânico se faltar: é dado fixo do pacote).
func goldenBytes(name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", "fingerprints", name))
	if err != nil {
		panic(err)
	}
	return b
}

type fingerprintGolden struct {
	TLS map[string]struct {
		JA3    string `json:"ja3"`
		JA3MD5 string `json:"ja3_md5"`
		JA4    string `json:"ja4"`
		JA4R   string `json:"ja4_r"`
		JA4O   string `json:"ja4_o"`
	} `json:"tls"`
	H2 map[string]struct {
		Akamai string `json:"akamai"`
	} `json:"h2"`
}

func loadFingerprintGolden(t *testing.T) fingerprintGolden {
	t.Helper()
	var g fingerprintGolden
	if err := json.Unmarshal(goldenBytes("golden.json"), &g); err != nil {
		t.Fatal(err)
	}
	if len(g.TLS) == 0 || len(g.H2) == 0 {
		t.Fatal("golden vazio")
	}
	return g
}

// webTLS calcula o que o web do espelho publica para os mesmos bytes (internal/web/conn.go, publishClientHello).
func webTLS(t *testing.T, raw []byte) *tlsparse.Info {
	t.Helper()
	ch, err := tlsparse.Parse(raw)
	if err != nil {
		t.Fatalf("web: %v", err)
	}
	info := tlsparse.NewInfo(ch, raw, tlsparse.DefaultInlineMax)
	ja3.Fill(info, ch)
	ja4.Fill(info, ch, ja4.TCP)
	return info
}

// webAkamai calcula o Akamai como o web (internal/web/h2_events.go): parser do sentido de entrada com o prefácio.
func webAkamai(prefix []byte) string {
	in := h2passive.Parse(append([]byte(h2passive.Preface), prefix...), h2passive.Options{Dir: h2passive.DirIn})
	return akamai.FromInfo(in)
}

// TestIngestFingerprintsGolden: critério 1 da task 277 — do ClientHello e do prefixo h2 crus do registro, o ingest
// calcula JA3/JA3N/JA4/JA4_r/JA4_o e o Akamai iguais aos goldens (FoxIO/tshark) e aos do web para os mesmos bytes.
func TestIngestFingerprintsGolden(t *testing.T) {
	g := loadFingerprintGolden(t)
	for name, want := range g.TLS {
		t.Run("tls/"+name, func(t *testing.T) {
			raw := goldenBytes("tls/" + name + ".bin")
			got := analyzeClientHello(raw, false)
			if got.ParseError {
				t.Fatal("parse_error num ClientHello válido")
			}
			if got.JA3 != want.JA3 || got.JA3MD5 != want.JA3MD5 || got.JA4 != want.JA4 || got.JA4R != want.JA4R ||
				got.JA4O != want.JA4O {
				t.Errorf("golden:\n got %+v\nwant %+v", got, want)
			}
			web := webTLS(t, raw)
			if got.JA3 != web.JA3 || got.JA3MD5 != web.JA3MD5 || got.JA3N != web.JA3N || got.JA3NMD5 != web.JA3NMD5 ||
				got.JA4 != web.JA4 || got.JA4R != web.JA4R || got.JA4O != web.JA4O || got.JA4Stable != web.JA4Stable ||
				got.JA4Stable == "" || !slices.Equal(got.ALPN, web.ALPN) {
				t.Errorf("diferente do web:\n bot %+v\n web ja3=%s ja3n=%s ja4=%s ja4_o=%s alpn=%v", got, web.JA3, web.JA3N,
					web.JA4, web.JA4O, web.ALPN)
			}
			if got.JA3N == "" || got.JA3NMD5 == "" {
				t.Error("ja3n vazio")
			}
		})
	}
	for name, want := range g.H2 {
		t.Run("h2/"+name, func(t *testing.T) {
			raw := goldenBytes("h2/" + name + ".prefix")
			got := analyzeH2Prefix(raw, false)
			if got.ParseError || !got.HeadersSeen {
				t.Fatalf("visão h2: %+v", got)
			}
			if got.Akamai != want.Akamai || got.Akamai != webAkamai(raw) {
				t.Errorf("akamai: bot %q golden %q web %q", got.Akamai, want.Akamai, webAkamai(raw))
			}
			// SETTINGS e WINDOW_UPDATE na mesma forma do primeiro campo do Akamai.
			parts := strings.Split(got.Akamai, "|")
			var settings []string
			for _, s := range got.Settings {
				settings = append(settings, itoa(s[0])+":"+itoa(s[1]))
			}
			if strings.Join(settings, ";") != parts[0] {
				t.Errorf("settings %v ≠ akamai %q", got.Settings, parts[0])
			}
			if got.WindowUpdate == nil || itoa(*got.WindowUpdate) != parts[1] {
				t.Errorf("window_update %v ≠ akamai %q", got.WindowUpdate, parts[1])
			}
			if order := pseudoLetters(got.PseudoOrder); order != parts[3] {
				t.Errorf("pseudo_order %v (%s) ≠ akamai %q", got.PseudoOrder, order, parts[3])
			}
		})
	}
}

func itoa(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

// pseudoLetters resume a ordem das pseudo-headers como no Akamai (`:method` → m, ...).
func pseudoLetters(order []string) string {
	l := make([]string, 0, len(order))
	for _, p := range order {
		l = append(l, p[1:2])
	}
	return strings.Join(l, ",")
}

// TestIngestFingerprintParseErrors: critério 2 — bytes malformados ou cortados viram parse_error da parte, sem
// fingerprint, e o lote segue aceito (contado em bot_ingest_parse_errors_total{part}).
func TestIngestFingerprintParseErrors(t *testing.T) {
	chrome := goldenBytes("tls/chrome.bin")
	prefix := goldenBytes("h2/chrome.prefix")
	for name, raw := range map[string][]byte{
		"vazio": {}, "lixo": []byte("GET / HTTP/1.1\r\n"), "cortado": chrome[:len(chrome)/2],
		"registro alerta": {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
	} {
		if got := analyzeClientHello(raw, false); !got.ParseError || got.JA4 != "" || got.JA3 != "" {
			t.Errorf("client_hello %s: %+v", name, got)
		}
	}
	if got := analyzeClientHello(chrome, true); !got.ParseError || got.JA4 != "" {
		t.Errorf("client_hello_truncated: %+v", got)
	}
	for name, raw := range map[string][]byte{
		"vazio": {}, "curto": prefix[:5], "com prefácio": append([]byte(h2passive.Preface), prefix...),
		"HEADERS primeiro": {0, 0, 1, 0x1, 0x5, 0, 0, 0, 1, 0x82},
	} {
		if got := analyzeH2Prefix(raw, false); !got.ParseError || got.Akamai != "" {
			t.Errorf("h2_prefix %s: %+v", name, got)
		}
	}
	if got := analyzeH2Prefix(prefix, true); !got.ParseError {
		t.Errorf("h2_prefix_truncated: %+v", got)
	}
	// Bloco HPACK com índice inválido: o parser para com erro.
	bad := slices.Clone(prefix[:9+int(prefix[2])])
	bad = append(bad, 0, 0, 1, 0x1, 0x5, 0, 0, 0, 1, 0xff)
	if got := analyzeH2Prefix(bad, false); !got.ParseError {
		t.Errorf("hpack inválido: %+v", got)
	}

	// Pelo ingest: os dois malformados no mesmo lote, registro aceito, uma contagem por parte.
	f := newFixture(t)
	body := batchWith(base64.StdEncoding.EncodeToString([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}),
		base64.StdEncoding.EncodeToString([]byte(h2passive.Preface)))
	c, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, body)
	if c != 202 || string(b) != `{"accepted":2,"rejected":0}`+"\n" {
		t.Fatalf("lote: %d %s", c, b)
	}
	fc, ok := f.srv.Index().Fork(testForkConnID, f.clock.Now())
	if !ok || fc.TLS == nil || !fc.TLS.ParseError || fc.H2 == nil || !fc.H2.ParseError || !fc.ParseError() {
		t.Fatalf("visão: %+v", fc)
	}
	for _, part := range []string{PartClientHello, PartH2Prefix} {
		if n := f.metrics.Get(metricIngestParseErrors + `{part="` + part + `"}`); n != 1 {
			t.Errorf("bot_ingest_parse_errors_total{part=%q} = %v", part, n)
		}
	}
	f.putStore()
	_, _, b = f.do(f.internal, "GET", "/bot/v1/auth", "", forkHeadersFor(), "")
	var v Verdict
	_ = json.Unmarshal(b, &v)
	if !v.View.ParseError || v.View.TLS {
		t.Errorf("view: %+v", v.View)
	}
}

// FuzzParseRecord: critério 2 — o decodificador do registro (JSON, base64, ClientHello e prefixo h2) nunca entra
// em pânico, e bytes que decodificam nunca recusam o registro por si.
func FuzzParseRecord(f *testing.F) {
	f.Add(goldenBytes("tls/chrome.bin"), goldenBytes("h2/chrome.prefix"), false)
	f.Add(goldenBytes("tls/go.bin"), goldenBytes("h2/go.prefix"), true)
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01}, []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}, false)
	f.Add([]byte{0x01, 0x00, 0x00, 0x02, 0x03, 0x03}, []byte{}, false)
	f.Fuzz(func(t *testing.T, ch, h2 []byte, truncated bool) {
		rec := map[string]any{
			"type": "connection", "fs_conn_id": testForkConnID, "ts": "2026-11-16T12:00:00Z",
			"client_hello": base64.StdEncoding.EncodeToString(ch), "client_hello_truncated": truncated,
			"h2_prefix": base64.StdEncoding.EncodeToString(h2), "h2_prefix_truncated": truncated,
		}
		raw, _ := json.Marshal(rec)
		p, err := parseRecord(raw)
		if err != nil {
			t.Fatalf("registro recusado por bytes analisáveis: %v", err)
		}
		if p.tls == nil || p.h2 == nil {
			t.Fatal("visão ausente")
		}
		if p.tls.ParseError && p.tls.JA4 != "" {
			t.Error("fingerprint com parse_error")
		}
		var c ForkConn
		p.apply(&c)
		_ = c.ParseError()
		// O JSON cru também não pode derrubar o decodificador.
		_, _ = parseRecord(ch)
	})
}
