package bot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/rules"
)

// Goldens de veredito ponta a ponta (task 282): um lote TraefikIngestBatch de exemplo (registro de conexão com o
// ClientHello cru e o prefixo h2, e o resumo da requisição) e a StoreConnection de exemplo da mesma conexão (visão
// IP/TCP do espelho) dão o veredito esperado pela consulta e pelo forwardAuth. As classes e os sinais são os da
// tabela da ADR 0057 item 1 (rules v1.6, ja4db desligada, IP residencial, sem comportamento).
//
// Os arquivos em testdata/verdicts são regravados com FS_BOT_UPDATE_GOLDEN=1 (ADR 0049 item 6: mudança de regra
// regrava os goldens no mesmo PR); a tabela abaixo é a referência que não muda com eles.

const goldenVerdictDir = "testdata/verdicts"

// verdictCase descreve um cliente: os bytes do fork, a requisição e a visão TCP do store.
type verdictCase struct {
	name        string
	ua          string
	tls         string // testdata/fingerprints/tls/<arquivo>
	h2          string // testdata/fingerprints/h2/<arquivo> ("" = h1)
	ja4h        string
	acceptLang  bool
	fieldNames  []string
	ja4t        string
	osGuess     string
	wantClass   string
	wantScore   int
	wantSignals []string
}

const (
	uaChrome    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
	uaHeadless  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36"
	uaFirefox   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0"
	uaGooglebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	ja4tChrome  = "65535_2-1-3-1-1-8-4-0-0_1432_6"
	ja4tMac     = "65535_2-1-3-1-1-8-4-0-0_1430_6"
	// ja4tFull é o SYN do Mac sem o grampo de MSS do caminho até o finger-01 (MSS 1460): a base mediu 1432/1430,
	// e na v1.2 o known_client compara sem o MSS (ADR 0058 item 4)
	ja4tFull = "65535_2-1-3-1-1-8-4-0-0_1460_6"
)

var chromeFields = []string{
	"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority",
}

var firefoxFields = []string{
	"user-agent", "accept", "accept-language", "accept-encoding", "upgrade-insecure-requests", "sec-fetch-dest",
	"sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "priority",
}

// verdictCases são os 7 clientes da ADR 0057 item 1 (critério da task 282). Os JA4H trazem as partes a e b medidas
// na base própria (known_clients.json); python-requests usa o ClientHello do OpenSSL 3 (a pilha dele, sem ALPN).
var verdictCases = []verdictCase{
	{
		name: "curl", ua: "curl/8.7.1", tls: "curl-macos.bin", h2: "curl-libressl.prefix",
		ja4h: "ge20nn020000_5594a17e7e7e_000000000000_000000000000", fieldNames: []string{"user-agent", "accept"},
		ja4t: ja4tMac, osGuess: "Mac OS X", wantClass: ClassBot, wantScore: 70,
		wantSignals: []string{"ja4h_library", "library_client"},
	},
	{
		name: "go", ua: "Go-http-client/2.0", tls: "go.bin", h2: "go.prefix",
		ja4h: "ge20nn020000_b89ce445e0b3_000000000000_000000000000", fieldNames: []string{"user-agent", "accept-encoding"},
		ja4t: ja4tChrome, wantClass: ClassBot, wantScore: 70, wantSignals: []string{"ja4h_library", "library_client"},
	},
	{
		name: "python_requests", ua: "python-requests/2.32.3", tls: "openssl3.bin",
		ja4h:       "ge11nn050000_b223a0ebb0b5_000000000000_000000000000",
		fieldNames: []string{"host", "user-agent", "accept-encoding", "accept", "connection"}, ja4t: ja4tMac,
		osGuess: "Mac OS X", wantClass: ClassBot, wantScore: 70, wantSignals: []string{"ja4h_library", "library_client"},
	},
	{
		name: "chrome", ua: uaChrome, tls: "chrome.bin", h2: "chrome.prefix", acceptLang: true, fieldNames: chromeFields,
		ja4h: "ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000", ja4t: ja4tFull, osGuess: "Mac OS X",
		wantClass: ClassHuman, wantScore: 0, wantSignals: []string{"known_client"},
	},
	{
		name: "firefox", ua: uaFirefox, tls: "firefox.bin", h2: "firefox.prefix", acceptLang: true, fieldNames: firefoxFields,
		ja4h: "ge20nn10ptbr_d353d425b0bb_000000000000_000000000000", ja4t: ja4tFull, osGuess: "Mac OS X",
		wantClass: ClassHuman, wantScore: 0, wantSignals: []string{"known_client"},
	},
	{
		name: "chrome_headless", ua: uaHeadless, tls: "chrome.bin", h2: "chrome.prefix", acceptLang: true,
		fieldNames: chromeFields, ja4h: "ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000", ja4t: ja4tChrome,
		wantClass: ClassBot, wantScore: 70, wantSignals: []string{"ua_automation"},
	},
	{
		// Googlebot falso: TLS e h2 do curl, IP residencial (fora da lista do Google)
		name: "googlebot_fake", ua: uaGooglebot, tls: "curl-macos.bin", h2: "curl-libressl.prefix",
		ja4h: "ge20nn020000_5594a17e7e7e_000000000000_000000000000", fieldNames: []string{"user-agent", "accept"},
		ja4t: ja4tMac, wantClass: ClassBot, wantScore: 80, wantSignals: []string{"ja4h_library", "ua_claims_crawler"},
	},
}

// verdictGolden é o arquivo de testdata/verdicts.
type verdictGolden struct {
	Client          string          `json:"client"`
	Batch           json.RawMessage `json:"batch"`
	StoreConnection json.RawMessage `json:"store_connection"`
	Verdict         goldenResult    `json:"verdict"`
}

type goldenResult struct {
	Class        string   `json:"class"`
	Score        int      `json:"score"`
	Signals      []Signal `json:"signals"`
	RulesVersion string   `json:"rules_version"`
}

// goldenIDs são os ids da conexão do caso i (fs_conn_id do fork, conn_id do store) e a porta de origem.
func goldenIDs(i int) (fsConnID, connID string, port int) {
	return fmt.Sprintf("01JC0X3K8V2T7Q9F4M6P1R5S%02d", 10+i), fmt.Sprintf("01JC0X3K8V2T7Q9N4M6P1R5S%02d", 10+i), 40000 + i
}

const goldenSrcIP = "198.51.100.23"

// build monta o lote e a StoreConnection do caso.
func (c verdictCase) build(t testing.TB, i int) (batch, store []byte) {
	t.Helper()
	fsID, connID, port := goldenIDs(i)
	proto, version, alpn := "h1", "1.1", []string{}
	conn := map[string]any{
		"type": "connection", "fs_conn_id": fsID, "ts": "2026-11-16T12:00:00.010000000Z",
		"src": map[string]any{"ip": goldenSrcIP, "port": port}, "dst": map[string]any{"ip": "10.249.0.2", "port": 443},
		"entry_point": "websecure", "sni": "www.example.com", "tls_version": "1.3", "cipher": "TLS_AES_128_GCM_SHA256",
		"client_hello": base64.StdEncoding.EncodeToString(goldenBytes("tls/" + c.tls)), "client_hello_truncated": false,
	}
	if c.h2 != "" {
		proto, version, alpn = "h2", "2.0", []string{"h2", "http/1.1"}
		conn["h2_prefix"] = base64.StdEncoding.EncodeToString(goldenBytes("h2/" + c.h2))
		conn["h2_prefix_truncated"] = false
		conn["alpn"] = "h2"
	} else {
		conn["alpn"] = nil
	}
	conn["alpn_offered"] = alpn
	fields := map[string]string{"user-agent": c.ua, "accept": "*/*"}
	if c.acceptLang {
		fields["accept-language"] = "pt-BR,pt;q=0.9"
	}
	req := map[string]any{
		"type": "request", "fs_conn_id": fsID, "ts": "2026-11-16T12:00:00.050000000Z", "proto": proto, "method": "GET",
		"authority": "www.example.com", "path": "/", "http_version": version, "field_names": c.fieldNames, "fields": fields,
		"cookie_names": []string{}, "ja4h": c.ja4h, "status": 200, "ended": "2026-11-16T12:00:00.060000000Z",
		"router": "site@docker", "service": "site@docker",
	}
	var err error
	if batch, err = json.Marshal(map[string]any{"sender": "v3.6.2-fs.1", "records": []any{conn, req}}); err != nil {
		t.Fatal(err)
	}
	tcp := map[string]any{
		"syn_mss": 1460, "mtu_implied": 1500, "mss_reduction": 0, "ja4t": c.ja4t, "p0f": nil, "os_guess": nil,
		"rtt_handshake_ms": 12.5,
	}
	if c.osGuess != "" {
		tcp["os_guess"] = c.osGuess
	}
	// a conexão vista pelo espelho na porta do traefik: só IP/TCP (o TLS termina no traefik)
	connection := map[string]any{
		"conn_id": connID, "probe_id": nil, "proto": "tcp", "l4": "tcp", "family": 4,
		"src": map[string]any{"ip": goldenSrcIP, "port": port}, "dst": map[string]any{"ip": "172.233.24.85", "port": 443},
		"started": "2026-11-16T12:00:00.000000000Z", "ended": nil,
		"ip":  map[string]any{"src_kind": "global", "ttl": 52, "ttl_initial": 64, "hops": 12, "df": true},
		"tcp": tcp,
	}
	payload, err := json.Marshal(map[string]any{"stage": "updated", "connection": connection})
	if err != nil {
		t.Fatal(err)
	}
	store = []byte(`{"schema_version":1,"service":"store","service_version":"v0.4.0","ts":"2026-11-16T12:00:00.020000000Z","payload":` +
		string(payload) + `}`)
	return batch, store
}

// loadVerdictGolden lê (ou regrava, com FS_BOT_UPDATE_GOLDEN=1) o golden do caso.
func loadVerdictGolden(t *testing.T, i int, c verdictCase, got *Verdict) verdictGolden {
	t.Helper()
	path := filepath.Join(goldenVerdictDir, c.name+".json")
	if os.Getenv("FS_BOT_UPDATE_GOLDEN") == "1" && got != nil {
		batch, store := c.build(t, i)
		g := verdictGolden{
			Client: c.name, Batch: batch, StoreConnection: store,
			Verdict: goldenResult{Class: got.Class, Score: got.Score, Signals: got.Signals, RulesVersion: got.RulesVersion},
		}
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(goldenVerdictDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (regrave com FS_BOT_UPDATE_GOLDEN=1)", err)
	}
	var g verdictGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func signalIDList(s []Signal) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.ID
	}
	return out
}

// TestVerdictGoldens: critério 1 da task 282 — os 7 clientes dão as classes e os sinais da ADR 0057 item 1 pela
// consulta (veredito da requisição na chegada do ingest) e pelo forwardAuth seguinte (com os cabeçalhos do
// visitante), e o forwardAuth com chave em modo block responde 403 só para `bot`.
func TestVerdictGoldens(t *testing.T) {
	for i, c := range verdictCases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			_, block := f.createKey(KeyOptions{Name: "b", Domains: []string{"*.example.com"}, Mode: ModeBlock, RatePerS: 1000, Burst: 1000})
			batch, store := c.build(t, i)
			if err := f.srv.feed.Handle(store); err != nil {
				t.Fatal(err)
			}
			if code, _, b := f.do(f.internal, "POST", "/bot/v1/ingest/traefik", "", nil, string(batch)); code != 202 ||
				!bytes.Contains(b, []byte(`"accepted":2`)) {
				t.Fatalf("ingest: %d %s", code, b)
			}
			fsID, connID, port := goldenIDs(i)
			code, _, b := f.do(f.internal, "GET", "/bot/v1/verdict/conn/"+fsID, "", nil, "")
			if code != 200 {
				t.Fatalf("consulta: %d %s", code, b)
			}
			var v Verdict
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			if v.Class != c.wantClass || v.Score != c.wantScore || !slices.Equal(signalIDList(v.Signals), c.wantSignals) {
				t.Fatalf("veredito %s %d %v, quer %s %d %v", v.Class, v.Score, signalIDList(v.Signals), c.wantClass, c.wantScore, c.wantSignals)
			}
			if !v.View.TCP || !v.View.TLS || !v.View.HTTP || v.Subject.ConnID == nil || *v.Subject.ConnID != connID {
				t.Errorf("visão ou casamento: %+v %+v", v.View, v.Subject)
			}
			if v.RulesVersion != rules.RulesVersion || v.ListsVersion == "" || v.ListsVersion == listsVersionNone {
				t.Errorf("versões %q %q", v.RulesVersion, v.ListsVersion)
			}
			g := loadVerdictGolden(t, i, c, &v)
			if g.Verdict.Class != v.Class || g.Verdict.Score != v.Score || !slices.Equal(g.Verdict.Signals, v.Signals) ||
				g.Verdict.RulesVersion != v.RulesVersion {
				t.Errorf("golden %+v, veredito %+v %d %+v", g.Verdict, v.Class, v.Score, v.Signals)
			}
			if wantBatch, wantStore := c.build(t, i); !bytes.Equal(compactJSON(t, g.Batch), compactJSON(t, wantBatch)) ||
				!bytes.Equal(compactJSON(t, g.StoreConnection), compactJSON(t, wantStore)) {
				t.Error("entradas do golden desatualizadas (regrave com FS_BOT_UPDATE_GOLDEN=1)")
			}

			// forwardAuth da requisição seguinte na mesma conexão: UA e Accept-Language dos cabeçalhos do
			// visitante, JA4H da última requisição que o ingest trouxe.
			hdr := map[string]string{
				"X-Fs-Src-Ip": goldenSrcIP, "X-Fs-Src-Port": strconv.Itoa(port), "X-Fs-Dst-Port": "443", "X-Fs-Conn-Id": fsID,
				"X-Fs-Proto": "h1", "X-Forwarded-Host": "www.example.com", "X-Forwarded-Uri": "/next?q=1",
				"X-Forwarded-Method": "GET", "User-Agent": c.ua,
			}
			if c.h2 != "" {
				hdr["X-Fs-Proto"] = "h2"
			}
			if c.acceptLang {
				hdr["Accept-Language"] = "pt-BR,pt;q=0.9"
			}
			code, h, b := f.do(f.internal, "GET", "/bot/v1/auth", "", hdr, "")
			if code != 200 || h.Get("X-Fs-Verdict") != c.wantClass || h.Get("X-Fs-Score") != strconv.Itoa(c.wantScore) {
				t.Fatalf("forwardAuth: %d %v %s", code, h, b)
			}
			if got := h.Get("X-Fs-Signals"); got != joinIDs(c.wantSignals) {
				t.Errorf("X-Fs-Signals %q", got)
			}
			// modo block: 403 mínimo só para bot (ADR 0074); os demais, 200 com o mesmo veredito
			code, h, b = f.do(f.internal, "GET", "/bot/v1/auth", block, hdr, "")
			if c.wantClass == ClassBot {
				checkMinimal403(t, "block", code, h, b)
				return
			}
			if code != 200 || h.Get("X-Fs-Verdict") != c.wantClass {
				t.Fatalf("block: %d %v %s", code, h, b)
			}
			var vb Verdict
			if err := json.Unmarshal(b, &vb); err != nil || vb.Class != c.wantClass {
				t.Fatalf("corpo do block: %s", b)
			}
		})
	}
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func compactJSON(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
