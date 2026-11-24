package e2e

// Simulador do traefix sem o finger-01 (task 359, spec 017 RF-08a). Este arquivo não tem a tag e2e: o
// TestF8SimOffline e os auxiliares puros do simulador (SYN tirado de pcap, X-Traefix-Alpn, registros
// traefix.fingerprint/v1) rodam no go test comum e no CI; os casos contra o finger-01 ficam em f8_bot_test.go e
// f8_traefix_test.go, com a tag.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/patrickbrandao/finger-sniffer/internal/bot"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4plus"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestF8SimOffline confere o traefix simulado sem o finger-01 (roda com -run TestF8SimOffline): o SYN tirado de um
// pcap golden dá o JA4T das referências da FoxIO, o X-Traefix-Alpn segue a codificação da spec 019 RF-05, e os
// registros traefix.fingerprint/v1 e os X-Traefix-* montados aqui, com o Chrome do lote de exemplo do traefix,
// entram no bot desta árvore (em processo) sem recusa nem divergência e dão a classe do golden do bot, na primeira
// requisição só pelos cabeçalhos e depois pelo ingest; o TraefikIngestBatch e os X-Fs-* seguem aceitos.
func TestF8SimOffline(t *testing.T) {
	t.Run("syn-from-pcap", func(t *testing.T) {
		for _, n := range []string{"curl-linux-v4", "curl-linux-v6", "chrome-macos"} {
			p, err := os.ReadFile("../golden/pcaps/" + n + ".pcap")
			if err != nil {
				t.Fatal(err)
			}
			line, err := os.ReadFile("../golden/pcaps/" + n + ".ja4.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			var ref struct {
				SrcPort int    `json:"src_port"`
				JA4T    string `json:"ja4t"`
			}
			first, _, _ := bytes.Cut(line, []byte("\n"))
			if err := json.Unmarshal(first, &ref); err != nil {
				t.Fatal(err)
			}
			syn := synFromPcap(p, ref.SrcPort)
			if syn == nil {
				t.Fatalf("%s: sem o SYN da porta %d", n, ref.SrcPort)
			}
			hl := 40
			if syn[0]>>4 == 4 {
				hl = int(syn[0]&0xf) * 4
			}
			if got, err := ja4plus.JA4T(syn[hl:]); err != nil || got != ref.JA4T {
				t.Errorf("%s: JA4T do SYN tirado do pcap %q (%v), FoxIO %q", n, got, err, ref.JA4T)
			}
		}
		if synFromPcap([]byte("curto"), 1) != nil {
			t.Error("pcap inválido deu SYN")
		}
	})

	t.Run("alpn-header", func(t *testing.T) {
		if got := alpnHeader([]string{"h2", "http/1.1", "a,b", "50%", "\x01é"}); got != "h2,http/1.1,a%2Cb,50%25,%01%C3%A9" {
			t.Errorf("alpnHeader = %q", got)
		}
	})

	t.Run("bot", func(t *testing.T) {
		testSimAgainstBot(t)
	})
}

// testSimAgainstBot passa os registros e cabeçalhos do simulador pelo bot desta árvore (banco temporário, porta
// pública em httptest, chave criada no banco).
func testSimAgainstBot(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/bot.db"
	db, err := bot.OpenDB(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m := service.NewMetrics()
	srv := bot.New(bot.Config{
		PublicPort: 9002, InternalPort: 9003, DBPath: path, MaxBytes: 2 << 30, FlushInterval: time.Second,
		AggRetention: bot.MaxAggRetention, ConnTTL: 10 * time.Minute, MaxConns: 1000, ViewWait: 20 * time.Millisecond, RateHigh: 120,
	}, bot.Deps{DB: db, Metrics: m, Version: "test"})
	_, secret, _, err := bot.CreateKey(ctx, db, bot.KeyOptions{Name: "e2e-sim", Domains: []string{vpsHost, f8Site}, Mode: bot.ModeObserve}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Keys().Reload(ctx); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler(false))
	t.Cleanup(hs.Close)
	// botDo usa botBase: aponta para o bot em processo só neste teste (os testes do e2e não rodam em paralelo)
	saved := botBase
	botBase = hs.URL + "/bot/v1"
	t.Cleanup(func() { botBase = saved })
	key := &botKey{id: "local", secret: secret}

	// o Chrome do lote de exemplo do traefix (h2-tcp.json), com o resultado conferido com a FoxIO pelo traefix
	b, err := os.ReadFile("../../internal/bot/testdata/ingest/h2-tcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var ex struct {
		Records []struct {
			TLS struct {
				ClientHello, JA4, JA4R, JA4O, JA3, JA3String, JA3N, JA3NString string
				ALPNOffered                                                    []string `json:"alpnOffered"`
			} `json:"tls"`
			HTTP2  struct{ Akamai, Prefix string } `json:"http2"`
			Fields []traefixField                  `json:"fields"`
			JA4H   string                          `json:"ja4h"`
		} `json:"records"`
	}
	if err := json.Unmarshal(b, &ex); err != nil {
		t.Fatal(err)
	}
	c, r := ex.Records[0], ex.Records[1]
	a := f8App{
		client: "chrome", hello: b64(t, c.TLS.ClientHello), h2Prefix: b64(t, c.HTTP2.Prefix), alpnOffered: c.TLS.ALPNOffered,
		proto: "h2", httpVersion: "HTTP/2.0", fields: map[string]string{}, ordered: r.Fields, ja4h: r.JA4H,
		ja4: c.TLS.JA4, ja4r: c.TLS.JA4R, ja4o: c.TLS.JA4O, ja3: c.TLS.JA3, ja3String: c.TLS.JA3String, ja3n: c.TLS.JA3N,
		ja3nString: c.TLS.JA3NString, akamai: c.HTTP2.Akamai,
	}
	for _, f := range r.Fields {
		a.names = append(a.names, f.Name)
		a.fields[f.Name] = f.Value
	}
	// a visão TCP do exemplo é de Windows (JA4T e TTL), e o UA dele é de macOS: aqui vai a de um Mac medido (o JA4T
	// do Chrome no macOS da base própria e TTL 52, de 64)
	const ja4tMac = "65535_2-1-3-1-1-8-4-0-0_1460_6"
	tcp := &f8TCP{ja4t: ja4tMac, ttl: 52, rttMicros: 1834}
	o := f8Origin{src: endpoint{IP: "198.51.100.42", Port: 6523}, dstIP: "192.0.2.10", started: time.Now()}
	id := ulid.Make().String()

	// primeira requisição só com os X-Traefix-*
	resp := botDo(t, http.MethodGet, "/auth", key, traefixAuthHeaders(id, o, a, f8Site, authOpts{ja4h: true, fp: true, tcp: tcp}), nil)
	v := decodeVerdict(t, "auth", resp)
	t.Logf("primeira requisição: %d %s", resp.status, v.String())
	if resp.status != http.StatusOK || v.Class != "human" || !v.has("known_client") || !v.View.TCP || !v.View.TLS {
		t.Errorf("primeira requisição pelos X-Traefix-*: %d %s; esperado human com known_client e as visões TCP e TLS", resp.status, v.String())
	}
	checkVerdictHeaders(t, "auth", resp, v)
	checkMirror(t, a, v)
	// o lote v1 com rawBytes e a visão TCP; depois a consulta pela origem
	ingestV1(t, key, traefixConnV1(id, o, a, v1Opts{raw: true, tcp: tcp, sni: f8Site}), traefixRequestV1(id, o, a, 0, f8Site))
	v = decodeVerdict(t, "verdict", verdictBySource(t, key, o, f8Site))
	t.Logf("pelo ingest: %s", v.String())
	if v.Class != "human" || !v.has("known_client") || !v.View.TCP || v.View.ParseError || deref(v.Fingerprints.JA4T) != tcp.ja4t {
		t.Errorf("pelo ingest: %s ja4t %q; esperado human com known_client e a visão TCP do traefix", v.String(), deref(v.Fingerprints.JA4T))
	}
	checkMirror(t, a, v)
	// só as prontas
	o2 := o
	o2.src.Port++
	id2 := ulid.Make().String()
	ingestV1(t, key, traefixConnV1(id2, o2, a, v1Opts{tcp: tcp, sni: f8Site}), traefixRequestV1(id2, o2, a, 0, f8Site))
	v = decodeVerdict(t, "verdict", verdictBySource(t, key, o2, f8Site))
	if v.Class != "human" || v.View.ParseError {
		t.Errorf("só prontas: %s", v.String())
	}
	checkMirror(t, a, v)
	// TTL de Windows no UA de macOS
	o3 := o
	o3.src.Port += 2
	id3 := ulid.Make().String()
	ingestV1(t, key, traefixConnV1(id3, o3, a, v1Opts{raw: true, tcp: &f8TCP{ja4t: tcp.ja4t, ttl: 117, rttMicros: -1}, sni: f8Site}),
		traefixRequestV1(id3, o3, a, 0, f8Site))
	if v = decodeVerdict(t, "verdict", verdictBySource(t, key, o3, f8Site)); !v.has("ua_os_tcp_mismatch") {
		t.Errorf("TTL 117 com UA de macOS: %s; esperado ua_os_tcp_mismatch", v.String())
	}
	// compatibilidade: X-Fs-* e TraefikIngestBatch
	o4 := o
	o4.src.Port += 3
	id4 := ulid.Make().String()
	lc := legacyConn(id4, o4, a)
	lc["sni"] = f8Site
	ingestLegacy(t, key, lc)
	lh := legacyAuthHeaders(id4, o4, a, true)
	lh["X-Forwarded-Host"] = f8Site
	resp = botDo(t, http.MethodGet, "/auth", key, lh, nil)
	v = decodeVerdict(t, "auth X-Fs-*", resp)
	if resp.status != http.StatusOK || v.Class != "human" {
		t.Errorf("X-Fs-*: %d %s", resp.status, v.String())
	}
	checkVerdictHeaders(t, "auth X-Fs-*", resp, v)
	checkNoVerdict(t, "auth sem chave", botDo(t, http.MethodGet, "/auth", nil, lh, nil), http.StatusUnauthorized, "invalid_key")

	snap := m.Snapshot()
	for k, n := range snap {
		if n != 0 && (strings.HasPrefix(k, "bot_ingest_fingerprint_mismatch_total") || strings.HasPrefix(k, "bot_ingest_parse_errors_total") ||
			strings.HasPrefix(k, "bot_ingest_ignored_total")) {
			t.Errorf("%s = %v, esperado 0", k, n)
		}
	}
	if n := snap[`bot_auth_fingerprint_total{kind="tls",source="header"}`]; n < 1 {
		t.Errorf(`bot_auth_fingerprint_total{kind="tls",source="header"} = %v, esperado ≥ 1`, n)
	}
}

// synFromPcap devolve o primeiro SYN (sem ACK) da porta de origem dada, desde o cabeçalho IP (a forma do tcp.syn do
// traefix), num pcap Ethernet do store; nil se não houver.
func synFromPcap(p []byte, srcPort int) []byte {
	if len(p) < 24 {
		return nil
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(p) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.BigEndian
	default:
		return nil
	}
	const linkEthernet = 1
	if bo.Uint32(p[20:24]) != linkEthernet {
		return nil
	}
	be := binary.BigEndian
	for off := 24; off+16 <= len(p); {
		n := int(bo.Uint32(p[off+8:]))
		off += 16
		if n < 0 || off+n > len(p) {
			return nil
		}
		pkt := p[off : off+n]
		off += n
		if len(pkt) < 14 {
			continue
		}
		et, l3 := be.Uint16(pkt[12:]), pkt[14:]
		if et == 0x8100 && len(pkt) >= 18 {
			et, l3 = be.Uint16(pkt[16:]), pkt[18:]
		}
		var seg []byte
		switch et {
		case 0x0800:
			if len(l3) < 20 || l3[9] != 6 {
				continue
			}
			if tot := int(be.Uint16(l3[2:])); tot <= len(l3) {
				l3 = l3[:tot]
			}
			if ihl := int(l3[0]&0xf) * 4; len(l3) >= ihl+20 {
				seg = l3[ihl:]
			}
		case 0x86dd:
			if len(l3) < 40 || l3[6] != 6 {
				continue
			}
			if pl := int(be.Uint16(l3[4:])); 40+pl <= len(l3) {
				l3 = l3[:40+pl]
			}
			seg = l3[40:]
		}
		if len(seg) < 20 {
			continue
		}
		const flagSYN, flagACK = 0x02, 0x10
		if int(be.Uint16(seg)) == srcPort && seg[13]&flagSYN != 0 && seg[13]&flagACK == 0 {
			return slices.Clone(l3)
		}
	}
	return nil
}

// alpnHeader codifica o ALPN oferecido como o X-Traefix-Alpn: na ordem do cliente, por vírgula, %XX fora do ASCII
// visível e para `,` e `%` (spec 019 RF-05).
func alpnHeader(vs []string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		var b strings.Builder
		for _, c := range []byte(v) {
			if c <= 0x20 || c >= 0x7f || c == ',' || c == '%' {
				_, _ = fmt.Fprintf(&b, "%%%02X", c)
				continue
			}
			b.WriteByte(c)
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, ",")
}

// vpsHost é o nome do servidor (certificado B da 9000 e das portas web; ADR 0038).
var vpsHost = env("FS_E2E_HOST", "finger-01.badblock.net.br")

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// f8Site é o Origin dos clientes de linha de comando.
const f8Site = "fs-e2e.example"

// botBase é a API pública do bot (spec 020 RF-01).
var botBase = env("FS_E2E_BOT", "https://"+vpsHost+":9002/bot/v1")

type botKey struct {
	id     string
	secret string // nunca em log
}

// traefixField é um item de fields do registro request do traefix.fingerprint/v1.
type traefixField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// f8App é a visão de aplicação de um cliente como o traefix a mandaria (spec 019 RF-05 e RF-06).
type f8App struct {
	client      string
	pub         string // IP público (IPv4) do gerador, o das conexões ao traefik-app
	hello       []byte
	h2Prefix    []byte // nil no HTTP/1.1
	alpnOffered []string
	proto       string // h1 | h2
	httpVersion string // como no registro do espelho (HTTP/1.1, HTTP/2.0)
	names       []string
	fields      map[string]string
	ordered     []traefixField // os campos permitidos na ordem recebida (fields do traefix.fingerprint/v1)
	ua          string
	ja4h        string
	// fingerprints do espelho: as prontas que o traefix manda (conferidas com a FoxIO, ADR 0063)
	ja4, ja4r, ja4o  string
	ja3, ja3String   string
	ja3n, ja3nString string
	akamai           string // "" no h1
	tcp              *f8TCP // visão TCP da conexão do probe (a do caso "site externo")
}

// f8TCP é a visão TCP que o traefix com `fingerprint.tcp: true` manda (spec 019 RF-06, ADR 0063 item 5): aqui ela
// sai do registro do store da mesma conexão (o mesmo SYN), e o SYN cru do pcap dela.
type f8TCP struct {
	ja4t      string
	p0f       string
	ttl       int
	rttMicros int64 // -1 sem medida
	syn       []byte
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

// f8Origin é a conexão ao traefik-app como o store a viu (a origem pública, depois do NAT).
type f8Origin struct {
	connID  string
	src     endpoint
	dstIP   string
	started time.Time
}

type endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// botDo chama a API do bot; k nil = sem Authorization.
func botDo(t *testing.T, method, path string, k *botKey, hdr map[string]string, body []byte) botResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, botBase+path, rd) //nolint:noctx // prazo no cliente
	if err != nil {
		t.Fatal(err)
	}
	if k != nil {
		req.Header.Set("Authorization", "Bearer "+k.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for n, v := range hdr {
		req.Header.Set(n, v)
	}
	resp, err := botHTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	b, _ := io.ReadAll(resp.Body)
	return botResp{status: resp.StatusCode, header: resp.Header, body: b}
}

type botResp struct {
	status int
	header http.Header
	body   []byte
}

// traefixAuthHeaders são os cabeçalhos que o traefix manda ao forwardAuth (spec 019 RF-04 e RF-05): os X-Traefix-*
// da conexão e da requisição, os X-Forwarded-* e os authRequestHeaders do visitante.
func traefixAuthHeaders(id string, o f8Origin, a f8App, site string, opt authOpts) map[string]string {
	h := map[string]string{
		"X-Forwarded-Method": "GET", "X-Forwarded-Host": site, "X-Forwarded-Uri": "/", "X-Forwarded-Proto": "https",
		"X-Traefix-Src-Ip": o.src.IP, "X-Traefix-Src-Port": strconv.Itoa(o.src.Port), "X-Traefix-Dst-Port": strconv.Itoa(traefikPort),
		"X-Traefix-Conn-Id": id, "X-Traefix-Proto": a.proto,
	}
	for n, v := range a.fields {
		for _, w := range visitorHeaders {
			if strings.EqualFold(n, w) {
				h[w] = v
			}
		}
	}
	if opt.ja4h {
		h["X-Traefix-Ja4h"] = a.ja4h
	}
	if opt.fp {
		h["X-Traefix-Ja4"] = a.ja4
		if a.ja3 != "" {
			h["X-Traefix-Ja3"] = a.ja3
		}
		if a.proto == "h2" && a.akamai != "" {
			h["X-Traefix-H2"] = a.akamai
		}
		if len(a.alpnOffered) > 0 {
			h["X-Traefix-Alpn"] = alpnHeader(a.alpnOffered)
		}
	}
	if opt.tcp != nil {
		h["X-Traefix-Ja4t"] = opt.tcp.ja4t
	}
	return h
}

// authOpts diz o que o traefix simulado manda ao forwardAuth além da origem.
type authOpts struct {
	ja4h bool   // X-Traefix-Ja4h (o traefix manda sempre em h1/h2; sem ele, o JA4H vem do ingest)
	fp   bool   // X-Traefix-Ja4, -Ja3, -H2 e -Alpn (o traefix manda sempre com TLS)
	tcp  *f8TCP // X-Traefix-Ja4t (com fingerprint.tcp)
}

func decodeVerdict(t *testing.T, what string, r botResp) botVerdict {
	t.Helper()
	var v botVerdict
	if err := json.Unmarshal(r.body, &v); err != nil {
		t.Fatalf("%s: %d %v %.300s", what, r.status, err, r.body)
	}
	return v
}

type botVerdict struct {
	Class   string      `json:"class"`
	Score   int         `json:"score"`
	Signals []botSignal `json:"signals"`
	View    struct {
		TCP        bool `json:"tcp"`
		TLS        bool `json:"tls"`
		HTTP       bool `json:"http"`
		H2         bool `json:"h2"`
		ParseError bool `json:"parse_error"`
	} `json:"view"`
	Fingerprints struct {
		JA4      *string `json:"ja4"`
		Akamai   *string `json:"akamai"`
		JA4H     *string `json:"ja4h"`
		JA4T     *string `json:"ja4t"`
		UAFamily *string `json:"ua_family"`
	} `json:"fingerprints"`
	RulesVersion string `json:"rules_version"`
	ListsVersion string `json:"lists_version"`
	Subject      struct {
		Kind     string    `json:"kind"`
		Site     *string   `json:"site"`
		Src      *endpoint `json:"src"`
		DstPort  *int      `json:"dst_port"`
		FsConnID *string   `json:"fs_conn_id"`
		ConnID   *string   `json:"conn_id"`
		ProbeID  *string   `json:"probe_id"`
	} `json:"subject"`
}

type botSignal struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

func (v *botVerdict) ids() []string {
	out := make([]string, 0, len(v.Signals))
	for _, s := range v.Signals {
		out = append(out, s.ID)
	}
	return out
}

func (v *botVerdict) has(id string) bool { return slices.Contains(v.ids(), id) }

func (v *botVerdict) String() string {
	var sig []string
	for _, s := range v.Signals {
		sig = append(sig, fmt.Sprintf("%s(%d: %s)", s.ID, s.Weight, s.Detail))
	}
	return fmt.Sprintf("%s score %d [%s] view tcp=%v tls=%v http=%v h2=%v", v.Class, v.Score, strings.Join(sig, ", "),
		v.View.TCP, v.View.TLS, v.View.HTTP, v.View.H2)
}

// checkVerdictHeaders confere os cabeçalhos do veredito nos dois conjuntos (X-Traefix-* e os X-Fs-* obsoletos, ADR
// 0063 item 1) contra o corpo.
func checkVerdictHeaders(t *testing.T, what string, r botResp, v botVerdict) {
	t.Helper()
	for _, p := range []string{"X-Traefix-", "X-Fs-"} {
		if got := r.header.Get(p + "Verdict"); got != v.Class {
			t.Errorf("%s: %sVerdict %q, corpo %s", what, p, got, v.Class)
		}
		if got := r.header.Get(p + "Score"); got != strconv.Itoa(v.Score) {
			t.Errorf("%s: %sScore %q, corpo %d", what, p, got, v.Score)
		}
		if got := r.header.Get(p + "Signals"); got != strings.Join(v.ids(), ",") {
			t.Errorf("%s: %sSignals %q, corpo %v", what, p, got, v.ids())
		}
	}
}

// checkMirror confere JA4 e Akamai do bot (calculados dos bytes do ingest, ou os prontos) contra os do espelho.
func checkMirror(t *testing.T, a f8App, v botVerdict) {
	t.Helper()
	if got := deref(v.Fingerprints.JA4); got != a.ja4 {
		t.Errorf("%s: ja4 do bot %q, espelho %q", a.client, got, a.ja4)
	}
	if a.akamai != "" {
		if got := deref(v.Fingerprints.Akamai); got != a.akamai {
			t.Errorf("%s: akamai do bot %q, espelho %q", a.client, got, a.akamai)
		}
	}
}

// ingestV1 manda o lote traefix.fingerprint/v1 ao bot e confere que todos os registros entraram.
func ingestV1(t *testing.T, k *botKey, records ...map[string]any) {
	t.Helper()
	postIngest(t, k, map[string]any{
		"schema": "traefix.fingerprint/v1", "sender": f8Sender, "entryPoint": "websecure", "sentAt": ts(time.Now()), "records": records,
	}, len(records))
}

// traefixConnV1 é o registro type=connection do traefix.fingerprint/v1 (spec 019 RF-06): as fingerprints prontas
// sempre (as do espelho, que o traefix calcula igual) e os bytes crus com rawBytes.
func traefixConnV1(id string, o f8Origin, a f8App, opt v1Opts) map[string]any {
	alpn := "http/1.1"
	if a.proto == "h2" {
		alpn = "h2"
	}
	tls := map[string]any{
		"sni": opt.sni, "alpnOffered": a.alpnOffered, "alpn": alpn, "version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256",
	}
	for k, v := range map[string]string{
		"ja4": a.ja4, "ja4r": a.ja4r, "ja4o": a.ja4o, "ja3": a.ja3, "ja3String": a.ja3String, "ja3n": a.ja3n, "ja3nString": a.ja3nString,
	} {
		// campos sem valor são omitidos (spec 019 RF-06)
		if v != "" {
			tls[k] = v
		}
	}
	if opt.raw {
		tls["clientHello"], tls["clientHelloTruncated"] = base64.StdEncoding.EncodeToString(a.hello), false
	}
	r := map[string]any{
		"type": "connection", "connId": id, "time": ts(o.started), "entryPoint": "websecure",
		"src": o.src, "dst": endpoint{IP: o.dstIP, Port: traefikPort}, "proto": a.proto, "tls": tls,
	}
	if a.proto == "h2" {
		h2 := map[string]any{}
		if a.akamai != "" {
			h2["akamai"] = a.akamai
		}
		if opt.raw && a.h2Prefix != nil {
			h2["prefix"], h2["prefixTruncated"] = base64.StdEncoding.EncodeToString(a.h2Prefix), false
		}
		r["http2"] = h2
	}
	if c := opt.tcp; c != nil {
		tcp := map[string]any{"ja4t": c.ja4t, "ttl": c.ttl}
		if c.p0f != "" {
			tcp["p0f"] = c.p0f
		}
		if c.rttMicros >= 0 {
			tcp["rttMicros"] = c.rttMicros
		}
		if opt.raw && c.syn != nil {
			tcp["syn"] = base64.StdEncoding.EncodeToString(c.syn)
		}
		r["tcp"] = tcp
	}
	return r
}

// v1Opts diz o que o traefix simulado manda no registro de conexão.
type v1Opts struct {
	raw bool   // rawBytes: ClientHello, prefixo h2 e SYN crus
	tcp *f8TCP // fingerprint.tcp: nil = sem visão TCP
	sni string
}

// traefixRequestV1 é o registro type=request do traefix.fingerprint/v1 (spec 019 RF-06): fields como lista na
// ordem recebida, só os da lista padrão do traefix.
func traefixRequestV1(id string, o f8Origin, a f8App, n int, site string) map[string]any {
	start := o.started.Add(time.Duration(50+n*10) * time.Millisecond)
	fields := a.ordered
	if fields == nil {
		fields = []traefixField{}
	}
	return map[string]any{
		"type": "request", "connId": id, "start": ts(start), "end": ts(start.Add(5 * time.Millisecond)), "entryPoint": "websecure",
		"proto": a.proto, "method": "GET", "authority": site, "path": "/", "httpVersion": v1HTTPVersion(a),
		"fieldNames": a.names, "fields": fields, "cookieNames": []string{}, "ja4h": a.ja4h, "headersTruncated": false,
		"status": 200, "router": "fs-e2e@internal", "service": "fs-e2e@internal",
	}
}

// verdictBySource é o GET /bot/v1/verdict pela origem pública da conexão.
func verdictBySource(t *testing.T, k *botKey, o f8Origin, site string) botResp {
	t.Helper()
	return botDo(t, http.MethodGet, fmt.Sprintf("/verdict?src_ip=%s&src_port=%d&site=%s&wait=1000",
		url.QueryEscape(o.src.IP), o.src.Port, url.QueryEscape(site)), k, nil, nil)
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// legacyConn é o registro type=connection do TraefikIngestBatch (formato anterior, mantido em /bot/v1).
func legacyConn(id string, o f8Origin, a f8App) map[string]any {
	alpn := "http/1.1"
	if a.proto == "h2" {
		alpn = "h2"
	}
	r := map[string]any{
		"type": "connection", "fs_conn_id": id, "ts": ts(o.started),
		"src": o.src, "dst": endpoint{IP: o.dstIP, Port: traefikPort}, "entry_point": "websecure",
		"sni": vpsHost, "alpn_offered": a.alpnOffered, "alpn": alpn, "tls_version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256",
		"client_hello": base64.StdEncoding.EncodeToString(a.hello),
	}
	if a.h2Prefix != nil {
		r["h2_prefix"] = base64.StdEncoding.EncodeToString(a.h2Prefix)
	}
	return r
}

// ingestLegacy manda o TraefikIngestBatch (sem schema) e confere que todos os registros entraram.
func ingestLegacy(t *testing.T, k *botKey, records ...map[string]any) {
	t.Helper()
	postIngest(t, k, map[string]any{"sender": "v3.6.2-traefix.e2e", "records": records}, len(records))
}

// legacyAuthHeaders são os X-Fs-* antigos (ADR 0058; só valem sem X-Traefix-Conn-Id, ADR 0063 item 1).
func legacyAuthHeaders(id string, o f8Origin, a f8App, ja4h bool) map[string]string {
	h := map[string]string{
		"X-Forwarded-Method": "GET", "X-Forwarded-Host": vpsHost, "X-Forwarded-Uri": "/", "X-Forwarded-Proto": "https",
		"X-Fs-Src-Ip": o.src.IP, "X-Fs-Src-Port": strconv.Itoa(o.src.Port), "X-Fs-Dst-Port": strconv.Itoa(traefikPort),
		"X-Fs-Conn-Id": id, "X-Fs-Proto": a.proto,
	}
	for n, v := range a.fields {
		h[n] = v
	}
	if ja4h {
		h["X-Fs-Ja4h"] = a.ja4h
	}
	return h
}

// checkNoVerdict confere que a resposta de erro não traz X-Traefix-Verdict nem X-Fs-Verdict e tem o código esperado
// (ADR 0058 item 3, ADR 0063 item 1).
func checkNoVerdict(t *testing.T, what string, r botResp, status int, code string) {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	if r.status != status || e.Error != code {
		t.Errorf("%s: %d %s, esperado %d %s", what, r.status, r.body, status, code)
	}
	for _, n := range []string{"X-Traefix-Verdict", "X-Fs-Verdict"} {
		if v := r.header.Values(n); len(v) > 0 {
			t.Errorf("%s: erro com %s %v (ADR 0058 item 3)", what, n, v)
		}
	}
}

var botHTTP = &http.Client{Timeout: 20 * time.Second}

const traefikPort = 443 // entrada web do traefik-app no finger-01 (capturada pelo espelho)

// visitorHeaders são os authRequestHeaders do perfil da spec 019 RF-04 (nunca Cookie nem Authorization).
var visitorHeaders = []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"}

func postIngest(t *testing.T, k *botKey, batch map[string]any, n int) {
	t.Helper()
	b, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	r := botDo(t, http.MethodPost, "/ingest/traefik", k, nil, b)
	var res struct{ Accepted, Rejected int }
	_ = json.Unmarshal(r.body, &res)
	if r.status != http.StatusAccepted || res.Accepted != n || res.Rejected != 0 {
		t.Fatalf("ingest (%v): %d %s (esperado 202 com %d aceitos)", batch["schema"], r.status, r.body, n)
	}
}

// f8Sender é o sender do traefix simulado (formato traefix/fork-point-<n>-g<sha>, spec 019 RF-06).
const f8Sender = "traefix/fork-point-0-g0e2e304"

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// v1HTTPVersion é o httpVersion do traefix (1.1, 2.0), sem o prefixo HTTP/ do registro do espelho.
func v1HTTPVersion(a f8App) string {
	if a.proto == "h2" {
		return "2.0"
	}
	return strings.TrimPrefix(a.httpVersion, "HTTP/")
}
