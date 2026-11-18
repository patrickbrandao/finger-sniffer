package bot

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"
)

// traefixAuthHeaders são os X-Traefix-* de origem da primeira requisição de uma conexão ainda sem registro do
// ingest, com o UA dado.
func traefixAuthHeaders(connID string, srcPort int, proto, ua string) map[string]string {
	return map[string]string{
		"X-Traefix-Src-Ip": "198.51.100.80", "X-Traefix-Src-Port": strconv.Itoa(srcPort), "X-Traefix-Dst-Port": "443",
		"X-Traefix-Conn-Id": connID, "X-Traefix-Proto": proto, "X-Forwarded-Host": "www.example.com",
		"X-Forwarded-Uri": "/", "X-Forwarded-Method": "GET", "User-Agent": ua, "Accept-Language": "pt-BR",
	}
}

// authVerdict faz o forwardAuth e devolve status, cabeçalhos e o veredito.
func (f *fixture) authVerdict(base string, key string, hdr map[string]string) (int, http.Header, Verdict, []byte) {
	f.t.Helper()
	srv := f.internal
	if base == "public" {
		srv = f.public
	}
	c, h, b := f.do(srv, "GET", "/bot/v1/auth", key, hdr, "")
	var v Verdict
	_ = json.Unmarshal(b, &v)
	return c, h, v, b
}

// TestAuthTraefixHeaderFingerprints: critérios 2 e 3 da task 303 — a primeira requisição de uma conexão, sem o
// registro de conexão do ingest, é julgada com JA4/Akamai/ALPN/JA4T dos X-Traefix-* (source="header"); sem
// X-Traefix-Alpn nenhum sinal de ALPN é avaliado.
func TestAuthTraefixHeaderFingerprints(t *testing.T) {
	chrome := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	chromeH2 := analyzeH2Prefix(goldenBytes("h2/chrome.prefix"), false).Akamai
	curl := analyzeClientHello(goldenBytes("tls/curl-macos.bin"), false)
	curlH2 := analyzeH2Prefix(goldenBytes("h2/curl-libressl.prefix"), false).Akamai
	ids := func(v Verdict) []string { return signalIDList(v.Signals) }

	t.Run("curl stack with chrome ua", func(t *testing.T) {
		f := newFixture(t)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T40", 50040, "h2", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-Ja3"], h["X-Traefix-H2"] = curl.JA4, curl.JA3MD5, curlH2
		h["X-Traefix-Alpn"] = "h2,http/1.1"
		c, _, v, b := f.authVerdict("internal", "", h)
		if c != 200 || !slices.Contains(ids(v), "ua_tls_mismatch") || !v.View.TLS || !v.View.H2 {
			t.Fatalf("veredito: %d %s", c, b)
		}
		if v.Fingerprints.JA4 == nil || *v.Fingerprints.JA4 != curl.JA4 || v.Fingerprints.JA3 == nil || *v.Fingerprints.JA3 != curl.JA3MD5 ||
			v.Fingerprints.Akamai == nil || *v.Fingerprints.Akamai != curlH2 {
			t.Errorf("fingerprints: %+v", v.Fingerprints)
		}
		for kind, src := range map[string]string{"tls": fpFromHeader, "h2": fpFromHeader, "tcp": fpNone} {
			if n := f.metrics.Get(authFPMetric(kind, src)); n != 1 {
				t.Errorf("bot_auth_fingerprint_total{kind=%q,source=%q} = %v", kind, src, n)
			}
		}
	})
	t.Run("alpn http/1.1 with chrome ua", func(t *testing.T) {
		f := newFixture(t)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T41", 50041, "h2", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-H2"], h["X-Traefix-Alpn"] = chrome.JA4, chromeH2, "http/1.1"
		if _, _, v, b := f.authVerdict("internal", "", h); !slices.Contains(ids(v), "ua_alpn_mismatch") {
			t.Fatalf("sem ua_alpn_mismatch: %s", b)
		}
		// decodificado de %XX: "h2" escrito como %68%32 conta como h2
		h["X-Traefix-Alpn"] = "%68%32,http%2F1.1"
		if _, _, v, b := f.authVerdict("internal", "", h); slices.Contains(ids(v), "ua_alpn_mismatch") {
			t.Fatalf("ALPN decodificado ignorado: %s", b)
		}
	})
	t.Run("no alpn header", func(t *testing.T) {
		f := newFixture(t)
		// h1 sem X-Traefix-Alpn: nem ua_alpn_mismatch nem o ramo de ALPN de ua_h2_mismatch
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T42", 50042, "h1", uaChrome)
		h["X-Traefix-Ja4"] = chrome.JA4
		for _, alpn := range []string{"", "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q", "%zz"} {
			if alpn != "" {
				h["X-Traefix-Alpn"] = alpn // malformado = ausente
			}
			_, _, v, b := f.authVerdict("internal", "", h)
			if !v.View.TLS || slices.Contains(ids(v), "ua_alpn_mismatch") || slices.Contains(ids(v), "ua_h2_mismatch") {
				t.Fatalf("alpn %q: sinal de ALPN sem o dado: %s", alpn, b)
			}
		}
	})
	t.Run("empty alpn header", func(t *testing.T) {
		f := newFixture(t)
		// presente e vazio: ClientHello sem ALPN (lista vazia conhecida), as regras de ALPN avaliam
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T4A", 50050, "h1", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-Alpn"] = chrome.JA4, ""
		if _, _, v, b := f.authVerdict("internal", "", h); !slices.Contains(ids(v), "ua_alpn_mismatch") {
			t.Fatalf("X-Traefix-Alpn vazio sem ua_alpn_mismatch: %s", b)
		}
	})
	t.Run("ja4t header from private origin", func(t *testing.T) {
		f := newFixture(t)
		// SYN de proxy local (ex.: docker-proxy): o JA4T do cabeçalho é descartado como no ingest (ADR 0063 item 5)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T4B", 50051, "h2", uaChrome)
		h["X-Traefix-Src-Ip"] = "172.17.0.1"
		h["X-Traefix-Ja4"], h["X-Traefix-H2"], h["X-Traefix-Alpn"] = chrome.JA4, chromeH2, "h2,http/1.1"
		h["X-Traefix-Ja4t"] = ja4tFull
		_, _, v, b := f.authVerdict("internal", "", h)
		if v.View.TCP || v.Fingerprints.JA4T != nil {
			t.Fatalf("JA4T do cabeçalho com origem privada usado: %s", b)
		}
		if n := f.metrics.Get(authFPMetric("tcp", fpNone)); n != 1 {
			t.Errorf("tcp/none = %v", n)
		}
	})
	t.Run("ja4t header", func(t *testing.T) {
		f := newFixture(t)
		h := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T43", 50043, "h2", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-H2"], h["X-Traefix-Alpn"] = chrome.JA4, chromeH2, "h2,http/1.1"
		h["X-Traefix-Ja4h"] = "ge20nn13ptbr_0c2c1d640f3e_000000000000_000000000000"
		h["X-Traefix-Ja4t"] = ja4tFull
		_, _, v, b := f.authVerdict("internal", "", h)
		if !v.View.TCP || v.Class != ClassHuman || !slices.Equal(ids(v), []string{"known_client"}) {
			t.Fatalf("JA4T do cabeçalho: %s", b)
		}
		if v.Fingerprints.TTLInitial != nil || v.Fingerprints.P0fOS != nil || v.Fingerprints.JA4T == nil || *v.Fingerprints.JA4T != ja4tFull {
			t.Errorf("visão TCP do cabeçalho com mais que o JA4T: %+v", v.Fingerprints)
		}
		if n := f.metrics.Get(authFPMetric("tcp", fpFromHeader)); n != 1 {
			t.Errorf("tcp/header = %v", n)
		}
		// MSS reduzido no JA4T do cabeçalho: tunnel_mss
		h["X-Traefix-Ja4t"] = "65535_2-1-3-1-1-8-4-0-0_1400_6"
		if _, _, v, b := f.authVerdict("internal", "", h); !slices.Contains(ids(v), "tunnel_mss") {
			t.Fatalf("tunnel_mss pelo cabeçalho: %s", b)
		}
	})
	t.Run("ingest wins over headers", func(t *testing.T) {
		f := newFixture(t)
		const id = "01JC0X3K8V2T7Q9F4M6P1R5T44"
		f.postIngest(traefixBatchJSON(t, id, "198.51.100.80", 50044, chromeConn(map[string]any{"ja4t": ja4tFull, "ttl": 52}), nil))
		h := traefixAuthHeaders(id, 50044, "h2", uaChrome)
		h["X-Traefix-Ja4"], h["X-Traefix-H2"], h["X-Traefix-Ja4t"] = curl.JA4, curlH2, "65535_2-1-3-1-1-8-4-0-0_1400_6"
		_, _, v, b := f.authVerdict("internal", "", h)
		if v.Fingerprints.JA4 == nil || *v.Fingerprints.JA4 != chrome.JA4 || slices.Contains(ids(v), "tunnel_mss") {
			t.Fatalf("o registro do ingest não venceu: %s", b)
		}
		for _, kind := range []string{"tls", "h2", "tcp"} {
			if n := f.metrics.Get(authFPMetric(kind, fpFromIngest)); n != 1 {
				t.Errorf("%s/ingest = %v", kind, n)
			}
		}
	})
	t.Run("malformed or repeated", func(t *testing.T) {
		f := newFixture(t)
		hdr := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T45", 50045, "h2", uaChrome)
		hdr["X-Traefix-Ja4"], hdr["X-Traefix-H2"], hdr["X-Traefix-Ja4t"] = "t13d_bogus", "a|b|c|d", "bogus"
		_, _, v, b := f.authVerdict("internal", "", hdr)
		if v.View.TLS || v.View.TCP || v.Fingerprints.Akamai != nil {
			t.Fatalf("cabeçalho malformado usado: %s", b)
		}
		req, _ := http.NewRequestWithContext(t.Context(), "GET", f.internal.URL+"/bot/v1/auth", nil)
		for k, v := range traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T46", 50046, "h1", uaChrome) {
			req.Header.Set(k, v)
		}
		req.Header.Add("X-Traefix-Ja4", chrome.JA4)
		req.Header.Add("X-Traefix-Ja4", chrome.JA4)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var rv Verdict
		_ = json.NewDecoder(resp.Body).Decode(&rv)
		_ = resp.Body.Close()
		if rv.View.TLS {
			t.Error("X-Traefix-Ja4 repetido usado")
		}
	})
}

// TestAuthTraefixHeaderSets: critério 1 da task 303 — X-Traefix-* lidos e respondidos; X-Fs-* só sem
// X-Traefix-Conn-Id e nunca misturados; respostas 200 e 403 com os dois conjuntos; erros sem nenhum Verdict.
func TestAuthTraefixHeaderSets(t *testing.T) {
	f := newFixture(t)
	vals := contractValues{}
	sameSets := func(h http.Header) {
		t.Helper()
		for _, k := range []string{"Verdict", "Score", "Signals"} {
			if h.Get("X-Traefix-"+k) != h.Get("X-Fs-"+k) || h.Values("X-Traefix-"+k) == nil {
				t.Errorf("%s: X-Traefix %q, X-Fs %q", k, h.Get("X-Traefix-"+k), h.Get("X-Fs-"+k))
			}
		}
	}
	// X-Fs-* forjados junto dos X-Traefix-*: ignorados (origem e JA4H)
	hdr := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T50", 50050, "h2", "curl/8.7.1")
	hdr["X-Fs-Src-Ip"], hdr["X-Fs-Src-Port"], hdr["X-Fs-Conn-Id"] = "192.0.2.66", "1", "01JC0X3K8V2T7Q9F4M6P1R5T99"
	hdr["X-Fs-Ja4h"] = ja4hCurl
	c, h, v, b := f.authVerdict("internal", "", hdr)
	if c != 200 || v.Subject.Src == nil || v.Subject.Src.IP != "198.51.100.80" || deref(v.Subject.FsConnID) != "01JC0X3K8V2T7Q9F4M6P1R5T50" ||
		v.Fingerprints.JA4H != nil {
		t.Fatalf("X-Fs-* misturados aos X-Traefix-*: %d %s", c, b)
	}
	if n := f.metrics.Get(authJA4HMetric(ja4hNone)); n != 1 {
		t.Errorf("ja4h{none} = %v", n)
	}
	sameSets(h)
	vals.add(refVerdict, b)
	// X-Traefix-Ja4h vale
	hdr = traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T51", 50051, "h2", "curl/8.7.1")
	hdr["X-Traefix-Ja4h"] = ja4hCurl
	if _, h, v, b = f.authVerdict("internal", "", hdr); v.Fingerprints.JA4H == nil || *v.Fingerprints.JA4H != ja4hCurl {
		t.Fatalf("X-Traefix-Ja4h: %s", b)
	}
	sameSets(h)
	vals.add(refVerdict, b)
	// X-Traefix-Conn-Id com o resto só em X-Fs-*: 400 com o nome novo, sem completar pelo outro conjunto
	hdr = traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T52", 50052, "h2", "curl/8.7.1")
	delete(hdr, "X-Traefix-Src-Ip")
	hdr["X-Fs-Src-Ip"] = "198.51.100.80"
	c, h, _, b = f.authVerdict("internal", "", hdr)
	if c != 400 || errorCode(t, b) != errMissingForkHeaders {
		t.Fatalf("conjuntos misturados: %d %s", c, b)
	}
	for _, k := range verdictHeaders {
		if h.Get(k) != "" {
			t.Errorf("erro com %s", k)
		}
	}
	vals.add(refError, b)
	// só X-Fs-* (formato antigo) segue funcionando, e responde os dois conjuntos
	f.postIngest(validBatch())
	c, h, _, b = f.authVerdict("internal", "", forkHeadersFor())
	if c != 200 {
		t.Fatalf("X-Fs-* antigos: %d %s", c, b)
	}
	sameSets(h)
	// 403 do block com os dois conjuntos
	_, blk := f.createKey(KeyOptions{Name: "blk", Domains: []string{"www.example.com"}, Mode: ModeBlock})
	hdr = traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T53", 50053, "h2", "curl/8.7.1")
	hdr["X-Traefix-Ja4h"] = ja4hCurl
	delete(hdr, "Accept-Language")
	c, h, v, b = f.authVerdict("internal", blk, hdr)
	if c != 403 || v.Class != ClassBot || h.Get("X-Traefix-Verdict") != ClassBot {
		t.Fatalf("block: %d %v %s", c, h, b)
	}
	sameSets(h)
	vals.add(refVerdict, b)
	// erro de chave: nenhum Verdict
	c, h, _, b = f.authVerdict("public", "", traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T54", 50054, "h2", "x"))
	if c != 401 {
		t.Fatalf("sem chave: %d %s", c, b)
	}
	for _, k := range verdictHeaders {
		if h.Get(k) != "" {
			t.Errorf("401 com %s", k)
		}
	}
	vals.add(refError, b)
	if !testing.Short() {
		for ref, vs := range vals {
			validateContract(t, ref, vs...)
		}
	}
}

// TestAuthTraefixWait: critério 5 da task 303 (ADR 0063 item 7) — na 9002 o forwardAuth não espera o store; na
// 9003, com X-Traefix-Ja4 (e -H2 em h2) espera só o store, e view_wait{missing="fork"} não conta.
func TestAuthTraefixWait(t *testing.T) {
	chrome := analyzeClientHello(goldenBytes("tls/chrome.bin"), false)
	chromeH2 := analyzeH2Prefix(goldenBytes("h2/chrome.prefix"), false).Akamai
	const wait = 400 * time.Millisecond
	f := newFixture(t)
	f.srv.api.ViewWait = wait
	_, key := f.createKey(KeyOptions{Name: "ext", Domains: []string{"www.example.com"}, RatePerS: 1000, Burst: 1000})
	hdr := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T60", 50060, "h2", uaChrome)
	hdr["X-Traefix-Ja4"], hdr["X-Traefix-H2"] = chrome.JA4, chromeH2

	// 9002 com as fingerprints nos cabeçalhos: nenhuma espera
	start := time.Now()
	if c, _, _, b := f.authVerdict("public", key, hdr); c != 200 {
		t.Fatalf("9002: %d %s", c, b)
	}
	if d := time.Since(start); d >= wait/2 {
		t.Errorf("9002 esperou %s", d)
	}
	if f.metrics.Get(viewWaitMetric("fork")) != 0 || f.metrics.Get(viewWaitMetric("tcp")) != 0 {
		t.Errorf("view_wait contado na 9002: fork %v tcp %v", f.metrics.Get(viewWaitMetric("fork")), f.metrics.Get(viewWaitMetric("tcp")))
	}
	// 9002 sem as fingerprints: espera só o traefix
	plain := traefixAuthHeaders("01JC0X3K8V2T7Q9F4M6P1R5T61", 50061, "h2", uaChrome)
	start = time.Now()
	f.authVerdict("public", key, plain)
	if d := time.Since(start); d < wait*3/4 {
		t.Errorf("9002 sem cabeçalhos não esperou o traefix: %s", d)
	}
	if f.metrics.Get(viewWaitMetric("fork")) != 1 || f.metrics.Get(viewWaitMetric("tcp")) != 0 {
		t.Errorf("view_wait na 9002: fork %v tcp %v", f.metrics.Get(viewWaitMetric("fork")), f.metrics.Get(viewWaitMetric("tcp")))
	}
	// 9003 com as fingerprints: espera o store (que não vem), não o traefix
	hdr["X-Traefix-Conn-Id"] = "01JC0X3K8V2T7Q9F4M6P1R5T62"
	start = time.Now()
	f.authVerdict("internal", "", hdr)
	if d := time.Since(start); d < wait*3/4 {
		t.Errorf("9003 não esperou o store: %s", d)
	}
	if f.metrics.Get(viewWaitMetric("fork")) != 1 || f.metrics.Get(viewWaitMetric("tcp")) != 1 {
		t.Errorf("view_wait na 9003: fork %v tcp %v", f.metrics.Get(viewWaitMetric("fork")), f.metrics.Get(viewWaitMetric("tcp")))
	}
	// h2 sem X-Traefix-H2: o traefix ainda é esperado
	delete(hdr, "X-Traefix-H2")
	hdr["X-Traefix-Conn-Id"] = "01JC0X3K8V2T7Q9F4M6P1R5T63"
	f.authVerdict("internal", "", hdr)
	if f.metrics.Get(viewWaitMetric("fork")) != 2 {
		t.Errorf("h2 sem X-Traefix-H2 não esperou o traefix: %v", f.metrics.Get(viewWaitMetric("fork")))
	}
}

// TestDecodeALPNHeader: X-Traefix-Alpn com %XX, até 16 valores de até 255 bytes.
func TestDecodeALPNHeader(t *testing.T) {
	for in, want := range map[string][]string{
		"h2,http/1.1": {"h2", "http/1.1"}, "%2C%25,h3": {",%", "h3"}, "a%C3%A9": {"aé"}, "": {},
	} {
		if got, ok := decodeALPNHeader(in); !ok || !slices.Equal(got, want) {
			t.Errorf("%q: %v %v", in, got, ok)
		}
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	for _, bad := range []string{"h2,,h3", "%zz", string(long), "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"} {
		if _, ok := decodeALPNHeader(bad); ok {
			t.Errorf("%q aceito", bad)
		}
	}
}
