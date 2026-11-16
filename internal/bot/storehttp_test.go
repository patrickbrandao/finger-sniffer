package bot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja3"
	"github.com/patrickbrandao/finger-sniffer/pkg/fingerprint/ja4"
	"github.com/patrickbrandao/finger-sniffer/pkg/tlsparse"
)

// Valores que nunca podem aparecer no índice (ADR 0052 item 2): query, caminho, corpo, cookie e Authorization.
const (
	secretQuery  = "token=QUERYSECRET"
	secretPath   = "/private/PATHSECRET"
	secretCookie = "sid=COOKIESECRET"
	secretAuth   = "Bearer AUTHSECRET"
	secretBody   = "BODYSECRET"
	secretRefQ   = "REFQUERYSECRET"
)

var secretValues = []string{"QUERYSECRET", "PATHSECRET", "COOKIESECRET", "AUTHSECRET", "BODYSECRET", "REFQUERYSECRET"}

// h1Item monta um HTTP1Request do store com campos sensíveis.
func h1Item(i int) map[string]any {
	return map[string]any{
		"index": i, "raw_head_b64": base64.StdEncoding.EncodeToString([]byte("GET " + secretPath + "?" + secretQuery)),
		"request_line": map[string]any{
			"method": "GET", "target": secretPath + "?" + secretQuery, "form": "origin", "version": "HTTP/1.1", "terminator": "crlf",
		},
		"fields": [][]string{
			{"Host", ": ", "www.example.com:8443", "crlf"},
			{"User-Agent", ": ", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0 Safari/537.36", "crlf"},
			{"Accept-Language", ": ", "pt-BR,pt;q=0.9", "crlf"},
			{"Cookie", ": ", secretCookie, "crlf"},
			{"Authorization", ": ", secretAuth, "crlf"},
			{"Referer", ": ", "https://Ref.Example.org:444/a/b?" + secretRefQ, "crlf"},
		},
		"body":   map[string]any{"framing": "content-length", "size": 10, "raw_b64": base64.StdEncoding.EncodeToString([]byte(secretBody))},
		"ja4h":   "ge11cr06pt_aaaaaaaaaaaa_bbbbbbbbbbbb_cccccccccccc",
		"status": 200,
	}
}

// h2Stream monta um HTTP2Stream do store com campos sensíveis.
func h2Stream(id int) map[string]any {
	return map[string]any{
		"stream_id": id, "pseudo_order": []string{":method", ":authority", ":scheme", ":path"},
		"fields": []map[string]any{
			{"name": ":method", "value": "POST"},
			{"name": ":authority", "value": "API.example.com"},
			{"name": ":scheme", "value": "https"},
			{"name": ":path", "value": secretPath + "?" + secretQuery},
			{"name": "user-agent", "value": "curl/8.10.1"},
			{"name": "cookie", "value": secretCookie},
			{"name": "authorization", "value": secretAuth},
			{"name": "origin", "value": "https://app.example.net"},
		},
		"ja4h": fmt.Sprintf("po20nn04nn_%012d_000000000000_000000000000", id),
	}
}

// storeMessageWith monta fs.v1.store.connection com o Connection dado (campos de base preenchidos).
func storeMessageWith(t testing.TB, connID, probeID string, srcPort int, extra map[string]any) []byte {
	t.Helper()
	conn := map[string]any{
		"conn_id": connID, "proto": "https", "l4": "tcp", "family": 4,
		"src": map[string]any{"ip": "203.0.113.9", "port": srcPort}, "dst": map[string]any{"ip": "172.233.24.85", "port": 443},
		"started": "2026-11-16T12:00:00.000000000Z", "ended": nil, "tcp": map[string]any{"syn": map[string]any{"ttl": 64}},
	}
	if probeID != "" {
		conn["probe_id"] = probeID
	} else {
		conn["probe_id"] = nil
	}
	for k, v := range extra {
		conn[k] = v
	}
	payload, err := json.Marshal(map[string]any{"stage": "updated", "connection": conn})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"schema_version":1,"service":"store","service_version":"v0.4.0","ts":"2026-11-16T12:00:00.000000000Z","payload":` +
		string(payload) + `}`)
}

// TestStoreHTTPSummary: critério 3 da task 277 — o índice guarda o resumo das requisições do store (h1, h2, h3)
// sem query, caminho, corpo nem valores de cookie/Authorization; o Record sai sem as listas e sem o ClientHello.
func TestStoreHTTPSummary(t *testing.T) {
	streams := make([]any, 0, 20)
	for i := 1; i <= 20; i++ {
		streams = append(streams, h2Stream(2*i-1))
	}
	msg := storeMessageWith(t, testStoreConnID, "", 40000, map[string]any{
		"http":  []any{h1Item(0)},
		"http2": map[string]any{"akamai": "1:65536|15663105|0|m,a,s,p", "streams": streams, "frames": []any{map[string]any{"type": "HEADERS"}}},
		"http3": map[string]any{"requests": []any{map[string]any{
			"stream_id": 0, "pseudo_order": []string{":method", ":scheme", ":authority", ":path"},
			"fields": []map[string]any{
				{"name": ":method", "value": "GET"},
				{"name": ":authority", "value": "h3.example.com"},
				{"name": ":path", "value": "/?" + secretQuery},
				{"name": "cookie", "value": secretCookie},
			},
		}}},
		"tls":       map[string]any{"client_hello_b64": base64.StdEncoding.EncodeToString([]byte(secretBody)), "ja4": "t13d1517h2_x_y"},
		"websocket": map[string]any{"frames": []any{secretBody}},
		"raw":       map[string]any{"in": secretBody},
	})
	c, err := ParseStoreConnection(msg)
	if err != nil {
		t.Fatal(err)
	}
	// 1 h1 + 20 h2 + 1 h3 = 22: fica a primeira (h1) e as 15 mais recentes.
	if c.RequestsSeen != 22 || len(c.Requests) != maxStoreRequests {
		t.Fatalf("requisições: seen %d kept %d", c.RequestsSeen, len(c.Requests))
	}
	h1 := c.Requests[0]
	want1 := StoreRequest{
		Proto: "h1", Method: "GET", Version: "1.1", Host: "www.example.com", HasUserAgent: true,
		UserAgent:  "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0 Safari/537.36",
		FieldOrder: "Host,User-Agent,Accept-Language,Cookie,Authorization,Referer",
		JA4H:       "ge11cr06pt_aaaaaaaaaaaa_bbbbbbbbbbbb_cccccccccccc", AcceptLanguage: true, RefererHost: "ref.example.org",
	}
	if *h1 != want1 {
		t.Errorf("h1:\n got %+v\nwant %+v", h1, want1)
	}
	h2 := c.Requests[1]
	if h2.Proto != "h2" || h2.Method != "POST" || h2.Version != "2.0" || h2.Host != "api.example.com" ||
		h2.UserAgent != "curl/8.10.1" || h2.AcceptLanguage || h2.OriginHost != "app.example.net" ||
		h2.PseudoOrder != ":method,:authority,:scheme,:path" || h2.FieldOrder != "user-agent,cookie,authorization,origin" ||
		h2.JA4H != "po20nn04nn_000000000013_000000000000_000000000000" {
		t.Errorf("h2 (stream 13, o primeiro dos mais recentes): %+v", h2)
	}
	if h3 := c.Requests[len(c.Requests)-1]; h3.Proto != "h3" || h3.Version != "3.0" || h3.Host != "h3.example.com" || h3.HasUserAgent {
		t.Errorf("h3: %+v", h3)
	}

	dump, _ := json.Marshal(c)
	for _, r := range c.Requests {
		dump = append(dump, fmt.Sprintf("%#v", *r)...)
	}
	for _, s := range secretValues {
		if bytes.Contains(dump, []byte(s)) {
			t.Errorf("valor sensível %q no índice: %s", s, dump)
		}
	}
	for _, k := range []string{`"http"`, `"websocket"`, `"raw"`, `"streams"`, `"frames"`, `"requests"`, `"client_hello_b64"`} {
		if bytes.Contains(c.Record, []byte(k)) {
			t.Errorf("record com %s: %s", k, c.Record)
		}
	}
	if !bytes.Contains(c.Record, []byte(`"akamai"`)) || !bytes.Contains(c.Record, []byte(`"ja4"`)) {
		t.Errorf("record perdeu o resto de http2/tls: %s", c.Record)
	}

	// User-Agent cortado em 512 bytes sem quebrar runa; Origin "null" e alvo absoluto.
	long := strings.Repeat("é", 400) // 800 bytes
	item := h1Item(0)
	item["request_line"] = map[string]any{"method": "GET", "target": "http://Proxy.Example.com:3128/x?" + secretQuery, "form": "absolute", "version": "HTTP/1.0"}
	item["fields"] = [][]string{{"user-agent", ":", long, "lf"}, {"Host", ":", "other.example.com", "lf"}, {"Origin", ":", "null", "lf"}}
	c, err = ParseStoreConnection(storeMessageWith(t, testStoreConnID, "", 40000, map[string]any{"http": []any{item}}))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Requests[0]
	if len(r.UserAgent) != 512 || !strings.HasPrefix(long, r.UserAgent) || r.Host != "proxy.example.com" || r.Version != "1.0" || r.OriginHost != "" {
		t.Errorf("borda: ua %d host %q version %q origin %q", len(r.UserAgent), r.Host, r.Version, r.OriginHost)
	}
	// Requisição fora do contrato é pulada sem recusar a mensagem.
	c, err = ParseStoreConnection(storeMessageWith(t, testStoreConnID, "", 40000, map[string]any{"http": []any{"x", h1Item(1)}}))
	if err != nil || c.RequestsSeen != 2 || len(c.Requests) != 1 {
		t.Errorf("item inválido: %v %+v", err, c)
	}
}

// TestIndexByProbe: o índice guarda o probe_id da conexão do store e responde por probe; mudança de probe, TTL e
// forget mantêm o índice secundário certo.
func TestIndexByProbe(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	ix := NewIndex(10*time.Minute, 3, nil)
	put := func(id, probe string, port int, at time.Time) {
		c, err := ParseStoreConnection(storeMessageWith(t, id, probe, port, nil))
		if err != nil {
			t.Fatal(err)
		}
		ix.PutStore(c, at)
	}
	const (
		a = "01JC0X3K8V2T7Q9N4M6P1R5S8A"
		b = "01JC0X3K8V2T7Q9N4M6P1R5S8B"
		c = "01JC0X3K8V2T7Q9N4M6P1R5S8C"
		d = "01JC0X3K8V2T7Q9N4M6P1R5S8D"
	)
	put(a, "p1", 1, now)
	put(b, "p1", 2, now)
	put(c, "", 3, now)
	if got := ix.StoreByProbe("p1", now); len(got) != 2 || got[0].ConnID != a || got[1].ConnID != b {
		t.Fatalf("p1: %+v", got)
	}
	put(b, "p2", 2, now) // a correlação trocou o probe
	if got := ix.StoreByProbe("p1", now); len(got) != 1 || got[0].ConnID != a {
		t.Errorf("p1 depois da troca: %+v", got)
	}
	if got := ix.StoreByProbe("p2", now); len(got) != 1 || got[0].ProbeID != "p2" {
		t.Errorf("p2: %+v", got)
	}
	put(d, "p1", 4, now) // teto 3: despeja a
	if got := ix.StoreByProbe("p1", now); len(got) != 1 || got[0].ConnID != d {
		t.Errorf("p1 depois do despejo: %+v", got)
	}
	if n := ix.Forget(netip.MustParsePrefix("203.0.113.0/24")); n != 3 {
		t.Errorf("forget: %d", n)
	}
	if len(ix.byProbe) != 0 {
		t.Errorf("byProbe depois do forget: %v", ix.byProbe)
	}
	put(a, "p3", 1, now)
	if got := ix.StoreByProbe("p3", now.Add(11*time.Minute)); len(got) != 0 || len(ix.byProbe) != 0 {
		t.Errorf("TTL: %+v %v", got, ix.byProbe)
	}
}

// BenchmarkIndexFullMemory: critério 4 da task 277 — memória do índice cheio (FS_BOT_MAX_CONNS = 100 000 nas
// duas visões). `typical`: store com o TLSInfo do web (Chrome), IP/TCP com séries e 16 streams h2; fork com
// ClientHello/h2 do Chrome e 4 requisições. `worst`: cada requisição com UA de 512 bytes e ordem de campos únicos
// (nada se compartilha) e o fork com 16 requisições de caminho de 256 bytes; medido em 10 000 conexões e
// extrapolado. Reporta bytes por conexão (as duas visões) e o total para 100 000 em MiB.
func BenchmarkIndexFullMemory(b *testing.B) {
	for _, tc := range []struct {
		name  string
		conns int
		worst bool
	}{{"typical", 100_000, false}, {"worst", 10_000, true}} {
		b.Run(tc.name, func(b *testing.B) { benchIndexMemory(b, tc.conns, tc.worst) })
	}
}

func benchIndexMemory(b *testing.B, conns int, worst bool) {
	// TLSInfo como o web publica (listas analisadas com nomes, extensões, ClientHello em base64) e IP/TCP com as
	// séries: o Record precisa ficar só com o que o veredito lê.
	ch, err := tlsparse.Parse(goldenBytes("tls/chrome.bin"))
	if err != nil {
		b.Fatal(err)
	}
	tlsInfo := tlsparse.NewInfo(ch, goldenBytes("tls/chrome.bin"), tlsparse.DefaultInlineMax)
	ja3.Fill(tlsInfo, ch)
	ja4.Fill(tlsInfo, ch, ja4.TCP)
	series := make([][2]float64, 64)
	tcpInfo := map[string]any{
		"syn":     map[string]any{"window": 65535, "options": [][]any{{"mss", 1432}, {"nop"}, {"wscale", 6}, {"sack_perm"}}},
		"syn_mss": 1432, "mtu_implied": 1492, "mss_reduction": 8, "ja4t": "65535_2-1-3-1-1-8-4-0-0_1432_6",
		"p0f": "6:53+11:0:1432:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:ecn,flow:0", "window_series": series,
		"segments_in": series, "segments_out": series,
	}
	ipInfo := map[string]any{"ttl": 53, "ttl_initial": 64, "hops": 11, "packets": map[string]any{"syn": map[string]any{"ttl": 53}}}
	streams := make([]any, 0, 16)
	for i := 1; i <= 16; i++ {
		st := h2Stream(2*i - 1)
		if worst {
			fields := st["fields"].([]map[string]any) //nolint:forcetypeassert // montado acima
			fields[4]["value"] = "UNIQ_UA_" + strings.Repeat("u", 500) + fmt.Sprintf("%02d", i)
			fields = append(fields, map[string]any{"name": fmt.Sprintf("x-uniq-%02d-UNIQF", i), "value": "1"})
			st["fields"] = fields
		}
		streams = append(streams, st)
	}
	storeTpl := string(storeMessageWith(b, "CONNIDCONNIDCONNIDCONNID00", "", 12345, map[string]any{
		"tls": tlsInfo, "tcp": tcpInfo, "ip": ipInfo,
		"http2": map[string]any{"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "streams": streams},
	}))
	fork := `{"type":"connection","fs_conn_id":"FSID","ts":"2026-11-16T12:00:00Z","src":{"ip":"198.51.100.7","port":12345},` +
		`"dst":{"ip":"10.249.0.2","port":443},"entry_point":"websecure","sni":"www.example.com","alpn_offered":["h2","http/1.1"],` +
		`"client_hello":"` + base64.StdEncoding.EncodeToString(goldenBytes("tls/chrome.bin")) + `","h2_prefix":"` +
		base64.StdEncoding.EncodeToString(goldenBytes("h2/chrome.prefix")) + `"}`
	req := `{"type":"request","fs_conn_id":"FSID","ts":"2026-11-16T12:00:01Z","proto":"h2","method":"GET","authority":"www.example.com",` +
		`"path":"PATH","http_version":"2.0","field_names":["sec-ch-ua","user-agent","accept","accept-language","cookie"],` +
		`"fields":{"user-agent":"UA","accept":"*/*"},` +
		`"cookie_names":["sid"],"ja4h":"ge20nn05ptbr_aaaaaaaaaaaa_000000000000_000000000000","status":200}`
	forkReqs := 4
	if worst {
		forkReqs = maxForkRequests
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for range b.N {
		ix := NewIndex(10*time.Minute, conns, nil)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := range conns {
			id := fmt.Sprintf("01JC0X3K8V2T7Q9N%010d", i)
			port := strconv.Itoa(10000 + i%50000)
			msg := strings.Replace(strings.Replace(storeTpl, "CONNIDCONNIDCONNIDCONNID00", id, 1), "12345", port, 1)
			if worst {
				msg = strings.ReplaceAll(strings.ReplaceAll(msg, "UNIQ_UA_", id[16:]), "UNIQF", id[16:])
			}
			sc, err := ParseStoreConnection([]byte(msg))
			if err != nil {
				b.Fatal(err)
			}
			ix.PutStore(sc, now)
			fid := fmt.Sprintf("01JC0X3K8V2T7Q9F%010d", i)
			recs := []string{strings.Replace(strings.Replace(fork, "FSID", fid, 1), "12345", port, 1)}
			for j := range forkReqs {
				path, ua := "/static/app.js", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
				if worst {
					path = fmt.Sprintf("/%s/%02d/%s", fid, j, strings.Repeat("p", 220))
					ua = fmt.Sprintf("%s-%02d-%s", fid, j, strings.Repeat("u", 480))
				}
				recs = append(recs, strings.NewReplacer("FSID", fid, "PATH", path, `"UA"`, `"`+ua+`"`).Replace(req))
			}
			for j, raw := range recs {
				p, err := parseRecord(json.RawMessage(raw))
				if err != nil {
					b.Fatal(j, err)
				}
				ix.UpdateFork(fid, now, p.apply)
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		used := float64(after.HeapAlloc) - float64(before.HeapAlloc)
		b.ReportMetric(used/float64(conns), "B/conn")
		b.ReportMetric(used/float64(conns)*100_000/(1<<20), "MiB/100k")
		runtime.KeepAlive(ix)
	}
}

// TestInterner: resumos e textos iguais são compartilhados entre conexões; cheio, o interner recomeça sem perder
// o que já foi entregue.
func TestInterner(t *testing.T) {
	in := &interner{max: 2}
	r := StoreRequest{Proto: "h2", Method: "GET", UserAgent: strings.Repeat("a", 10)}
	p1, p2 := in.request(r), in.request(r)
	if p1 != p2 || *p1 != r {
		t.Fatalf("resumo não compartilhado: %p %p", p1, p2)
	}
	in.request(StoreRequest{Method: "POST"})
	p3 := in.request(r) // a geração encheu (2) e recomeçou: novo ponteiro, mesmo conteúdo
	if *p3 != r || *p1 != r {
		t.Errorf("depois da troca de geração: %+v %+v", p3, p1)
	}
	l := in.list([]string{"h2", "http/1.1"})
	if l2 := in.list([]string{"h2", "http/1.1"}); &l[0] != &l2[0] {
		t.Error("lista não compartilhada")
	}
	if in.list(nil) != nil || in.fields(map[string]string{}) != nil {
		t.Error("vazios")
	}
	m := in.fields(map[string]string{"user-agent": "x", "accept": "*/*"})
	if m2 := in.fields(map[string]string{"accept": "*/*", "user-agent": "x"}); len(m2) != 2 || m2["user-agent"] != "x" ||
		fmt.Sprintf("%p", m) != fmt.Sprintf("%p", m2) {
		t.Error("mapa não compartilhado")
	}
	if m3 := in.fields(map[string]string{"user-agent": "y", "accept": "*/*"}); m3["user-agent"] != "y" {
		t.Error("mapa diferente compartilhado")
	}
}
