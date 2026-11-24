// Package htdocs confere o site estático da spec 014 (este arquivo não é servido: .go não está na lista do RF-01).
package htdocs

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedExt é a lista de extensões que o web serve (spec 014 RF-01).
var allowedExt = map[string]bool{
	".html": true, ".css": true, ".js": true, ".mjs": true, ".json": true, ".svg": true, ".png": true,
	".jpg": true, ".webp": true, ".ico": true, ".woff2": true, ".txt": true,
}

// Hosts permitidos (spec 014 "Comportamento"): a API e a zona dos probes; nenhum outro.
const (
	apiHost   = "finger-01.badblock.net.br"
	probeZone = ".finger-west-01.badblock.net.br"
)

// resourceAttrs são atributos que fazem o navegador carregar algo sozinho.
var resourceAttrs = map[string]bool{"src": true, "srcset": true, "poster": true, "data": true, "action": true, "formaction": true}

// forbiddenElements carregam código ou conteúdo de fora; o único <script> aceito é o módulo local /app.mjs.
var forbiddenElements = map[string]bool{"iframe": true, "object": true, "embed": true, "frame": true}

type element struct {
	name  string
	attrs map[string]string
}

// parseHTML lê o HTML como XML tolerante: a página é escrita bem formada para dar para conferir sem dependências.
func parseHTML(t *testing.T, data []byte) (elems []element, text string) {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	var sb strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("HTML mal formado: %v", err)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			depth++
			e := element{name: strings.ToLower(v.Name.Local), attrs: map[string]string{}}
			for _, a := range v.Attr {
				e.attrs[strings.ToLower(a.Name.Local)] = a.Value
			}
			elems = append(elems, e)
		case xml.EndElement:
			depth--
		case xml.CharData:
			sb.Write(v)
		}
	}
	if depth != 0 {
		t.Fatalf("elementos não fechados: profundidade %d", depth)
	}
	return elems, sb.String()
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestIndexStructure(t *testing.T) {
	data := readFile(t, "index.html")
	if !bytes.HasPrefix(data, []byte("<!DOCTYPE html>\n")) {
		t.Error("index.html deve começar com <!DOCTYPE html>")
	}
	elems, text := parseHTML(t, data)
	var hasLang, hasCharset, hasTitle, hasMain, hasCSS, hasIcon, hasModule bool
	ids := map[string]element{}
	for _, e := range elems {
		if id := e.attrs["id"]; id != "" {
			ids[id] = e
		}
		switch e.name {
		case "link":
			hasCSS = hasCSS || (e.attrs["rel"] == "stylesheet" && e.attrs["href"] == "/style.css")
			hasIcon = hasIcon || (e.attrs["rel"] == "icon" && e.attrs["href"] == "/favicon.svg")
		case "script":
			hasModule = e.attrs["type"] == "module" && e.attrs["src"] == "/app.mjs"
		case "html":
			hasLang = e.attrs["lang"] == "en"
		case "meta":
			if strings.EqualFold(e.attrs["charset"], "utf-8") {
				hasCharset = true
			}
		case "title":
			hasTitle = true
		case "main":
			hasMain = true
		}
	}
	if !hasLang || !hasCharset || !hasTitle || !hasMain {
		t.Errorf("faltam lang=en (%v), charset utf-8 (%v), title (%v) ou main (%v)", hasLang, hasCharset, hasTitle, hasMain)
	}
	if !hasCSS || !hasIcon || !hasModule {
		t.Errorf("faltam style.css (%v), favicon.svg (%v) ou o módulo app.mjs (%v)", hasCSS, hasIcon, hasModule)
	}
	// elementos que o app.mjs procura por id (spec 014 RF-03..RF-05)
	for _, id := range []string{
		"feed", "feed-state", "feed-empty", "pause", "pending", "clear", "run-probe", "filters",
		"f-port", "f-proto", "f-ip", "f-probe", "announce", "probe-panel", "probe-title", "probe-steps",
		"probe-result", "detail", "detail-title", "detail-status", "detail-fields", "detail-pre",
		"detail-pcap", "detail-raw-in", "detail-raw-out", "detail-json", "detail-refresh", "detail-close",
	} {
		if _, ok := ids[id]; !ok {
			t.Errorf("index.html sem o elemento id=%q", id)
		}
	}
	for id, name := range map[string]string{"f-port": "port", "f-proto": "proto", "f-ip": "ip", "f-probe": "probe"} {
		if ids[id].attrs["name"] != name {
			t.Errorf("filtro %s deve ter name=%q", id, name)
		}
	}
	if ids["announce"].attrs["aria-live"] != "polite" {
		t.Error("a região de anúncios deve ter aria-live=polite")
	}
	if _, ok := ids["feed"].attrs["aria-live"]; ok {
		t.Error("a lista do feed não pode ser aria-live (anúncio moderado fica em #announce)")
	}
	// conteúdo exigido pela task 034 e pela spec 014 RF-07
	for _, want := range []string{
		"finger-west-01.badblock.net.br:8443/p/",
		"https://finger-01.badblock.net.br:9000/api/v1/probes/",
		"nc finger-01.badblock.net.br 7",
		"TCP 8080, 8443", "UDP 8443",
		"behind the reverse proxy",
		"/api/v1/openapi.yaml",
		"10 minutes",
		"All traffic is public",
		"This is a non-commercial service.", "FoxIO License 1.1", "BSD-3-Clause",
		"https://finger-01.badblock.net.br:9002/bot/v1/openapi.yaml",
		"9000", "9001",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("texto da página não menciona %q", want)
		}
	}
}

func TestIndexNoThirdParty(t *testing.T) {
	data := readFile(t, "index.html")
	elems, _ := parseHTML(t, data)
	for _, e := range elems {
		if forbiddenElements[e.name] {
			t.Errorf("elemento proibido <%s>", e.name)
		}
		if e.name == "script" && (e.attrs["type"] != "module" || e.attrs["src"] != "/app.mjs") {
			t.Errorf("<script> só como módulo local /app.mjs: %v", e.attrs)
		}
		for k, v := range e.attrs {
			if strings.HasPrefix(k, "on") {
				t.Errorf("<%s> com tratador de evento %s (o JS fica em app.mjs)", e.name, k)
			}
			if resourceAttrs[k] && isExternal(v) {
				t.Errorf("<%s %s=%q> carrega recurso externo", e.name, k, v)
			}
		}
		if e.name == "link" && isExternal(e.attrs["href"]) {
			t.Errorf("<link href=%q> carrega recurso externo", e.attrs["href"])
		}
		if e.name == "a" {
			if h := e.attrs["href"]; isExternal(h) && !isAllowedHost(h) {
				t.Errorf("link para host de terceiros: %q", h)
			}
		}
	}
	lower := bytes.ToLower(data)
	for _, bad := range []string{"url(", "@import", "cookie=", "document.cookie"} {
		if bytes.Contains(lower, []byte(bad)) {
			t.Errorf("index.html contém %q", bad)
		}
	}
}

// isExternal diz se a URL aponta para outro host (esquema ou "//"), em vez de um caminho local.
func isExternal(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "//") || strings.Contains(v, "://")
}

// isAllowedHost diz se a URL aponta para a API ou para um host da zona dos probes.
func isAllowedHost(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == apiHost || (strings.HasSuffix(h, probeZone) && len(h) > len(probeZone))
}

func TestRobots(t *testing.T) {
	data := string(readFile(t, "robots.txt"))
	if !strings.Contains(data, "User-agent: *\n") || !strings.Contains(data, "Disallow: /p/\n") {
		t.Errorf("robots.txt sem User-agent: * e Disallow: /p/: %q", data)
	}
}

func TestOnlyServableFiles(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, "_test.go") {
			return nil
		}
		if !allowedExt[strings.ToLower(filepath.Ext(p))] {
			t.Errorf("%s: extensão que o web não serve (spec 014 RF-01)", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsAllowedHost(t *testing.T) {
	cases := map[string]bool{
		"https://finger-01.badblock.net.br:9000/x":         true,
		"wss://finger-01.badblock.net.br:9000/ws":          true,
		"https://abc.finger-west-01.badblock.net.br:8443/": true,
		"https://finger-west-01.badblock.net.br/":          false,
		"https://abc.finger-01.badblock.net.br/":           false,
		"https://blog.badblock.net.br/":                    false,
		"https://evilfinger-west-01.badblock.net.br/":      false,
		"https://finger-01.tmsoft.com.br:9000/x":           false,
		"https://abc.finger-01.badblock.net.br:8443/":      false,
		"https://cdn.example.com/a.js":                     false,
	}
	for in, want := range cases {
		if got := isAllowedHost(in); got != want {
			t.Errorf("isAllowedHost(%q) = %v, quero %v", in, got, want)
		}
	}
}

// TestNoPreviousServer: o servidor e a zona anteriores saíram do site (ADR 0038). Os nomes são montados por partes
// para que o grep do critério de aceite da task 233 não ache este arquivo.
func TestNoPreviousServer(t *testing.T) {
	old := []string{"vps" + "602", "dns" + "-monitor", "tmsoft.com.br:9000"}
	for _, name := range siteFiles {
		data := strings.ToLower(string(readFile(t, name)))
		for _, bad := range old {
			if strings.Contains(data, bad) {
				t.Errorf("%s ainda cita %q", name, bad)
			}
		}
	}
}

// TestIndexCSP: a página traz a Content-Security-Policy em <meta>, antes de qualquer recurso, com script e estilo
// só da própria origem, sem 'unsafe-inline'/'unsafe-eval', e connect-src só para a API (9000/9001, inclusive o
// ?api= de testes) e a zona dos probes (task 391). O web não manda CSP: as respostas do espelho não mudam.
func TestIndexCSP(t *testing.T) {
	elems, _ := parseHTML(t, readFile(t, "index.html"))
	csp := ""
	for _, e := range elems {
		if e.name == "meta" && strings.EqualFold(e.attrs["http-equiv"], "Content-Security-Policy") {
			csp = e.attrs["content"]
			break
		}
		if e.name == "link" || e.name == "script" || e.name == "style" || e.name == "img" {
			t.Fatalf("<%s> antes da CSP: a política em <meta> só vale para o que vem depois dela", e.name)
		}
	}
	if csp == "" {
		t.Fatal(`index.html sem <meta http-equiv="Content-Security-Policy">`)
	}
	dirs := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			dirs[strings.ToLower(f[0])] = f[1:]
		}
	}
	want := map[string]string{
		"default-src": "'none'", "script-src": "'self'", "style-src": "'self'", "img-src": "'self'",
		"base-uri": "'none'", "form-action": "'none'",
	}
	for d, v := range want {
		if got := strings.Join(dirs[d], " "); got != v {
			t.Errorf("CSP %s = %q, quero %q", d, got, v)
		}
	}
	if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP com unsafe-inline/unsafe-eval: %q", csp)
	}
	allowed := map[string]bool{
		"https://*:9000": true, "wss://*:9000": true, "http://*:9001": true, "ws://*:9001": true,
		"https://*" + probeZone + ":8443": true, "wss://*" + probeZone + ":8443": true,
		"http://*" + probeZone + ":8080": true,
	}
	got := map[string]bool{}
	for _, src := range dirs["connect-src"] {
		got[src] = true
		if !allowed[src] {
			t.Errorf("connect-src com origem fora da API e da zona: %q", src)
		}
	}
	for src := range allowed {
		if !got[src] {
			t.Errorf("connect-src sem %q (API, ?api= de testes ou probe da zona)", src)
		}
	}
}
