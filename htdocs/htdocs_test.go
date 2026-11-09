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

// ownHostSuffix é o domínio dos nossos hosts; links para fora dele são proibidos (spec 000 RNF-08).
const ownHostSuffix = ".tmsoft.com.br"

// resourceAttrs são atributos que fazem o navegador carregar algo sozinho.
var resourceAttrs = map[string]bool{"src": true, "srcset": true, "poster": true, "data": true, "action": true, "formaction": true}

// forbiddenElements carregam código ou conteúdo de fora; a página da F3 não usa nenhum.
var forbiddenElements = map[string]bool{"script": true, "iframe": true, "object": true, "embed": true, "frame": true}

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
	var hasLang, hasCharset, hasTitle, hasMain bool
	for _, e := range elems {
		switch e.name {
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
	// conteúdo exigido pela task 034 e pela spec 014 RF-07
	for _, want := range []string{
		"dns-monitor.tmsoft.com.br/p/",
		"https://vps602.tmsoft.com.br:9000/api/v1/probes/",
		"/api/v1/openapi.yaml",
		"10 minutes",
		"All traffic is public",
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
		for k, v := range e.attrs {
			if strings.HasPrefix(k, "on") {
				t.Errorf("<%s> com tratador de evento %s (sem JS na F3)", e.name, k)
			}
			if resourceAttrs[k] && isExternal(v) {
				t.Errorf("<%s %s=%q> carrega recurso externo", e.name, k, v)
			}
		}
		if e.name == "link" && isExternal(e.attrs["href"]) {
			t.Errorf("<link href=%q> carrega recurso externo", e.attrs["href"])
		}
		if e.name == "a" {
			if h := e.attrs["href"]; isExternal(h) && !isOwnHost(h) {
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

func isOwnHost(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	return strings.HasSuffix("."+u.Hostname(), ownHostSuffix)
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

func TestIsOwnHost(t *testing.T) {
	cases := map[string]bool{
		"https://vps602.tmsoft.com.br:9000/x":    true,
		"https://abc.dns-monitor.tmsoft.com.br/": true,
		"https://eviltmsoft.com.br/":             false,
		"https://cdn.example.com/a.js":           false,
	}
	for in, want := range cases {
		if got := isOwnHost(in); got != want {
			t.Errorf("isOwnHost(%q) = %v, quero %v", in, got, want)
		}
	}
}
