package htdocs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// siteFiles são os arquivos de texto do site conferidos (spec 014 "Comportamento").
var siteFiles = []string{"index.html", "app.mjs", "style.css", "favicon.svg", "robots.txt"}

// urlRe acha URLs com esquema; o host vai até o primeiro separador.
var urlRe = regexp.MustCompile(`(?i)\b(https?|wss?)://([^\s"'<>()/\x60]*)`)

// svgNamespace é o único "http://" que não é requisição: o namespace do SVG.
const svgNamespace = `xmlns="http://www.w3.org/2000/svg"`

// cspMetaRe acha a CSP em <meta> do index.html: as origens dela são fontes com curinga, não requisições, e são
// conferidas à parte pelo TestIndexCSP (task 391).
var cspMetaRe = regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="[^"]*" />`)

// TestSiteURLs: nenhum http(s)/ws(s) fora da API e da zona dos probes, em nenhum arquivo do site. As URLs
// montadas por template no app.mjs só podem usar ${host}, que é sempre <id>.PROBE_ZONE, com a porta explícita do web
// (${TLS_PORT} ou ${PLAIN_PORT}): sem porta, a sondagem cairia no traefik da 80/443 (ADR 0038).
func TestSiteURLs(t *testing.T) {
	for _, name := range siteFiles {
		data := readFile(t, name)
		if name == "favicon.svg" {
			if bytes.Count(data, []byte(svgNamespace)) != 1 {
				t.Errorf("favicon.svg: namespace SVG inesperado")
			}
			data = bytes.Replace(data, []byte(svgNamespace), nil, 1)
		}
		if name == "index.html" {
			if n := len(cspMetaRe.FindAll(data, -1)); n != 1 {
				t.Errorf("index.html: %d metas de CSP, quero 1", n)
			}
			data = cspMetaRe.ReplaceAll(data, nil)
		}
		for _, m := range urlRe.FindAllSubmatch(data, -1) {
			host := string(m[2])
			if strings.HasPrefix(host, "${") {
				if name != "app.mjs" || (!strings.HasPrefix(host, "${host}:${TLS_PORT}") &&
					!strings.HasPrefix(host, "${host}:${PLAIN_PORT}")) {
					t.Errorf("%s: URL montada fora do padrão ${host}:${porta}: %q", name, m[0])
				}
				continue
			}
			if !isAllowedHost(string(m[1]) + "://" + host + "/") {
				t.Errorf("%s: host não permitido em %q", name, m[0])
			}
		}
	}
	app := string(readFile(t, "app.mjs"))
	if n := strings.Count(app, "const host = "); n != 1 || !strings.Contains(app, "const host = `${id}.${PROBE_ZONE}`;") {
		t.Errorf("app.mjs: host das sondagens deve ser só `${id}.${PROBE_ZONE}` (%d definições)", n)
	}
	if !strings.Contains(app, `export const PROBE_ZONE = "finger-west-01.badblock.net.br";`) ||
		!strings.Contains(app, `export const DEFAULT_API = "https://finger-01.badblock.net.br:9000";`) ||
		!strings.Contains(app, `export const TLS_PORT = 8443;`) ||
		!strings.Contains(app, `export const PLAIN_PORT = 8080;`) {
		t.Error("app.mjs: constantes da API, da zona ou das portas mudaram (ADR 0038)")
	}
}

// TestNoUnsafeDOM: os dados da API vêm de terceiros; nada de HTML montado por string, eval ou cookies.
func TestNoUnsafeDOM(t *testing.T) {
	for _, name := range siteFiles {
		lower := strings.ToLower(string(readFile(t, name)))
		for _, bad := range []string{
			"innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "eval(", "new function",
			"document.cookie", "sessionstorage", "indexeddb", "serviceworker", "sendbeacon",
		} {
			if strings.Contains(lower, bad) {
				t.Errorf("%s contém %q", name, bad)
			}
		}
	}
	css := strings.ToLower(string(readFile(t, "style.css")))
	for _, bad := range []string{"url(", "@import", "@font-face"} {
		if strings.Contains(css, bad) {
			t.Errorf("style.css contém %q (sem recursos carregados pelo CSS)", bad)
		}
	}
	app := string(readFile(t, "app.mjs"))
	if regexp.MustCompile(`(?m)^\s*import[\s{*"]`).MatchString(app) || strings.Contains(app, "import(") {
		t.Error("app.mjs não importa outros módulos")
	}
}

// TestAppModule confere a sintaxe do app.mjs e roda os testes de comportamento em JS (harness_test.go)
// com o node. Sem node no PATH, o teste é pulado (o CI e o Mac de desenvolvimento têm).
func TestAppModule(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node não encontrado no PATH")
	}
	if out, err := exec.Command(node, "--check", "app.mjs").CombinedOutput(); err != nil {
		t.Fatalf("node --check app.mjs: %v\n%s", err, out)
	}
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.mjs")
	if err := os.WriteFile(harness, []byte(jsHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := filepath.Abs("app.mjs")
	if err != nil {
		t.Fatal(err)
	}
	examples, err := filepath.Abs(filepath.Join("..", "cmd", "finger-sniffer-store", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, harness, app, examples)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("testes JS falharam: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
