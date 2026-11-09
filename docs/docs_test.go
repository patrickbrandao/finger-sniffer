// Package docs confere a documentação derivada (este arquivo não é documentação: só testa os links).
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// linkRe acha links Markdown [texto](alvo); imagens e links externos são filtrados depois.
var linkRe = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// headingRe acha títulos ATX para montar as âncoras no estilo do GitHub.
var headingRe = regexp.MustCompile(`(?m)^#{1,6} (.+)$`)

// slug imita o GitHub: minúsculas, sem pontuação (exceto - e _), espaços viram "-".
func slug(h string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(h)) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r > 127:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripFences remove os blocos de código (um "# comentário" dentro deles não é título).
func stripFences(s string) string {
	return regexp.MustCompile("(?s)```.*?```").ReplaceAllString(s, "")
}

// stripCode remove também os trechos de código, onde "](" não é link.
func stripCode(s string) string {
	return regexp.MustCompile("`[^`\n]*`").ReplaceAllString(stripFences(s), "")
}

func anchors(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range headingRe.FindAllStringSubmatch(stripFences(string(data)), -1) {
		out[slug(m[1])] = true
	}
	return out
}

// TestRelativeLinks: todo link relativo dos .md de docs/ aponta para um arquivo existente e, com âncora, para um
// título existente.
func TestRelativeLinks(t *testing.T) {
	files, err := filepath.Glob("*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("nenhum .md em docs/: %v", err)
	}
	sub, _ := filepath.Glob("*/*.md")
	files = append(files, sub...)
	// O README de raiz também é do papel docs (spec 002) e aponta para docs/, specs e contratos.
	files = append(files, filepath.Join("..", "README.md"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range linkRe.FindAllStringSubmatch(stripCode(string(data)), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			dest := f
			if file != "" {
				dest = filepath.Join(filepath.Dir(f), file)
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s: link quebrado %q", f, target)
					continue
				}
			}
			if anchor != "" && strings.HasSuffix(dest, ".md") && !anchors(t, dest)[anchor] {
				t.Errorf("%s: âncora inexistente %q", f, target)
			}
		}
	}
}

// TestIndexListsGuides: o README lista todos os guias da pasta.
func TestIndexListsGuides(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("*.md")
	for _, f := range files {
		if f != "README.md" && !strings.Contains(string(readme), "]("+f+")") {
			t.Errorf("README.md não lista %s", f)
		}
	}
}

// TestIndexListsDevDocs: o índice de dev/ lista todos os documentos da pasta.
func TestIndexListsDevDocs(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("dev", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("dev", "*.md"))
	for _, f := range files {
		name := filepath.Base(f)
		if name != "README.md" && !strings.Contains(string(readme), "]("+name+")") {
			t.Errorf("dev/README.md não lista %s", name)
		}
	}
}

// TestRootReadme: o README de raiz traz o aviso de tráfego público e aponta para docs, specs, contratos e licença.
func TestRootReadme(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"](docs/README.md)", "](docs/probes.md)", "](specs/INDEX.md)", "](cmd/finger-sniffer-store/openapi.yaml)",
		"](eventbus/nats/asyncapi.yaml)", "](LICENSE)", "](NOTICE)", "FoxIO License 1.1",
		"público", "10 minutos", "make verify-quick", "make deploy", "make tools",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("README.md sem %q", want)
		}
	}
}

// TestProbesMatrix: probes.md tem uma receita por caso da matriz da spec 017 (1–13), cada uma com o que procurar,
// os campos estáveis e as diferenças esperadas por proxy (ADR 0022), e documenta o Date e o date=0 (ADR 0021).
func TestProbesMatrix(t *testing.T) {
	data, err := os.ReadFile("probes.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	heads := regexp.MustCompile(`(?m)^### Caso (\d+):`).FindAllStringSubmatchIndex(s, -1)
	if len(heads) != 13 {
		t.Fatalf("probes.md tem %d casos, quero 13", len(heads))
	}
	for i, h := range heads {
		num := s[h[2]:h[3]]
		if want := strconv.Itoa(i + 1); num != want {
			t.Errorf("caso fora de ordem: %s, quero %s", num, want)
		}
		end := len(s)
		if i+1 < len(heads) {
			end = heads[i+1][0]
		}
		body := s[h[0]:end]
		for _, want := range []string{"```console", "**Procurar**", "**Estáveis**", "**Diferenças esperadas**"} {
			if !strings.Contains(body, want) {
				t.Errorf("caso %s sem %q", num, want)
			}
		}
	}
	for _, want := range []string{
		"`date=0`", "### `Date`", "squid 1080", "go-xproxy 4128", "go-xproxy 4443",
		"`-random`", "absolute-form", "`Proxy-Connection`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("probes.md sem %q", want)
		}
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"Controles de resposta: `/p/<id>/r?...`": "controles-de-resposta-pidr",
		"HTTP/1, h2 e h3":                        "http1-h2-e-h3",
		"Probe: `GET /api/v1/probes/{id}`":       "probe-get-apiv1probesid",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, quero %q", in, got, want)
		}
	}
}

// TestHTTP3Fields: http3.md descreve os campos do HTTP3Info que o xProxy e a página usam, inclusive os do contrato
// 0.3.2.
func TestHTTP3Fields(t *testing.T) {
	data, err := os.ReadFile("http3.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`h3_settings`", "`h3_control_stream_seen`", "`transport_params`", "`date`"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("http3.md sem %s", want)
		}
	}
}
