// Package docs confere a documentação derivada (este arquivo não é documentação: só testa os links).
package docs

import (
	"os"
	"path/filepath"
	"regexp"
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
