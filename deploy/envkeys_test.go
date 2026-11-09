package deploy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// notEnvKeys são literais "FS_*" do código de produção que não são variáveis de ambiente.
var notEnvKeys = map[string]string{
	"FS_EVENTS": "nome do stream JetStream (internal/store/bus.go)",
}

var fsKeyLiteral = regexp.MustCompile(`"(FS_[A-Z0-9_]+)"`)

// codeEnvKeys extrai as chaves FS_* citadas como literal no código de produção (cmd/, internal/, pkg/,
// sem *_test.go), com o arquivo da primeira ocorrência.
func codeEnvKeys(t *testing.T) map[string]string {
	t.Helper()
	keys := map[string]string{}
	for _, root := range []string{"../cmd", "../internal", "../pkg"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range fsKeyLiteral.FindAllStringSubmatch(string(b), -1) {
				if _, skip := notEnvKeys[m[1]]; skip {
					continue
				}
				if _, ok := keys[m[1]]; !ok {
					keys[m[1]] = strings.TrimPrefix(p, "../")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// O .env.example lista exatamente as chaves FS_* lidas pelo código de produção, sem falta nem sobra (task 084).
func TestEnvExampleMatchesCodeKeys(t *testing.T) {
	code := codeEnvKeys(t)
	if len(code) < 40 {
		t.Fatalf("só %d chaves no código: a extração quebrou?", len(code))
	}
	example, _ := envMap(t, "../.env.example")
	var missing, extra []string
	for k, where := range code {
		if _, ok := example[k]; !ok {
			missing = append(missing, k+" ("+where+")")
		}
	}
	for k := range example {
		if _, ok := code[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("chaves lidas pelo código e ausentes do .env.example:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("chaves do .env.example que o código não lê:\n  %s", strings.Join(extra, "\n  "))
	}
}

// Toda exceção de notEnvKeys ainda aparece no código (sem exceção morta escondendo uma chave futura).
func TestNotEnvKeysStillInCode(t *testing.T) {
	seen := map[string]bool{}
	for _, root := range []string{"../cmd", "../internal", "../pkg"} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, _ := os.ReadFile(p)
			for _, m := range fsKeyLiteral.FindAllStringSubmatch(string(b), -1) {
				seen[m[1]] = true
			}
			return nil
		})
	}
	for k, why := range notEnvKeys {
		if !seen[k] {
			t.Errorf("%s (%s) não aparece mais no código: tire de notEnvKeys", k, why)
		}
	}
}
