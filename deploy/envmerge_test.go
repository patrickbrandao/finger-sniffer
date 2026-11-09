package deploy

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runMerge executa deploy/env-merge.sh e devolve a saída combinada.
func runMerge(t *testing.T, example, target string) string {
	t.Helper()
	out, err := exec.Command("bash", "env-merge.sh", example, target).CombinedOutput()
	if err != nil {
		t.Fatalf("env-merge.sh: %v\n%s", err, out)
	}
	return string(out)
}

// envMap lê KEY=VALUE (a última ocorrência vale) e conta as ocorrências de cada chave.
func envMap(t *testing.T, path string) (map[string]string, map[string]int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	vals := map[string]string{}
	count := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[k] = v
		count[k]++
	}
	return vals, count
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestEnvMergeAddsMissingKeysOnce(t *testing.T) {
	dir := t.TempDir()
	example := filepath.Join(dir, "example")
	target := filepath.Join(dir, "target")
	writeFile(t, example, `# cabeçalho

# --- Seção A ---
FS_A=1
FS_B=novo

# --- Seção nova ---
# explicação de FS_C
FS_C=3
FS_EMPTY=
`, 0o644)
	// servidor: FS_B com valor antigo (deve ser mantido), FS_A já igual, sem newline final
	writeFile(t, target, "FS_A=1\nFS_B=antigo\nFS_LOCAL=x", 0o640)

	out := runMerge(t, example, target)
	if !strings.Contains(out, "acrescentada FS_C=3") || !strings.Contains(out, "acrescentada FS_EMPTY=") {
		t.Errorf("saída sem as chaves acrescentadas:\n%s", out)
	}
	if !strings.Contains(out, "aviso: FS_B=antigo") || !strings.Contains(out, "(novo)") {
		t.Errorf("saída sem o aviso de valor diferente:\n%s", out)
	}
	if strings.Contains(out, "FS_A=1 no servidor") {
		t.Errorf("aviso indevido para valor igual:\n%s", out)
	}

	vals, count := envMap(t, target)
	want := map[string]string{"FS_A": "1", "FS_B": "antigo", "FS_LOCAL": "x", "FS_C": "3", "FS_EMPTY": ""}
	for k, v := range want {
		if got, ok := vals[k]; !ok || got != v {
			t.Errorf("%s = %q (presente=%v), quer %q", k, got, ok, v)
		}
		if count[k] != 1 {
			t.Errorf("%s aparece %d vezes", k, count[k])
		}
	}
	raw, _ := os.ReadFile(target)
	if !strings.Contains(string(raw), "# explicação de FS_C\nFS_C=3") {
		t.Errorf("comentário de FS_C não acompanhou a chave:\n%s", raw)
	}
	if strings.Contains(string(raw), "# cabeçalho") {
		t.Errorf("cabeçalho separado por linha em branco não deveria ser copiado:\n%s", raw)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("modo mudou para %v", st.Mode().Perm())
	}

	// segunda execução: nada acrescentado, arquivo idêntico
	out2 := runMerge(t, example, target)
	if strings.Contains(out2, "acrescentada") {
		t.Errorf("segunda execução acrescentou chaves:\n%s", out2)
	}
	raw2, _ := os.ReadFile(target)
	if string(raw2) != string(raw) {
		t.Errorf("segunda execução mudou o arquivo:\nantes:\n%s\ndepois:\n%s", raw, raw2)
	}
}

// O .env.example real aplicado sobre o env da F2 traz as chaves da F3 e avisa do FS_RAW_BODY_MAX_BYTES antigo.
func TestEnvMergeRealExampleOverF2Env(t *testing.T) {
	example := filepath.Join("..", ".env.example")
	dir := t.TempDir()
	target := filepath.Join(dir, "finger-sniffer.env")
	exampleVals, _ := envMap(t, example)

	var b strings.Builder
	for k, v := range exampleVals {
		switch k {
		case "FS_ACME_ENABLE", "FS_ACME_DIR", "FS_EVENT_INLINE_MAX", "FS_RAW_STREAM_MAX_BYTES":
			continue // chaves que não existiam na F2
		case "FS_RAW_BODY_MAX_BYTES":
			v = "1048576"
		}
		b.WriteString(k + "=" + v + "\n")
	}
	writeFile(t, target, b.String(), 0o640)

	out := runMerge(t, example, target)
	if !strings.Contains(out, "aviso: FS_RAW_BODY_MAX_BYTES=1048576") {
		t.Errorf("sem aviso para FS_RAW_BODY_MAX_BYTES:\n%s", out)
	}
	vals, count := envMap(t, target)
	for k, v := range map[string]string{
		"FS_ACME_ENABLE":          "0",
		"FS_ACME_DIR":             "/finger-sniffer/var/acme",
		"FS_EVENT_INLINE_MAX":     "131072",
		"FS_RAW_STREAM_MAX_BYTES": "16777216",
		"FS_RAW_BODY_MAX_BYTES":   "1048576",
	} {
		if vals[k] != v || count[k] != 1 {
			t.Errorf("%s = %q (%d vezes), quer %q uma vez", k, vals[k], count[k], v)
		}
	}
	if out2 := runMerge(t, example, target); strings.Contains(out2, "acrescentada") {
		t.Errorf("segunda execução acrescentou chaves:\n%s", out2)
	}
}

func TestEnvMergeUsage(t *testing.T) {
	if err := exec.Command("bash", "env-merge.sh", "/nao/existe", "/nao/existe").Run(); err == nil {
		t.Error("esperava erro com arquivos inexistentes")
	}
}
