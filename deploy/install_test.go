package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installHarness carrega install-lib.sh com systemd e /proc falsos em $T: cada unit "roda" a cópia do
// binário feita no reinício ($T/proc/<pid>/exe), como o kernel mantém o inode antigo depois do rename.
const installHarness = `
set -euo pipefail
. ./install-lib.sh
T=$1
shift
export FS_PROC_ROOT=$T/proc
main_pid() { cat "$T/pids/$1" 2>/dev/null || echo 0; }
unit_active() { [ "$(main_pid "$1")" != 0 ]; }
mkdir -p "$T/staging/bin" "$T/dest/bin" "$T/pids" "$T/proc"
[ -f "$T/dest/bin/nats-server" ] || printf 'nats' >"$T/dest/bin/nats-server"
[ -f "$T/nextpid" ] || echo 100 >"$T/nextpid"

# deploy <commit> <svc>: build do commit no staging, instala, planeja e "reinicia"; imprime as units reiniciadas
deploy() {
	local s u why pid
	for s in $FS_SERVICES; do printf 'bin %s %s' "$s" "$1" >"$T/staging/bin/finger-sniffer-$s"; done
	install_binaries "$T/staging" "$T/dest" "$2" >/dev/null
	plan_restarts "$T/dest" "$2" >"$T/plan"
	while IFS=$'\t' read -r u why; do
		pid=$(cat "$T/nextpid")
		echo $((pid + 1)) >"$T/nextpid"
		mkdir -p "$T/proc/$pid"
		cp "$(unit_binary "$T/dest" "$u")" "$T/proc/$pid/exe"
		echo "$pid" >"$T/pids/$u"
	done <"$T/plan"
	echo "restart: $(cut -f1 "$T/plan" | sed 's/finger-sniffer-//' | tr '\n' ' ')"
}

# versions: commit em execução e em disco de cada serviço
versions() {
	local s
	for s in $FS_SERVICES; do
		echo "$s run=$(cut -d' ' -f3 "$T/proc/$(main_pid "finger-sniffer-$s")/exe") disk=$(cut -d' ' -f3 "$T/dest/bin/finger-sniffer-$s")"
	done
}

"$@"
`

// harness roda um comando do installHarness no sandbox t.
func harness(t *testing.T, sandbox string, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"-c", installHarness, "harness", sandbox}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestDeploySVCThenFullConvergesVersions(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash ausente")
	}
	T := t.TempDir()

	// vps limpa: tudo parado, todos sobem
	if got := harness(t, T, "deploy", "A", ""); got != "restart: nats store capture web raw dns" {
		t.Fatalf("primeiro deploy: %q", got)
	}

	// SVC=web de outro commit: instala e reinicia só o web; os outros binários em disco ficam no A
	if got := harness(t, T, "deploy", "B", "web"); got != "restart: web" {
		t.Fatalf("SVC=web: %q", got)
	}
	v := harness(t, T, "versions")
	for _, want := range []string{"web run=B disk=B", "store run=A disk=A", "capture run=A disk=A", "dns run=A disk=A"} {
		if !strings.Contains(v, want) {
			t.Errorf("depois do SVC=web, sem %q:\n%s", want, v)
		}
	}

	// deploy completo do mesmo commit: reinicia só quem roda outro binário (o web já está no B)
	if got := harness(t, T, "deploy", "B", ""); got != "restart: store capture raw dns" {
		t.Fatalf("deploy completo: %q", got)
	}
	v = harness(t, T, "versions")
	if strings.Contains(v, "=A") {
		t.Fatalf("versões desencontradas depois do deploy completo:\n%s", v)
	}

	// mesmo commit outra vez: nada a fazer
	if got := harness(t, T, "deploy", "B", ""); got != "restart:" {
		t.Fatalf("deploy repetido: %q", got)
	}
}

func TestDeployRestartsWhenRunningBinaryDiffersFromDisk(t *testing.T) {
	// o estado da auditoria: disco no B (rsync antigo de todo o bin/), processos ainda no A
	T := t.TempDir()
	harness(t, T, "deploy", "A", "")
	for _, s := range []string{"store", "capture", "web", "raw", "dns"} {
		if err := os.WriteFile(filepath.Join(T, "dest/bin/finger-sniffer-"+s), []byte("bin "+s+" B"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := harness(t, T, "deploy", "B", ""); got != "restart: store capture web raw dns" {
		t.Fatalf("o disco já igual ao staging não pode esconder o binário antigo em execução: %q", got)
	}
	// com SVC também: o serviço desencontrado é reiniciado
	if err := os.WriteFile(filepath.Join(T, "dest/bin/finger-sniffer-raw"), []byte("bin raw C"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := harness(t, T, "deploy", "B", "dns"); got != "restart: raw dns" {
		t.Fatalf("SVC=dns com o raw desencontrado: %q", got)
	}
}

func TestPlanRestartsReasonsWithoutDrift(t *testing.T) {
	T := t.TempDir()
	harness(t, T, "deploy", "A", "")
	cases := []struct {
		env  []string
		svc  string
		want string
	}{
		{nil, "", ""},
		{[]string{"FORCE=1"}, "", "nats store capture web raw dns"},
		{[]string{"ENV_CHANGED=1"}, "", "store capture web raw dns"},
		{[]string{"NATS_CONF_CHANGED=1"}, "", "nats"},
		{[]string{"FORCE=1"}, "nats", "nats"},
		{nil, "store", "store"},
	}
	for _, c := range cases {
		cmd := exec.Command("bash", "-c", installHarness+`
plan_restarts "$T/dest" "$SVCX" | cut -f1 | sed 's/finger-sniffer-//' | tr '\n' ' '`, "harness", T, "true")
		cmd.Env = append(append(os.Environ(), "SVCX="+c.svc), c.env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", c, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("env=%v svc=%q: %q, quer %q", c.env, c.svc, got, c.want)
		}
	}
}

func TestBinariesFor(t *testing.T) {
	cases := map[string]string{
		"":     "finger-sniffer-store finger-sniffer-capture finger-sniffer-web finger-sniffer-raw finger-sniffer-dns",
		"web":  "finger-sniffer-web",
		"nats": "",
	}
	for svc, want := range cases {
		out, err := exec.Command("bash", "-c", `. ./install-lib.sh; binaries_for "$1" | tr '\n' ' '`, "x", svc).CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("SVC=%q: %q, quer %q", svc, got, want)
		}
	}
}

func TestInstallHtdocsOnlyServableFiles(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync ausente")
	}
	T := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(T, "staging/htdocs/index.html"), "<html>")
	write(filepath.Join(T, "staging/htdocs/app.mjs"), "x")
	write(filepath.Join(T, "staging/htdocs/app_test.go"), "package htdocs")
	write(filepath.Join(T, "staging/htdocs/testdata/fixture.txt"), "x")
	// sobras de um deploy antigo (rsync da árvore inteira)
	write(filepath.Join(T, "dest/htdocs/htdocs_test.go"), "package htdocs")
	write(filepath.Join(T, "dest/htdocs/gone.html"), "x")

	out, err := exec.Command("bash", "-c", `. ./install-lib.sh; install_htdocs "$1/staging" "$1/dest"`, "x", T).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got []string
	_ = filepath.Walk(filepath.Join(T, "dest/htdocs"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(T, "dest/htdocs"), p)
			got = append(got, rel)
			if info.Mode().Perm()&0o004 == 0 {
				t.Errorf("%s sem leitura para todos: %v", rel, info.Mode())
			}
		}
		return nil
	})
	if strings.Join(got, " ") != "app.mjs index.html" {
		t.Fatalf("htdocs instalado: %v", got)
	}
}
