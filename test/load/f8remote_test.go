package load

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubs do f8-remote.sh (task 396, ADR 0071): systemd-run registra os argumentos e lê a primeira linha da entrada
// padrão (como o botload lê a chave); systemctl guarda as units num arquivo; runuser faz o papel da CLI do bot.
var f8Stubs = map[string]string{
	"systemd-run": `#!/usr/bin/env bash
echo "systemd-run $*" >>"$STUB_LOG"
unit=
for a in "$@"; do
	case "$a" in
	--unit=*) unit=${a#--unit=} ;;
	StandardInput=file:*) head -n1 "${a#StandardInput=file:}" >"$STUB_DIR/stdin-$unit" ;;
	esac
done
echo "$unit.service" >>"$STUB_DIR/units"
`,
	"systemctl": `#!/usr/bin/env bash
echo "systemctl $*" >>"$STUB_LOG"
touch "$STUB_DIR/units"
case "$1" in
list-units) cat "$STUB_DIR/units" ;;
stop) grep -vx -e "$2" -e "$2.service" "$STUB_DIR/units" >"$STUB_DIR/u.tmp" || true; mv "$STUB_DIR/u.tmp" "$STUB_DIR/units" ;;
is-active) echo active ;;
esac
`,
	"runuser": `#!/usr/bin/env bash
echo "runuser $*" >>"$STUB_LOG"
case "$*" in
*"key create"*) printf 'id: k1\nkey: fsk_secret123\n' ;;
*"key list"*) printf 'k9 site load-f8-old-1 -\nk8 site other -\n' ;;
esac
`,
	"sleep":  "#!/bin/sh\nexit 0\n",
	"docker": "#!/bin/sh\necho \"docker $*\" >>\"$STUB_LOG\"\nexit 1\n",
}

type f8Env struct{ dir, log, bin string }

func newF8Env(t *testing.T) f8Env {
	t.Helper()
	dir := t.TempDir()
	stubBin := filepath.Join(dir, "stubs")
	if err := os.Mkdir(stubBin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range f8Stubs {
		if err := os.WriteFile(filepath.Join(stubBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	work := filepath.Join(dir, "fs-load-f8")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "botload"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f8Env{dir: dir, log: filepath.Join(dir, "stub.log"), bin: stubBin}
}

func (e f8Env) run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"f8-remote.sh"}, args...)...)
	cmd.Env = []string{
		"PATH=" + e.bin + string(os.PathListSeparator) + "/usr/bin:/bin", "HOME=" + e.dir,
		"STUB_LOG=" + e.log, "STUB_DIR=" + e.dir,
		"FS_LOAD_F8_DIR=" + filepath.Join(e.dir, "fs-load-f8"),
		"FS_LOAD_F8_BIN=" + filepath.Join(e.dir, "finger-sniffer", "tmp", "fs-load-f8-botload"),
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("f8-remote.sh %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (e f8Env) stubLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(e.log)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestF8RemoteTransientUnit confere o ciclo install → start → start-nokey → cleanup: units transitórias
// finger-sniffer-load-f8-* com os limites da ADR 0071, fora de finger-sniffer.slice, chave só pela entrada
// padrão, nada de Docker, e no fim nenhuma unit, binário ou FIFO.
func TestF8RemoteTransientUnit(t *testing.T) {
	e := newF8Env(t)
	e.run(t, "install")
	bin := filepath.Join(e.dir, "finger-sniffer", "tmp", "fs-load-f8-botload")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("binário não instalado: %v", err)
	}
	e.run(t, "start", "auth", "auth", "-duration", "5s", "-rate", "5")
	e.run(t, "start-nokey", "feed", "feed", "-duration", "5s")

	log := e.stubLog(t)
	for _, want := range []string{
		"--unit=finger-sniffer-load-f8-auth --collect", "--unit=finger-sniffer-load-f8-feed --collect",
		"-p CPUQuota=100% -p MemoryMax=1G -p MemorySwapMax=0", "StandardInput=null",
		bin + " auth -out " + filepath.Join(e.dir, "fs-load-f8", "out-auth") + " -duration 5s -rate 5",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("chamadas sem %q:\n%s", want, log)
		}
	}
	for _, bad := range []string{"docker", "--slice", "finger-sniffer.slice", "fsk_secret123"} {
		if strings.Contains(log, bad) {
			t.Errorf("chamadas com %q:\n%s", bad, log)
		}
	}
	key, err := os.ReadFile(filepath.Join(e.dir, "stdin-finger-sniffer-load-f8-auth"))
	if err != nil || strings.TrimSpace(string(key)) != "fsk_secret123" {
		t.Fatalf("a unit não recebeu a chave pela entrada padrão: %q %v", key, err)
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, "fs-load-f8", "key.*")); len(left) > 0 {
		t.Errorf("FIFO da chave ficou para trás: %v", left)
	}

	out := e.run(t, "cleanup")
	if units, _ := os.ReadFile(filepath.Join(e.dir, "units")); strings.TrimSpace(string(units)) != "" {
		t.Errorf("units sobraram depois do cleanup: %q", units)
	}
	if _, err := os.Stat(bin); !os.IsNotExist(err) {
		t.Errorf("binário não apagado: %v", err)
	}
	for _, want := range []string{"chave k1 revogada", "chave k9 revogada"} {
		if !strings.Contains(out, want) {
			t.Errorf("cleanup sem %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "k8") {
		t.Errorf("cleanup revogou chave que não é da carga:\n%s", out)
	}
}
