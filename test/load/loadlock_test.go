package load

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH ignora -p/-o e o destino e roda o comando "remoto" aqui: o servidor é esta máquina, com a trava e o
// diretório remoto num diretório temporário. pkill e sleep são stubs (pkill só registra a chamada em $PKILL_LOG).
const fakeSSH = `#!/usr/bin/env bash
while [ $# -gt 0 ]; do
	case "$1" in
	-p | -o) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
shift
exec bash -c "$*"
`

type lockEnv struct {
	dir, lock, remote, pkillLog string
	env                         []string
}

func newLockEnv(t *testing.T) lockEnv {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stubs := map[string]string{
		"ssh":   fakeSSH,
		"pkill": "#!/bin/sh\necho \"pkill $*\" >>\"$PKILL_LOG\"\nexit 0\n",
		"sleep": "#!/bin/sh\nexit 0\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := lockEnv{
		dir: dir, lock: filepath.Join(dir, "fs-load-running"), remote: filepath.Join(dir, "fs-load"),
		pkillLog: filepath.Join(dir, "pkill.log"),
	}
	e.env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + "/usr/bin:/bin", "HOME=" + dir,
		"FS_LOAD_LOCK=" + e.lock, "PKILL_LOG=" + e.pkillLog, "REMOTE_DIR=" + e.remote,
	}
	return e
}

// run executa uma "carga" num processo bash próprio (outro $$, outro token): carrega loadlock.sh, toma a trava e
// roda body; o trap EXIT devolve a trava como no run.sh. Devolve o código de saída e a saída.
func (e lockEnv) run(t *testing.T, body string, env ...string) (int, string) {
	t.Helper()
	script := `ssh_vps() { ssh -p 1 -o BatchMode=yes root@load-test.invalid "$@"; }
REMOTE="$REMOTE_DIR"
. ./loadlock.sh
trap load_lock_release EXIT
load_lock_take || exit 1
mkdir -p "$REMOTE"
` + body
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(append([]string{}, e.env...), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("bash: %v\n%s", err, out)
		}
		return ee.ExitCode(), string(out)
	}
	return 0, string(out)
}

func (e lockEnv) read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// Uma carga em andamento (trava e diretório remoto presentes) e uma segunda que começa: a segunda recusa, não para o
// loadmon da primeira e, ao sair, não apaga a trava nem o diretório dela (spec 017 RF-13, task 361).
func TestLoadLockSecondRunRefusesWithoutTouchingFirst(t *testing.T) {
	e := newLockEnv(t)
	// a primeira "fica rodando": toma a trava e sai sem devolvê-la
	if code, out := e.run(t, "touch \"$REMOTE/cgroup.csv\"\ntrap - EXIT\n"); code != 0 {
		t.Fatalf("primeira carga: %d\n%s", code, out)
	}
	first := e.read(t, e.lock)
	if first == "" {
		t.Fatal("a primeira carga não gravou a trava")
	}
	code, out := e.run(t, "echo segunda-rodou\n")
	if code == 0 || strings.Contains(out, "segunda-rodou") || !strings.Contains(out, "outra carga em andamento") {
		t.Errorf("a segunda carga não recusou: %d\n%s", code, out)
	}
	if got := e.read(t, e.lock); got != first {
		t.Errorf("trava trocada pela segunda carga: %q, era %q", got, first)
	}
	if _, err := os.Stat(filepath.Join(e.remote, "cgroup.csv")); err != nil {
		t.Errorf("a segunda carga apagou o diretório da primeira: %v", err)
	}
	if got := e.read(t, e.pkillLog); got != "" {
		t.Errorf("a segunda carga parou o loadmon da primeira: %q", got)
	}
}

// Quem tomou a trava a devolve no fim (para o loadmon, apaga o diretório e a trava); se a trava foi regravada por outro
// no meio, o fim não a apaga.
func TestLoadLockReleaseOnlyOwnToken(t *testing.T) {
	e := newLockEnv(t)
	if code, out := e.run(t, ""); code != 0 {
		t.Fatalf("carga: %d\n%s", code, out)
	}
	if e.read(t, e.lock) != "" {
		t.Error("a trava ficou depois do fim da carga")
	}
	if _, err := os.Stat(e.remote); !os.IsNotExist(err) {
		t.Errorf("o diretório remoto ficou: %v", err)
	}
	if !strings.Contains(e.read(t, e.pkillLog), "[l]oadmon sample") {
		t.Error("o fim da carga não parou o loadmon")
	}
	if code, out := e.run(t, "echo outro-dono >\"$FS_LOAD_LOCK\"\n"); code != 0 {
		t.Fatalf("carga: %d\n%s", code, out)
	}
	if got := strings.TrimSpace(e.read(t, e.lock)); got != "outro-dono" {
		t.Errorf("a trava de outro dono foi apagada: %q", got)
	}
}

// FS_LOAD_LOCK_HELD=1 (vigia da mesma carga segurando a trava, como o f8-side.sh): sem a trava, recusa; com ela, roda
// e no fim para o loadmon e apaga o diretório, mas deixa a trava para o vigia.
func TestLoadLockHeldByWatcher(t *testing.T) {
	e := newLockEnv(t)
	code, out := e.run(t, "echo rodou\n", "FS_LOAD_LOCK_HELD=1")
	if code == 0 || strings.Contains(out, "rodou") || !strings.Contains(out, "não existe") {
		t.Errorf("FS_LOAD_LOCK_HELD=1 sem trava não recusou: %d\n%s", code, out)
	}
	if err := os.WriteFile(e.lock, []byte("vigia\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := e.run(t, "echo rodou\n", "FS_LOAD_LOCK_HELD=1"); code != 0 || !strings.Contains(out, "rodou") {
		t.Fatalf("FS_LOAD_LOCK_HELD=1 com trava: %d\n%s", code, out)
	}
	if got := strings.TrimSpace(e.read(t, e.lock)); got != "vigia" {
		t.Errorf("a trava do vigia foi apagada ou trocada: %q", got)
	}
	if _, err := os.Stat(e.remote); !os.IsNotExist(err) {
		t.Errorf("o diretório remoto ficou: %v", err)
	}
	if !strings.Contains(e.read(t, e.pkillLog), "[l]oadmon sample") {
		t.Error("o fim da carga não parou o loadmon")
	}
}

// run.sh e budget.sh usam a trava comum e tomam-na antes de qualquer outra coisa no servidor; o pkill do loadmon só
// vem depois de ela ser nossa.
func TestLoadScriptsUseLoadLock(t *testing.T) {
	for _, name := range []string{"run.sh", "budget.sh"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		take := strings.Index(s, "load_lock_take || exit 1")
		if !strings.Contains(s, ". \"$ROOT/test/load/loadlock.sh\"") || !strings.Contains(s, "trap load_lock_release EXIT") ||
			take < 0 {
			t.Errorf("%s sem a trava comum (loadlock.sh, trap e load_lock_take)", name)
			continue
		}
		if i := strings.Index(s, "pkill"); i >= 0 && i < take {
			t.Errorf("%s para o loadmon antes de tomar a trava", name)
		}
		if strings.Contains(s, "> $LOCK") || strings.Contains(s, "rm -rf $REMOTE $LOCK") {
			t.Errorf("%s ainda grava ou apaga a trava por conta própria", name)
		}
	}
}
