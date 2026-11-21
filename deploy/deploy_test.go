package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// deployTargets roda deploy.sh só para mostrar os alvos resolvidos (FS_DEPLOY_PRINT_TARGETS=1: sem build nem ssh).
func deployTargets(t *testing.T, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", "deploy.sh")
	// sem herdar destinos do ambiente de quem roda o teste
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "FS_VPS_") && !strings.HasPrefix(kv, "FS_SMOKE_") && !strings.HasPrefix(kv, "SVC=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "FS_DEPLOY_PRINT_TARGETS=1")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deploy.sh: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// ADR 0038 (task 224): o deploy vai para o finger-01 por padrão e o h3 do Mac usa a UDP 8443.
func TestDeployDefaultsFinger01(t *testing.T) {
	want := "host=root@finger-01.tmsoft.com.br port=48022 h3=finger-01.badblock.net.br:8443"
	if got := deployTargets(t); got != want {
		t.Errorf("padrões:\n got %s\nwant %s", got, want)
	}
	want = "host=root@outro.example port=22 h3=x.example:9443"
	got := deployTargets(t, "FS_VPS_SSH=root@outro.example", "FS_VPS_PORT=22", "FS_SMOKE_NAME=x.example",
		"FS_SMOKE_H3_PORT=9443")
	if got != want {
		t.Errorf("com variáveis:\n got %s\nwant %s", got, want)
	}
}

// O rsync do repositório para o servidor não leva os worktrees dos agentes (.claude/, dezenas de GB) nem o que é
// só local (task 294).
func TestDeployRsyncExcludesLocalDirs(t *testing.T) {
	b, err := os.ReadFile("deploy.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"--exclude='/.claude/'", "--exclude='/.git'", "--exclude='/tasks/'", "--exclude='/tmp/'"} {
		if !strings.Contains(s, want) {
			t.Errorf("deploy.sh sem %q no rsync", want)
		}
	}
}

// fakeSSHLocal troca o ssh do deploy: ignora -p/-o e o destino e roda o comando remoto aqui (o "servidor" é esta
// máquina; a trava vem de FS_LOAD_LOCK, num diretório temporário). make e rsync só registram a chamada em $FAKE_LOG.
const fakeSSHLocal = `#!/usr/bin/env bash
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

// deployDuringLoad roda deploy.sh com o ssh local e make/rsync falsos (make falha, para o deploy parar logo depois
// do build); devolve o código de saída, a saída e as chamadas registradas.
func deployDuringLoad(t *testing.T, lockPresent bool, env ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls.log")
	writeFile(t, filepath.Join(bin, "ssh"), fakeSSHLocal, 0o755)
	writeFile(t, filepath.Join(bin, "make"), "#!/bin/sh\necho make >>\"$FAKE_LOG\"\nexit 1\n", 0o755)
	writeFile(t, filepath.Join(bin, "rsync"), "#!/bin/sh\necho rsync >>\"$FAKE_LOG\"\nexit 1\n", 0o755)
	lock := filepath.Join(dir, "fs-load-running")
	if lockPresent {
		writeFile(t, lock, "2026-11-21T10:00:00Z\n", 0o644)
	}
	cmd := exec.Command("bash", "deploy.sh")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "FS_") && !strings.HasPrefix(kv, "SVC=") && !strings.HasPrefix(kv, "FORCE") &&
			!strings.HasPrefix(kv, "PATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+"/usr/bin:/bin", "FAKE_LOG="+log,
		"FS_LOAD_LOCK="+lock, "FS_VPS_SSH=root@deploy-test.invalid")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("deploy.sh: %v\n%s", err, out)
		}
		code = ee.ExitCode()
	}
	calls, _ := os.ReadFile(log)
	return code, string(out), string(calls)
}

// Com a trava da carga no servidor o deploy sai 3 antes do build, com a data da trava na mensagem (spec 017 RF-13,
// task 361); sem ela, ou com FORCE_DURING_LOAD=1, segue para o build.
func TestDeployRefusesDuringLoad(t *testing.T) {
	code, out, calls := deployDuringLoad(t, true)
	if code != 3 || !strings.Contains(out, "deploy recusado") || !strings.Contains(out, "2026-11-21T10:00:00Z") {
		t.Errorf("com a trava: código %d, quer 3 com a mensagem\n%s", code, out)
	}
	if strings.Contains(calls, "make") {
		t.Errorf("com a trava o build rodou: %q", calls)
	}
	for _, c := range []struct {
		name string
		lock bool
		env  []string
	}{
		{"sem trava", false, nil},
		{"trava com FORCE_DURING_LOAD=1", true, []string{"FORCE_DURING_LOAD=1"}},
	} {
		code, out, calls := deployDuringLoad(t, c.lock, c.env...)
		if code == 3 || strings.Contains(out, "deploy recusado") || !strings.Contains(calls, "make") {
			t.Errorf("%s: código %d, chamadas %q (quer o build)\n%s", c.name, code, calls, out)
		}
	}
}

// load_lock_refuse (install-lib.sh, chamada pelo remote-install.sh já sob a trava do deploy): 3 com a trava, 0 sem
// ela ou com FORCE_DURING_LOAD=1; e o remote-install.sh a chama antes de instalar qualquer coisa.
func TestLoadLockRefuse(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "fs-load-running")
	writeFile(t, lock, "x\n", 0o644)
	for _, c := range []struct {
		script, want string
	}{
		{`load_lock_refuse "$1" 2>/dev/null; echo $?`, "3"},
		{`FORCE_DURING_LOAD=1 load_lock_refuse "$1"; echo $?`, "0"},
		{`load_lock_refuse "$1.nao-existe"; echo $?`, "0"},
	} {
		if got := libBash(t, dir, c.script, lock); got != c.want {
			t.Errorf("%s: %q, quer %q", c.script, got, c.want)
		}
	}
	b, err := os.ReadFile("remote-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i, j := strings.Index(s, "load_lock_refuse"), strings.Index(s, "missing_packages")
	if i < 0 || j < 0 || i > j {
		t.Errorf("remote-install.sh precisa chamar load_lock_refuse antes do bootstrap (%d, %d)", i, j)
	}
}
