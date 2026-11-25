package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// readUpSh devolve as linhas do up.sh.
func readUpSh(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../up.sh")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(b), "\n")
}

// TestUpShDirOnlyAfterLock confere que a pasta do teste no servidor só nasce com a trava da carga na mão (task
// 406): antes, o mkdir vinha antes da espera e uma espera vencida deixava a pasta para trás.
func TestUpShDirOnlyAfterLock(t *testing.T) {
	lines := readUpSh(t)
	lockAt, mkdirs := -1, 0
	for i, l := range lines {
		if strings.Contains(l, `set -C; echo '$token' > '$LOCK'`) {
			lockAt = i
		}
		if strings.Contains(l, "mkdir") && strings.Contains(l, "$DIR") {
			mkdirs++
			if lockAt < 0 || i < lockAt {
				t.Errorf("up.sh:%d cria $DIR antes de tomar a trava: %s", i+1, strings.TrimSpace(l))
			}
			if !strings.Contains(l, "lock.token") {
				t.Errorf("up.sh:%d cria $DIR fora do comando que grava o lock.token: %s", i+1, strings.TrimSpace(l))
			}
		}
	}
	if lockAt < 0 {
		t.Fatal("up.sh sem a tomada atômica da trava (set -C)")
	}
	if mkdirs != 1 {
		t.Errorf("up.sh cria $DIR em %d lugares, esperado 1 (junto do lock.token)", mkdirs)
	}
}

// recorderLaunch extrai do up.sh o comando remoto que sobe o gravador, já como o bash do servidor o recebe (sem a
// continuação de linha e com \$ virando $), e troca $DIR por dir.
func recorderLaunch(t *testing.T, dir string) string {
	t.Helper()
	lines := readUpSh(t)
	for i, l := range lines {
		if !strings.Contains(l, `ssh_vps "cd $DIR`) || !strings.Contains(l, "recorder") {
			continue
		}
		s := strings.TrimSpace(l)
		for strings.HasSuffix(s, `\`) && i+1 < len(lines) {
			i++
			s = strings.TrimSuffix(s, `\`) + strings.TrimSpace(lines[i])
		}
		s = strings.TrimPrefix(s, `ssh_vps "`)
		s = strings.TrimSuffix(s, `"`)
		s = strings.ReplaceAll(s, `\$`, "$")
		return strings.ReplaceAll(s, "$DIR", dir)
	}
	t.Fatal("up.sh sem o comando que sobe o gravador")
	return ""
}

// TestUpShRecorderLaunchDetaches roda o comando de subida do gravador do up.sh como o ssh o roda (saídas em pipe) e
// confere que ele volta logo e que o recorder.pid é o do gravador (task 406). Em "cd && setsid ... &" o "&" valia
// para a lista inteira: o subshell que sobrava segurava os pipes (o ssh não voltava) e era ele quem ia no $!.
func TestUpShRecorderLaunchDetaches(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("sem bash")
	}
	dir := t.TempDir()
	bin := t.TempDir()
	// gravador falso: grava o próprio pid em real.pid e fica vivo
	if err := os.WriteFile(filepath.Join(dir, "recorder"), []byte("#!/bin/sh\necho $$ > \"$(dirname \"$0\")/real.pid\"\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("PATH")
	if _, err := exec.LookPath("setsid"); err != nil {
		// macOS não tem setsid; o calço só repassa (o que se testa aqui são os descritores e o $!)
		if err := os.WriteFile(filepath.Join(bin, "setsid"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		path = bin + string(os.PathListSeparator) + path
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", recorderLaunch(t, dir))
	cmd.Env = append(os.Environ(), "PATH="+path)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out // pipes, como os do ssh
	cmd.WaitDelay = 3 * time.Second     // pipe ainda aberto 3 s depois do fim do bash: o ssh ficaria preso
	err := cmd.Run()

	// real.pid sai do gravador falso logo depois do fork; espera um pouco por ele
	readPid := func(name string) int {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if n, cerr := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && cerr == nil && n > 0 {
				return n
			}
		}
		return 0
	}
	pid, real := readPid("recorder.pid"), readPid("real.pid")
	defer func() {
		for _, p := range []int{real, pid} {
			if p > 0 {
				_ = syscall.Kill(p, syscall.SIGKILL)
			}
		}
	}()
	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("o comando de subida do gravador não solta os pipes (o ssh do up.sh não voltaria): %q", out.String())
	}
	if err != nil {
		t.Fatalf("subida do gravador: %v (%q)", err, out.String())
	}
	if pid == 0 || real == 0 {
		t.Fatalf("recorder.pid %d, pid do gravador %d: um deles não foi gravado", pid, real)
	}
	if pid != real {
		t.Errorf("recorder.pid %d, mas o gravador é o %d (o down.sh mataria o processo errado)", pid, real)
	}
}
