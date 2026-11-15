package deploy

import (
	"os"
	"os/exec"
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
