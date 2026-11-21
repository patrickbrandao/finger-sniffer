package golden

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH registra cada comando remoto em $FAKE_LOG e simula a qdisc raiz da ens192: $FAKE_ROOT até o netem_on pôr
// a prio 1: (guardada em $FAKE_STATE), de volta a $FAKE_ROOT depois do "del root". Nada é executado.
const fakeSSH = `#!/bin/bash
cmd="${@: -1}"
printf '%s\n' "$cmd" >>"$FAKE_LOG"
case "$cmd" in
*SSH_CLIENT*) [ "$1" = -6 ] && exit 255; echo 203.0.113.5; exit 0 ;;
esac
case "$cmd" in
*"tc qdisc add dev ens192 root handle 1: prio"*) echo "qdisc prio 1: root refcnt 2 bands 3" >"$FAKE_STATE" ;;
*"tc qdisc del dev ens192 root"*) rm -f "$FAKE_STATE" ;;
esac
case "$cmd" in
*"tc qdisc show dev ens192 root"*) if [ -f "$FAKE_STATE" ]; then cat "$FAKE_STATE"; else echo "$FAKE_ROOT"; fi ;;
*"getent ahostsv4"*) echo 192.0.2.80 ;;
*"getent ahostsv6"*) echo 2001:db8::80 ;;
*"pgrep -fc"*) echo 0; echo 0; case "$cmd" in *"grep -c netem"*) echo 0 ;; esac ;;
esac
exit 0
`

// stubs: o resto do que o script chama no Mac. python3 -c conta 0 pacotes (o caso é descartado sem tocar em pcaps/),
// perl (o "limit" dos navegadores) falha, sleep volta na hora.
var stubs = map[string]string{
	"ssh":     fakeSSH,
	"scp":     "#!/bin/bash\nexit 0\n",
	"curl":    "#!/bin/bash\n[ \"$1\" = --version ] && echo 'curl 8.0.0'\nexit 0\n",
	"go":      "#!/bin/bash\n[ \"$1\" = version ] && echo 'go version go1.27'\nexit 0\n",
	"python3": "#!/bin/bash\n[ \"$1\" = -c ] && echo 0\nexit 0\n",
	"perl":    "#!/bin/bash\nexit 1\n",
	"sleep":   "#!/bin/bash\nexit 0\n",
	"sw_vers": "#!/bin/bash\necho 15.0\n",
}

// runCollect roda o collect.sh com os stubs e devolve a saída e os comandos remotos enviados.
func runCollect(t *testing.T, root string, env ...string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out")
	log := filepath.Join(dir, "ssh.log")
	cmd := exec.Command("bash", "collect.sh")
	// sem herdar variáveis do ambiente de quem roda o teste (nada de destino real)
	cmd.Env = append([]string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"HOME=" + dir,
		"TMPDIR=" + dir,
		"FS_GOLDEN_OUT=" + out,
		"FAKE_LOG=" + log,
		"FAKE_STATE=" + filepath.Join(dir, "qdisc"),
		"FAKE_ROOT=" + root,
		"CHROME_BIN=" + filepath.Join(dir, "sem-chrome"),
		"FIREFOX_BIN=" + filepath.Join(dir, "sem-firefox"),
		"VPS_SSH=root@golden.invalid",
	}, env...)
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("collect.sh: %v\n%s", err, got)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return string(got), strings.Split(strings.TrimSpace(string(b)), "\n")
}

func count(cmds []string, sub string) int {
	n := 0
	for _, c := range cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

// Sem FS_GOLDEN_NETEM o caso de retransmissão é pulado e nenhum comando tc vai ao servidor, nem no cleanup (task 357,
// ADR 0038 item 9): a qdisc raiz da ens192, qualquer que seja, não é lida nem apagada.
func TestCollectWithoutNetemSendsNoTC(t *testing.T) {
	out, cmds := runCollect(t, "qdisc htb 1: root refcnt 17 r2q 10 default 0x10")
	if n := count(cmds, "tc "); n != 0 {
		t.Errorf("%d comandos com tc sem FS_GOLDEN_NETEM:\n%s", n, strings.Join(cmds, "\n"))
	}
	if !strings.Contains(out, "retransmit-macos pulado") {
		t.Errorf("sem o aviso do caso pulado:\n%s", out)
	}
	if !strings.Contains(out, "servidor limpo") {
		t.Errorf("sem a conferência do cleanup:\n%s", out)
	}
}

// Com FS_GOLDEN_NETEM=1 mas uma raiz configurada no host (handle diferente de 0:), o netem não é ligado e a raiz não
// é apagada: nem pelo caso, nem pelo cleanup.
func TestCollectNetemKeepsForeignRoot(t *testing.T) {
	out, cmds := runCollect(t, "qdisc htb 1: root refcnt 17 r2q 10 default 0x10", "FS_GOLDEN_NETEM=1")
	if n := count(cmds, "tc qdisc add"); n != 0 {
		t.Errorf("netem ligado sobre raiz alheia (%d add)", n)
	}
	if n := count(cmds, "tc qdisc del"); n != 0 {
		t.Errorf("raiz alheia apagada (%d del):\n%s", n, strings.Join(cmds, "\n"))
	}
	if !strings.Contains(out, "netem não ligado") {
		t.Errorf("sem o aviso da raiz alheia:\n%s", out)
	}
}

// Com FS_GOLDEN_NETEM=1 e a raiz padrão do kernel, o netem é ligado uma vez e a prio 1: que ele pôs é apagada uma
// vez (no fim do caso); o cleanup não apaga de novo.
func TestCollectNetemRemovesOnlyItsRoot(t *testing.T) {
	_, cmds := runCollect(t, "qdisc mq 0: root", "FS_GOLDEN_NETEM=1")
	if n := count(cmds, "tc qdisc add dev ens192 root handle 1: prio"); n != 1 {
		t.Errorf("netem ligado %d vezes, quer 1", n)
	}
	if n := count(cmds, "tc qdisc del dev ens192 root"); n != 1 {
		t.Errorf("raiz apagada %d vezes, quer 1:\n%s", n, strings.Join(cmds, "\n"))
	}
}
