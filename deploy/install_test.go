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
export FS_PROC_ROOT=$T/proc FS_SYSTEMD_DIR=$T/systemd
main_pid() { cat "$T/pids/$1" 2>/dev/null || echo 0; }
unit_active() { [ "$(main_pid "$1")" != 0 ]; }
mkdir -p "$T/staging/bin" "$T/dest/bin" "$T/pids" "$T/proc" "$T/systemd"
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
		mark_applied "$T/dest" "$u"
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

// putFile grava p (criando os diretórios) ou falha o teste.
func putFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

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
	if got := harness(t, T, "deploy", "A", ""); got != "restart: nats store bot capture web raw dns" {
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
	if got := harness(t, T, "deploy", "B", ""); got != "restart: store bot capture raw dns" {
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
	for _, s := range []string{"store", "bot", "capture", "web", "raw", "dns"} {
		if err := os.WriteFile(filepath.Join(T, "dest/bin/finger-sniffer-"+s), []byte("bin "+s+" B"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := harness(t, T, "deploy", "B", ""); got != "restart: store bot capture web raw dns" {
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
		{[]string{"FORCE=1"}, "", "nats store bot capture web raw dns"},
		{[]string{"ENV_CHANGED=1"}, "", "store bot capture web raw dns"},
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

// Configuração instalada por um deploy com SVC (nats.conf, unit de outro serviço, env) e não aplicada é
// aplicada pelo deploy completo seguinte, mesmo com binários idênticos (task 172, spec 016 RF-11).
func TestDeploySVCThenFullAppliesPendingConfig(t *testing.T) {
	T := t.TempDir()
	putFile(t, filepath.Join(T, "dest/eventbus/nats/nats.conf"), "# v1\n")
	putFile(t, filepath.Join(T, "dest/etc/finger-sniffer.env"), "FS_A=1\n")
	for _, u := range []string{"nats", "store", "bot", "capture", "web", "raw", "dns"} {
		putFile(t, filepath.Join(T, "systemd/finger-sniffer-"+u+".service"), "[Service] "+u+" v1\n")
	}
	if got := harness(t, T, "deploy", "A", ""); got != "restart: nats store bot capture web raw dns" {
		t.Fatalf("primeiro deploy: %q", got)
	}
	if got := harness(t, T, "deploy", "A", ""); got != "restart:" {
		t.Fatalf("deploy completo repetido: %q", got)
	}

	steps := []struct {
		name   string
		change func()
		want   string
	}{
		{"nats.conf", func() { putFile(t, filepath.Join(T, "dest/eventbus/nats/nats.conf"), "# v2\n") }, "nats"},
		{"unit do NATS", func() {
			putFile(t, filepath.Join(T, "systemd/finger-sniffer-nats.service"), "[Service] nats v2\n")
		}, "nats"},
		{"unit do raw", func() {
			putFile(t, filepath.Join(T, "systemd/finger-sniffer-raw.service"), "[Service] raw v2\n")
		}, "raw"},
		// o web reinicia no próprio SVC=web; o deploy completo pega os outros quatro
		{"chave nova de env", func() {
			putFile(t, filepath.Join(T, "dest/etc/finger-sniffer.env"), "FS_A=1\nFS_B=2\n")
		}, "store bot capture raw dns"},
	}
	for _, st := range steps {
		st.change()
		if got := harness(t, T, "deploy", "A", "web"); got != "restart: web" {
			t.Fatalf("%s: SVC=web reiniciou além do web: %q", st.name, got)
		}
		if got := harness(t, T, "deploy", "A", ""); got != "restart: "+st.want {
			t.Fatalf("%s: deploy completo seguinte: %q, quer %q", st.name, got, st.want)
		}
		if !strings.Contains(slurp(t, filepath.Join(T, "plan")), "configuração instalada e ainda não aplicada") {
			t.Errorf("%s: motivo ausente do plano:\n%s", st.name, slurp(t, filepath.Join(T, "plan")))
		}
		if got := harness(t, T, "deploy", "A", ""); got != "restart:" {
			t.Fatalf("%s: segundo deploy completo: %q", st.name, got)
		}
	}
}

// slurp devolve o conteúdo de p ou falha o teste.
func slurp(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBinariesFor(t *testing.T) {
	cases := map[string]string{
		"":     "finger-sniffer-store finger-sniffer-bot finger-sniffer-capture finger-sniffer-web finger-sniffer-raw finger-sniffer-dns",
		"web":  "finger-sniffer-web",
		"bot":  "finger-sniffer-bot",
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

// libBash roda um trecho com install-lib.sh carregado, PATH com bin à frente, e devolve a saída.
func libBash(t *testing.T, bin, script string, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"-c", ". ./install-lib.sh; " + script, "x"}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+"/usr/bin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// Bootstrap (task 225): só os pacotes das ferramentas ausentes, sem repetir; ethtool, iproute2 e nftables na lista.
func TestMissingPackages(t *testing.T) {
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "fs-present"), "#!/bin/sh\n", 0o755)
	got := libBash(t, bin, `FS_TOOL_PACKAGES="fs-absent-a:pkg-a fs-absent-b:pkg-a fs-present:pkg-p fs-absent-c:pkg-c"
missing_packages | tr '\n' ' '`)
	if got != "pkg-a pkg-c" {
		t.Errorf("missing_packages = %q, quer %q", got, "pkg-a pkg-c")
	}
	if got := libBash(t, bin, `FS_TOOL_PACKAGES="fs-present:pkg-p"; missing_packages`); got != "" {
		t.Errorf("nada faltando: %q", got)
	}
	list := " " + libBash(t, bin, `echo "$FS_TOOL_PACKAGES"`) + " "
	for _, tp := range []string{"ethtool:ethtool", "ss:iproute2", "ip:iproute2", "nft:nftables"} {
		if !strings.Contains(list, " "+tp+" ") {
			t.Errorf("FS_TOOL_PACKAGES sem %s: %q", tp, list)
		}
	}
}

// O smoke do deploy compara todas as chaves do nosso sysctl com o kernel (ADR 0038 item 7), com o tab do
// ip_local_port_range normalizado.
func TestSysctlMismatches(t *testing.T) {
	bin := t.TempDir()
	kernel := filepath.Join(bin, "kernel.txt")
	writeFile(t, filepath.Join(bin, "sysctl"), `#!/bin/sh
[ "$1" = -n ] || exit 2
v=$(grep "^$2=" "`+kernel+`" | cut -d= -f2-)
[ -n "$v" ] || exit 1
printf '%s\n' "$v"
`, 0o755)
	conf := filepath.Join(bin, "90.conf")
	writeFile(t, conf, "# comentário\nnet.core.somaxconn = 65535\n\nnet.ipv4.ip_local_port_range = 32768 60999\n"+
		"net.core.rmem_max = 134217728\n", 0o644)

	writeFile(t, kernel, "net.core.somaxconn=65535\nnet.ipv4.ip_local_port_range=32768\t60999\nnet.core.rmem_max=134217728\n", 0o644)
	if got := libBash(t, bin, `sysctl_mismatches "$1"`, conf); got != "" {
		t.Errorf("kernel igual: %q", got)
	}

	// valor antigo (4096), faixa do host e chave ausente no kernel
	writeFile(t, kernel, "net.core.somaxconn=4096\nnet.ipv4.ip_local_port_range=1024\t65535\n", 0o644)
	got := libBash(t, bin, `sysctl_mismatches "$1"`, conf)
	for _, want := range []string{
		"net.core.somaxconn: 4096 (esperado 65535)",
		"net.ipv4.ip_local_port_range: 1024 65535 (esperado 32768 60999)",
		"net.core.rmem_max: ausente (esperado 134217728)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sem %q em:\n%s", want, got)
		}
	}

	// o arquivo do projeto inteiro contra um kernel com os mesmos valores: nenhuma diferença
	var b strings.Builder
	for k, v := range sysctlValues(t) {
		b.WriteString(k + "=" + v + "\n")
	}
	writeFile(t, kernel, b.String(), 0o644)
	if got := libBash(t, bin, `sysctl_mismatches "$1"`, "sysctl/90-finger-sniffer.conf"); got != "" {
		t.Errorf("arquivo do projeto: %q", got)
	}
}

// remote-install.sh: o bootstrap usa missing_packages, o smoke confere fatia, sysctl e NAT, e nada toca o que é
// do host (ADR 0038 item 9).
func TestRemoteInstallTouchesOnlyMirror(t *testing.T) {
	b, err := os.ReadFile("remote-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"missing_packages", "sysctl_mismatches", `"nat_on_mirror_ports":true`, "finger-sniffer.slice",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("remote-install.sh sem %q", want)
		}
	}
	// só o código (os comentários citam o que não é tocado)
	var code strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code.WriteString(line + "\n")
		}
	}
	s = code.String()
	for _, bad := range []string{
		"/etc/docker", "docker ", "nft add", "nft flush", "nft delete", "iptables -", "sysctl -w",
		"somaxconn)\" != 4096", "/sys/kernel/mm/transparent_hugepage", "systemctl stop", "systemctl disable",
	} {
		if strings.Contains(s, bad) {
			t.Errorf("remote-install.sh contém %q", bad)
		}
	}
}

// env_upgrade troca só o padrão antigo (a última ocorrência ativa) e mantém o valor mudado à mão (task 269).
func TestEnvUpgrade(t *testing.T) {
	const oldV, newV = "48022,48161,9000,9001", "48022,48161,9000,9001,9002,9003"
	cases := []struct {
		name, in, want string
		changed        bool
	}{
		{
			"padrão antigo", "A=1\nFS_CAPTURE_EXCLUDE_PORTS=" + oldV + "\nB=2\n",
			"A=1\nFS_CAPTURE_EXCLUDE_PORTS=" + newV + "\nB=2\n", true,
		},
		{"mudado à mão", "FS_CAPTURE_EXCLUDE_PORTS=48022,9000\n", "FS_CAPTURE_EXCLUDE_PORTS=48022,9000\n", false},
		{"já novo", "FS_CAPTURE_EXCLUDE_PORTS=" + newV + "\n", "FS_CAPTURE_EXCLUDE_PORTS=" + newV + "\n", false},
		{
			"só a última", "FS_CAPTURE_EXCLUDE_PORTS=1\n# x\nFS_CAPTURE_EXCLUDE_PORTS=" + oldV + "\n",
			"FS_CAPTURE_EXCLUDE_PORTS=1\n# x\nFS_CAPTURE_EXCLUDE_PORTS=" + newV + "\n", true,
		},
		{"ausente", "A=1\n", "A=1\n", false},
	}
	for _, c := range cases {
		f := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(f, []byte(c.in), 0o640); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("bash", "-c", `. ./install-lib.sh; env_upgrade "$1" FS_CAPTURE_EXCLUDE_PORTS "$2" "$3"`,
			"x", f, oldV, newV).CombinedOutput()
		if changed := err == nil; changed != c.changed {
			t.Errorf("%s: trocou=%v, quer %v (%v)\n%s", c.name, changed, c.changed, err, out)
		}
		b, _ := os.ReadFile(f)
		if string(b) != c.want {
			t.Errorf("%s: %q, quer %q", c.name, b, c.want)
		}
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o640 {
			t.Errorf("%s: modo %v", c.name, st.Mode().Perm())
		}
	}
}

// O deploy cria var/bot e nunca o apaga (ADR 0047 item 2): o rsync do repositório exclui /var/.
func TestRemoteInstallKeepsBotDB(t *testing.T) {
	b, err := os.ReadFile("remote-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"$DEST/var/bot"`, "--exclude='/var/'", "env_upgrade \"$DEST/etc/finger-sniffer.env\" FS_CAPTURE_EXCLUDE_PORTS"} {
		if !strings.Contains(s, want) {
			t.Errorf("remote-install.sh sem %q", want)
		}
	}
	if strings.Contains(s, "var/bot/") || strings.Contains(s, "bot.db") {
		t.Error("remote-install.sh não mexe no conteúdo de var/bot")
	}
}

// ADR 0075 item 3 (task 352): journald_namespace instala journald@finger-sniffer.conf e reinicia só o journald do
// namespace quando ele muda; o drop-in antigo do host é apagado e só essa remoção reinicia o journald do sistema.
func TestJournaldNamespace(t *testing.T) {
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	writeFile(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\necho \"$*\" >>\""+calls+"\"\n", 0o755)
	dir := filepath.Join(t.TempDir(), "systemd")
	old := filepath.Join(dir, "journald.conf.d", "finger-sniffer.conf")
	putFile(t, old, "[Journal]\nSystemMaxUse=200M\n")
	run := func() string {
		_ = os.Remove(calls)
		libBash(t, bin, `journald_namespace "$1" "$2"`, "journald/finger-sniffer.conf", dir)
		b, _ := os.ReadFile(calls)
		return strings.TrimSpace(string(b))
	}

	// primeira vez: apaga o drop-in do host e reinicia os dois journalds
	if got := run(); got != "restart systemd-journald.service\nrestart systemd-journald@finger-sniffer.service" {
		t.Errorf("primeira vez: %q", got)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("drop-in antigo ainda existe: %v", err)
	}
	if got, want := slurp(t, filepath.Join(dir, "journald@finger-sniffer.conf")), slurp(t, "journald/finger-sniffer.conf"); got != want {
		t.Errorf("journald@finger-sniffer.conf = %q, quer %q", got, want)
	}
	// sem mudança: nenhum reinício
	if got := run(); got != "" {
		t.Errorf("sem mudança: %q", got)
	}
	// arquivo mudado: só o journald do namespace
	putFile(t, filepath.Join(dir, "journald@finger-sniffer.conf"), "x\n")
	if got := run(); got != "restart systemd-journald@finger-sniffer.service" {
		t.Errorf("arquivo mudado: %q", got)
	}
}

// ADR 0075 item 3 (task 352): o remote-install.sh não escreve em /etc/systemd/journald.conf.d/ nem reinicia o
// journald do sistema (isso só no journald_namespace, na remoção do drop-in antigo) e lê o journal do espelho com
// --namespace=finger-sniffer.
func TestRemoteInstallJournalNamespace(t *testing.T) {
	b, err := os.ReadFile("remote-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `journald_namespace "$DEST/deploy/journald/finger-sniffer.conf"`) {
		t.Error("remote-install.sh sem journald_namespace")
	}
	for i, line := range strings.Split(string(b), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "journald.conf.d") || strings.Contains(code, "restart systemd-journald") {
			t.Errorf("linha %d mexe no journald do host: %q", i+1, code)
		}
		if strings.Contains(code, "journalctl") && !strings.Contains(code, "journalctl --namespace=finger-sniffer ") {
			t.Errorf("linha %d lê o journal sem --namespace=finger-sniffer: %q", i+1, code)
		}
	}
}
