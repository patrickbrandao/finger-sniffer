package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nome da mount unit do banco: escape de /finger-sniffer/var/store (systemd-escape -p --suffix=mount).
const storeMountUnit = `finger\x2dsniffer-var-store.mount`

// Mount unit do banco do store (ADR 0045 item 1, spec 016 RF-07a): tmpfs de 4G, 0700, ids numéricos por modelo,
// sem PartOf no target.
func TestStoreMountUnit(t *testing.T) {
	d := unitDirectives(t, storeMountUnit)
	for k, want := range map[string]string{
		"What":    "tmpfs",
		"Where":   "/finger-sniffer/var/store",
		"Type":    "tmpfs",
		"Options": "size=4G,mode=0700,uid=@FS_UID@,gid=@FS_GID@,nosuid,nodev,noexec",
	} {
		if got := strings.Join(d[k], ","); got != want {
			t.Errorf("%s = %q, quer %q", k, got, want)
		}
	}
	for _, k := range []string{"PartOf", "WantedBy", "StopWhenUnneeded", "BindsTo"} {
		if len(d[k]) > 0 {
			t.Errorf("mount unit com %s=%v: parar o target ou o store desmontaria o banco", k, d[k])
		}
	}
	// o nome da unit é o escape do Where=
	if got := strings.ReplaceAll(strings.TrimPrefix(d["Where"][0], "/"), "-", `\x2d`); strings.ReplaceAll(got, "/", "-")+".mount" != storeMountUnit {
		t.Errorf("nome %q não é o escape de %q", storeMountUnit, d["Where"][0])
	}
}

// Store puxa o tmpfs e não o controla (ADR 0045 itens 1 e 3).
func TestStoreUnitRequiresTmpfs(t *testing.T) {
	d := unitDirectives(t, "finger-sniffer-store.service")
	if got := strings.Join(d["RequiresMountsFor"], ","); got != "/finger-sniffer/var/store" {
		t.Errorf("RequiresMountsFor = %q", got)
	}
	if got := strings.Join(d["ExecStop"], ","); strings.Contains(got, "umount") {
		t.Errorf("store desmonta o banco: %q", got)
	}
}

func TestRenderStoreMount(t *testing.T) {
	got := libBash(t, t.TempDir(), `render_store_mount "systemd/$FS_STORE_MOUNT_UNIT" 998 997`)
	if !strings.Contains(got, "\nOptions=size=4G,mode=0700,uid=998,gid=997,nosuid,nodev,noexec") {
		t.Errorf("unit renderizada sem os ids:\n%s", got)
	}
	if strings.Contains(got, "@FS_") {
		t.Errorf("sobrou marcador:\n%s", got)
	}
	if got := libBash(t, t.TempDir(), `mount_unit_size "systemd/$FS_STORE_MOUNT_UNIT"; size_bytes 4G; size_bytes 512m; size_bytes 1024`); got != "4G\n4294967296\n536870912\n1024" {
		t.Errorf("tamanho: %q", got)
	}
}

// tmpfsSandbox cria findmnt, systemctl e mount falsos: o estado da montagem fica em $dir/state ("<fstype>
// <bytes>" ou ausente) e cada chamada de systemctl/mount vai para $dir/log. Devolve o bin, o ponto e a unit.
func tmpfsSandbox(t *testing.T, state string) (bin, mnt, unit string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "bin")
	mnt = filepath.Join(dir, "store")
	for _, p := range []string{bin, mnt} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if state != "" {
		writeFile(t, filepath.Join(dir, "state"), state+"\n", 0o644)
	}
	writeFile(t, filepath.Join(bin, "findmnt"), `#!/bin/sh
[ -f "`+dir+`/state" ] || exit 1
cat "`+dir+`/state"
`, 0o755)
	writeFile(t, filepath.Join(bin, "systemctl"), `#!/bin/sh
printf 'systemctl %s\n' "$*" >>"`+dir+`/log"
[ "$1 $2" = 'start finger\x2dsniffer-var-store.mount' ] && echo "tmpfs 4294967296" >"`+dir+`/state"
exit 0
`, 0o755)
	writeFile(t, filepath.Join(bin, "mount"), `#!/bin/sh
printf 'mount %s\n' "$*" >>"`+dir+`/log"
`, 0o755)
	unit = filepath.Join(dir, storeMountUnit)
	writeFile(t, unit, libBash(t, bin, `render_store_mount "systemd/$FS_STORE_MOUNT_UNIT" 998 997`)+"\n", 0o644)
	return bin, mnt, unit
}

func readLog(t *testing.T, mnt string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(mnt), "log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// Primeira instalação: para o store, apaga o banco em disco (e só ele) e monta pela unit (ADR 0045 item 1).
func TestEnsureStoreTmpfsFirstInstall(t *testing.T) {
	bin, mnt, unit := tmpfsSandbox(t, "")
	for _, f := range []string{"finger-sniffer.sqlite", "finger-sniffer.sqlite-wal", "finger-sniffer.sqlite-shm", "other.txt"} {
		writeFile(t, filepath.Join(mnt, f), "x", 0o600)
	}
	libBash(t, bin, `FS_STORE_MNT="$1" ensure_store_tmpfs "$2"`, mnt, unit)
	want := "systemctl stop finger-sniffer-store.service\nsystemctl start " + storeMountUnit
	if got := readLog(t, mnt); got != want {
		t.Errorf("chamadas:\n%s\nquer:\n%s", got, want)
	}
	left, _ := filepath.Glob(filepath.Join(mnt, "*"))
	if len(left) != 1 || filepath.Base(left[0]) != "other.txt" {
		t.Errorf("sobrou no disco: %v", left)
	}
	if got := libBash(t, bin, `FS_STORE_MNT="$1" store_tmpfs_check "$2"`, mnt, unit); !strings.Contains(got, "tmpfs 4G") {
		t.Errorf("check depois de montar: %q", got)
	}
}

// Deploy seguinte com o tamanho certo: nada (nem stop, nem restart, nem remount); o banco fica.
func TestEnsureStoreTmpfsMountedSameSize(t *testing.T) {
	bin, mnt, unit := tmpfsSandbox(t, "tmpfs 4294967296")
	writeFile(t, filepath.Join(mnt, "finger-sniffer.sqlite"), "db", 0o600)
	libBash(t, bin, `FS_STORE_MNT="$1" ensure_store_tmpfs "$2"`, mnt, unit)
	if got := readLog(t, mnt); got != "" {
		t.Errorf("deploy tocou a montagem: %q", got)
	}
	if _, err := os.Stat(filepath.Join(mnt, "finger-sniffer.sqlite")); err != nil {
		t.Errorf("banco apagado: %v", err)
	}
}

// Tamanho diferente: só remount (o conteúdo fica), sem parar o store nem a mount unit.
func TestEnsureStoreTmpfsRemountOnSizeChange(t *testing.T) {
	bin, mnt, unit := tmpfsSandbox(t, "tmpfs 2147483648")
	writeFile(t, filepath.Join(mnt, "finger-sniffer.sqlite"), "db", 0o600)
	libBash(t, bin, `FS_STORE_MNT="$1" ensure_store_tmpfs "$2"`, mnt, unit)
	if got, want := readLog(t, mnt), "mount -o remount,size=4G "+mnt; got != want {
		t.Errorf("chamadas %q, quer %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(mnt, "finger-sniffer.sqlite")); err != nil {
		t.Errorf("banco apagado: %v", err)
	}
	// antes do remount o smoke reprova o tamanho
	out := libBash(t, bin, `FS_STORE_MNT="$1" store_tmpfs_check "$2" || echo FAIL`, mnt, unit)
	if !strings.Contains(out, "NÃO é tmpfs de 4G") || !strings.Contains(out, "FAIL") {
		t.Errorf("check com 2G: %q", out)
	}
}

// Ponto montado com outro tipo: erro, sem apagar nada.
func TestEnsureStoreTmpfsRejectsOtherFS(t *testing.T) {
	bin, mnt, unit := tmpfsSandbox(t, "ext4 107374182400")
	out := libBash(t, bin, `FS_STORE_MNT="$1" ensure_store_tmpfs "$2" 2>&1 && echo OK || echo FAIL`, mnt, unit)
	if !strings.Contains(out, "não tmpfs") || !strings.HasSuffix(out, "FAIL") {
		t.Errorf("ext4: %q", out)
	}
	if got := readLog(t, mnt); got != "" {
		t.Errorf("chamadas com ext4: %q", got)
	}
	out = libBash(t, bin, `FS_STORE_MNT="$1" store_tmpfs_check "$2" || echo FAIL`, mnt, unit)
	if !strings.Contains(out, "FAIL") {
		t.Errorf("check com ext4: %q", out)
	}
}

// remote-install.sh: a mount unit é renderizada com os ids e nunca parada, reiniciada ou desmontada; o smoke
// confere o tmpfs.
func TestRemoteInstallStoreTmpfs(t *testing.T) {
	b, err := os.ReadFile("remote-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"render_store_mount", "id -u finger-sniffer", "id -g finger-sniffer", "ensure_store_tmpfs", "store_tmpfs_check",
		"*.mount) continue",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("remote-install.sh sem %q", want)
		}
	}
	lib, err := os.ReadFile("install-lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{s, string(lib)} {
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if strings.Contains(line, "umount") || (strings.Contains(line, "FS_STORE_MOUNT_UNIT") &&
				(strings.Contains(line, "stop") || strings.Contains(line, "restart"))) {
				t.Errorf("deploy para ou desmonta o banco: %q", line)
			}
		}
	}
	// a unit do banco fica fora da lista de reinícios
	if strings.Contains(libBash(t, t.TempDir(), `echo "$FS_UNITS"`), "mount") {
		t.Error("mount unit em FS_UNITS")
	}
}
