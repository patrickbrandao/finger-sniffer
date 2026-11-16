//go:build load

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCgroupLine: a linha tem as 15 colunas do cabeçalho, com shmem, memory.max e memory.events (ADR 0045);
// memory.max "max" vira 0.
func TestCgroupLine(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"cpu.stat":       "usage_usec 1500\nnr_throttled 3\n",
		"memory.current": "4096\n",
		"memory.stat":    "anon 100\nfile 200\nsock 1\nkernel 2\nslab 3\npercpu 4\nshmem 150\n",
		"memory.max":     "6442450944\n",
		"memory.events":  "low 0\nhigh 0\nmax 7\noom 1\noom_kill 1\n",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := cgroupLine(42, "store", dir)
	if want := "42,store,1500,4096,100,200,1,2,3,4,3,150,6442450944,7,1"; got != want {
		t.Fatalf("cgroupLine = %q, esperava %q", got, want)
	}
	if n, h := len(strings.Split(got, ",")), len(strings.Split(csvHeader, ",")); n != h {
		t.Fatalf("linha com %d colunas, cabeçalho com %d", n, h)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := cgroupLine(42, "store", dir); !strings.HasSuffix(got, ",150,0,7,1") {
		t.Fatalf("memory.max \"max\" deveria dar 0: %q", got)
	}
}
