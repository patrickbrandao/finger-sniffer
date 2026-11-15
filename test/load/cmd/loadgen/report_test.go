//go:build load

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCgroupUsageThrottled: o cgroup.csv de 11 colunas (ADR 0039) dá o Δ de nr_throttled por unit dentro da
// janela e os núcleos do host; o formato antigo (10 colunas) dá -1 (sem a coluna).
func TestCgroupUsageThrottled(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "cgroup.csv")
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu,nr_throttled\n" +
		"1000000000,web,0,100,50,0,0,0,0,0,2\n" +
		"1000000000,host,100,1000,0,16,0,0,0,0,0\n" +
		"2000000000,web,500000,100,50,0,0,0,0,0,2\n" +
		"2000000000,host,150,1100,0,16,0,0,0,0,0\n" +
		"3000000000,web,1000000,100,60,0,0,0,0,0,5\n" +
		"3000000000,host,200,1200,0,16,0,0,0,0,0\n" +
		"3000000000,raw,10,1,1,0,0,0,0,0\n" + // formato antigo, sem a coluna
		"4000000000,raw,20,1,1,0,0,0,0,0\n"
	if err := os.WriteFile(in, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	usage, host, err := cgroupUsage(in, filepath.Join(dir, "out.csv"), 1500000000, 5000000000)
	if err != nil {
		t.Fatal(err)
	}
	if got := usage["web"].Throttled; got != 3 {
		t.Errorf("web nr_throttled Δ = %d, esperava 3", got)
	}
	if got := usage["raw"].Throttled; got != -1 {
		t.Errorf("raw sem a coluna: Δ = %d, esperava -1", got)
	}
	if usage["web"].CPUMean != 50 {
		t.Errorf("web CPU média = %v, esperava 50", usage["web"].CPUMean)
	}
	if host.NCPU != 16 || host.Mean != 50 {
		t.Errorf("host = %+v, esperava 16 núcleos e 50%%", host)
	}
	if s := hostCPUText(host); !strings.Contains(s, "800 / 800 / 800 % de um núcleo (16 vCPU)") {
		t.Errorf("hostCPUText = %q", s)
	}
}

// TestConntrackDelta: deltas de drop/insert_failed/early_drop/error entre os dois arquivos do run.sh.
func TestConntrackDelta(t *testing.T) {
	dir := t.TempDir()
	if conntrackDelta(dir) != "" {
		t.Fatal("sem arquivos deveria ser vazio")
	}
	_ = os.WriteFile(filepath.Join(dir, "conntrack-antes.txt"), []byte("cpu=0 drop=1 insert_failed=0 early_drop=0 error=2\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "conntrack-depois.txt"), []byte("cpu=0 drop=4 insert_failed=1 early_drop=0 error=2\n"), 0o600)
	if got := conntrackDelta(dir); got != "drop 3, insert_failed 1, early_drop 0, error 0" {
		t.Fatalf("conntrackDelta = %q", got)
	}
}
