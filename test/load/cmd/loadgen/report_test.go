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

// TestCgroupUsageMemoryMax: com as 15 colunas do loadmon (task 247) o MemoryMax vem do memory.max lido do cgroup
// (store 6G e fatia 10G, ADR 0045), com o shmem máximo e os Δ de memory.events max/oom_kill; sem elas, a tabela de
// reserva já traz os limites da ADR 0045, e não os 2 GiB antigos do store.
func TestCgroupUsageMemoryMax(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "cgroup.csv")
	csv := "t_ns,unit,cpu_usec,mem_current,anon,file,sock,kernel,slab,percpu,nr_throttled,shmem,memory_max,events_max,oom_kill\n" +
		"1000000000,store,0,100,50,0,0,0,0,0,0,1048576,6442450944,4,0\n" +
		"1000000000,slice,0,200,80,0,0,0,0,0,0,1048576,10737418240,0,0\n" +
		"2000000000,store,1000,100,50,0,0,0,0,0,0,3145728,6442450944,4,0\n" +
		"2000000000,slice,1000,200,80,0,0,0,0,0,0,3145728,10737418240,0,0\n" +
		"3000000000,store,2000,100,50,0,0,0,0,0,0,2097152,6442450944,6,1\n" +
		"3000000000,slice,2000,200,80,0,0,0,0,0,0,2097152,10737418240,0,0\n" +
		"3000000000,web,0,1,1,0,0,0,0,0,0\n" + // 11 colunas: tabela de reserva
		"4000000000,web,10,1,1,0,0,0,0,0,0\n"
	if err := os.WriteFile(in, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	usage, _, err := cgroupUsage(in, filepath.Join(dir, "out.csv"), 1500000000, 5000000000)
	if err != nil {
		t.Fatal(err)
	}
	st, sl, web := usage["store"], usage["slice"], usage["web"]
	if st.MemoryMax != 6144 || st.MemoryMaxSource != "cgroup" || sl.MemoryMax != 10240 {
		t.Errorf("MemoryMax store %v (%s), fatia %v; esperava 6144 (cgroup) e 10240", st.MemoryMax, st.MemoryMaxSource, sl.MemoryMax)
	}
	if st.ShmemMax != 3 || st.EventsMax != 2 || st.OOMKill != 1 {
		t.Errorf("store shmem %v, Δ max %d, Δ oom_kill %d; esperava 3, 2, 1", st.ShmemMax, st.EventsMax, st.OOMKill)
	}
	if web.MemoryMax != 768 || web.MemoryMaxSource != "tabela" || web.EventsMax != -1 {
		t.Errorf("web sem as colunas: %+v", web)
	}
	if memoryMax["store"] != 6<<30 || memoryMax["slice"] != 10<<30 {
		t.Errorf("tabela de reserva fora da ADR 0045: store %v, fatia %v", memoryMax["store"], memoryMax["slice"])
	}
	md := renderMD(summaryDoc{Usage: usage, Generator: results{}}, gen{})
	if !strings.Contains(md, "| store | ") || !strings.Contains(md, "| 6144 | 0 | 2 / 1 |") || !strings.Contains(md, "| slice | ") ||
		!strings.Contains(md, "768 (tabela)") {
		t.Errorf("tabela de CPU/RAM:\n%s", md)
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
