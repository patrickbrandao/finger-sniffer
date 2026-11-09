package loadstat

import (
	"math"
	"testing"
)

func TestSummarize(t *testing.T) {
	xs := make([]float64, 0, 100)
	for i := 100; i >= 1; i-- {
		xs = append(xs, float64(i))
	}
	s := Summarize(xs)
	if s.N != 100 || s.P50 != 50 || s.P95 != 95 || s.P99 != 99 || s.Max != 100 || s.Mean != 50.5 {
		t.Fatalf("Summarize: %+v", s)
	}
	// a entrada não é reordenada
	if xs[0] != 100 {
		t.Fatalf("Summarize alterou a entrada")
	}
	if s := Summarize(nil); s.N != 0 {
		t.Fatalf("vazio: %+v", s)
	}
	if got := Summarize([]float64{7}); got.P50 != 7 || got.P99 != 7 {
		t.Fatalf("uma amostra: %+v", got)
	}
	if !math.IsNaN(Rank(nil, 0.5)) {
		t.Fatal("Rank vazio deveria ser NaN")
	}
}

const promText = `# HELP fs_x help
# TYPE fs_x histogram
fs_x_bucket{route="GET /a/{id}",le="0.1"} 5
fs_x_bucket{route="GET /a/{id}",le="0.5"} 9
fs_x_bucket{route="GET /a/{id}",le="+Inf"} 10
fs_x_bucket{route="GET /b",le="0.1"} 1
fs_x_bucket{route="GET /b",le="0.5"} 1
fs_x_bucket{route="GET /b",le="+Inf"} 1
fs_x_count{route="GET /a/{id}"} 10
fs_up{service="web",path="a\"b\\c"} 1
fs_plain 42 1700000000000

`

func TestParseProm(t *testing.T) {
	ss, err := ParseProm(promText)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 9 {
		t.Fatalf("%d amostras", len(ss))
	}
	if v := Sum(ss, "fs_plain", nil); v != 42 {
		t.Fatalf("fs_plain = %v", v)
	}
	if v := Sum(ss, "fs_up", map[string]string{"path": `a"b\c`}); v != 1 {
		t.Fatalf("rótulo com escape: %v (%+v)", v, ss[7].Labels)
	}
	h := Histogram(ss, "fs_x", map[string]string{"route": "GET /a/{id}"})
	if len(h) != 3 || h[0] != (Bucket{0.1, 5}) || !math.IsInf(h[2].LE, 1) {
		t.Fatalf("Histogram: %+v", h)
	}
	all := Histogram(ss, "fs_x", nil)
	if all[2].Count != 11 {
		t.Fatalf("soma entre séries: %+v", all)
	}
	for _, bad := range []string{"semvalor", `x{a="b} 1`, `x{a} 1`, "x abc"} {
		if _, err := ParseProm(bad); err == nil {
			t.Errorf("ParseProm(%q) sem erro", bad)
		}
	}
}

func TestQuantile(t *testing.T) {
	b := []Bucket{{0.1, 50}, {0.5, 90}, {1, 100}, {math.Inf(1), 100}}
	if q := Quantile(b, 0.5); q != 0.1 {
		t.Fatalf("p50 = %v", q)
	}
	// p70: rank 70 no bucket (0.1, 0.5]: 0.1 + 0.4·20/40 = 0.3
	if q := Quantile(b, 0.7); math.Abs(q-0.3) > 1e-9 {
		t.Fatalf("p70 = %v", q)
	}
	if q := Quantile(b, 0.99); math.Abs(q-0.95) > 1e-9 {
		t.Fatalf("p99 = %v", q)
	}
	inf := []Bucket{{1, 1}, {math.Inf(1), 10}}
	if q := Quantile(inf, 0.9); q != 1 {
		t.Fatalf("quantil no +Inf = %v", q)
	}
	if !math.IsNaN(Quantile(nil, 0.5)) || !math.IsNaN(Quantile([]Bucket{{1, 0}}, 0.5)) {
		t.Fatal("sem amostras deveria ser NaN")
	}
	if f := FractionBelow(b, 0.5); f != 0.9 {
		t.Fatalf("FractionBelow = %v", f)
	}
	if f := FractionBelow(b, 5); f != 1 {
		t.Fatalf("FractionBelow acima de tudo = %v", f)
	}
	d := DiffBuckets([]Bucket{{0.1, 10}, {math.Inf(1), 20}}, []Bucket{{0.1, 15}, {math.Inf(1), 40}})
	if d[0].Count != 5 || d[1].Count != 20 {
		t.Fatalf("DiffBuckets: %+v", d)
	}
}

func TestCgroup(t *testing.T) {
	kv := ParseKV("usage_usec 2816143\nuser_usec 1063519\nlixo\nanon x\n")
	if kv["usage_usec"] != 2816143 || kv["user_usec"] != 1063519 || len(kv) != 2 {
		t.Fatalf("ParseKV: %v", kv)
	}
	if p := CPUPercent(1_000_000, 1_500_000, 1_000_000); p != 50 {
		t.Fatalf("CPUPercent = %v", p)
	}
	if p := CPUPercent(2, 1, 10); p != 0 {
		t.Fatalf("contador que voltou (restart) = %v", p)
	}
	busy, total, steal, err := ProcStatCPU("cpu  100 0 50 800 10 5 5 30 0 0\ncpu0 1 2 3\n")
	if err != nil || busy != 190 || total != 1000 || steal != 30 {
		t.Fatalf("ProcStatCPU = %d %d %d %v", busy, total, steal, err)
	}
	if _, _, _, err := ProcStatCPU("intr 1"); err == nil {
		t.Fatal("ProcStatCPU sem linha cpu deveria falhar")
	}
}
