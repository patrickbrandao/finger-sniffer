// Package loadstat reúne as contas do teste de carga (task 068, spec 017 RF-13): percentis de amostras,
// leitura do formato de exposição do Prometheus, quantis de histogramas por diferença de duas coletas e
// leitura dos arquivos de cgroup v2 da vps602. Fica fora das build tags para ter testes no verify.
package loadstat

import (
	"bufio"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Summary resume uma série de amostras (em milissegundos ou na unidade de quem chamou).
type Summary struct {
	N    int     `json:"n"`
	Mean float64 `json:"mean"`
	P50  float64 `json:"p50"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
}

// Summarize ordena uma cópia das amostras e devolve os percentis pelo método do posto mais próximo
// (o menor valor com ao menos q·N amostras até ele), sem interpolação.
func Summarize(xs []float64) Summary {
	if len(xs) == 0 {
		return Summary{}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	var sum float64
	for _, x := range s {
		sum += x
	}
	return Summary{
		N: len(s), Mean: sum / float64(len(s)),
		P50: Rank(s, 0.50), P95: Rank(s, 0.95), P99: Rank(s, 0.99), Max: s[len(s)-1],
	}
}

// Rank devolve o quantil q (0..1] de uma série já ordenada pelo posto mais próximo.
func Rank(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return sorted[min(max(i, 0), len(sorted)-1)]
}

// ---------------------------------------------------------------- Prometheus

// Sample é uma linha do formato de exposição: nome, rótulos e valor.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// ParseProm lê o formato de exposição de texto do Prometheus (linhas `nome{a="b",...} valor [ts]`),
// ignorando comentários e linhas em branco.
func ParseProm(text string) ([]Sample, error) {
	var out []Sample
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		s, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("linha %d: %w", n, err)
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func parseLine(line string) (Sample, error) {
	s := Sample{Labels: map[string]string{}}
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return s, fmt.Errorf("sem valor: %q", line)
	}
	s.Name = line[:i]
	rest := line[i:]
	if strings.HasPrefix(rest, "{") {
		rest = rest[1:]
		for {
			rest = strings.TrimLeft(rest, " ,")
			if strings.HasPrefix(rest, "}") {
				rest = rest[1:]
				break
			}
			eq := strings.Index(rest, "=\"")
			if eq < 0 {
				return s, fmt.Errorf("rótulo malformado: %q", line)
			}
			key := rest[:eq]
			rest = rest[eq+2:]
			var b strings.Builder
			closed := false
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				if c == '\\' && i+1 < len(rest) {
					i++
					switch rest[i] {
					case 'n':
						b.WriteByte('\n')
					default:
						b.WriteByte(rest[i])
					}
					continue
				}
				if c == '"' {
					rest = rest[i+1:]
					closed = true
					break
				}
				b.WriteByte(c)
			}
			if !closed {
				return s, fmt.Errorf("aspas sem fim: %q", line)
			}
			s.Labels[key] = b.String()
		}
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return s, fmt.Errorf("sem valor: %q", line)
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return s, fmt.Errorf("valor %q: %w", f[0], err)
	}
	s.Value = v
	return s, nil
}

// Matches diz se a amostra tem o nome e todos os rótulos pedidos.
func (s Sample) Matches(name string, labels map[string]string) bool {
	if s.Name != name {
		return false
	}
	for k, v := range labels {
		if s.Labels[k] != v {
			return false
		}
	}
	return true
}

// Sum soma os valores das amostras com o nome e os rótulos pedidos.
func Sum(samples []Sample, name string, labels map[string]string) float64 {
	var t float64
	for _, s := range samples {
		if s.Matches(name, labels) {
			t += s.Value
		}
	}
	return t
}

// Bucket é um limite superior de histograma e a contagem acumulada até ele.
type Bucket struct {
	LE    float64
	Count float64
}

// Histogram junta os buckets (somados entre séries que casam com labels) de um histograma.
func Histogram(samples []Sample, base string, labels map[string]string) []Bucket {
	acc := map[float64]float64{}
	for _, s := range samples {
		if !s.Matches(base+"_bucket", labels) {
			continue
		}
		le, err := strconv.ParseFloat(s.Labels["le"], 64)
		if err != nil {
			continue
		}
		acc[le] += s.Value
	}
	out := make([]Bucket, 0, len(acc))
	for le, c := range acc {
		out = append(out, Bucket{le, c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LE < out[j].LE })
	return out
}

// DiffBuckets subtrai a coleta anterior da posterior (mesmos limites), para ter só o intervalo medido.
func DiffBuckets(before, after []Bucket) []Bucket {
	prev := map[float64]float64{}
	for _, b := range before {
		prev[b.LE] = b.Count
	}
	out := make([]Bucket, len(after))
	for i, b := range after {
		out[i] = Bucket{b.LE, b.Count - prev[b.LE]}
	}
	return out
}

// Quantile estima o quantil q pela interpolação linear dentro do bucket, como o histogram_quantile do
// Prometheus. Se o quantil cai no +Inf, devolve o maior limite finito. Sem amostras devolve NaN.
func Quantile(buckets []Bucket, q float64) float64 {
	if len(buckets) == 0 {
		return math.NaN()
	}
	total := buckets[len(buckets)-1].Count
	if total <= 0 {
		return math.NaN()
	}
	rank := q * total
	prevLE, prevCount := 0.0, 0.0
	for _, b := range buckets {
		if b.Count >= rank {
			if math.IsInf(b.LE, 1) {
				return prevLE
			}
			if b.Count == prevCount {
				return b.LE
			}
			return prevLE + (b.LE-prevLE)*(rank-prevCount)/(b.Count-prevCount)
		}
		prevLE, prevCount = b.LE, b.Count
	}
	return prevLE
}

// FractionBelow é a fração das observações com valor ≤ le (o le precisa ser um limite de bucket).
func FractionBelow(buckets []Bucket, le float64) float64 {
	if len(buckets) == 0 {
		return math.NaN()
	}
	total := buckets[len(buckets)-1].Count
	if total <= 0 {
		return math.NaN()
	}
	for _, b := range buckets {
		if b.LE >= le {
			return b.Count / total
		}
	}
	return 1
}

// ---------------------------------------------------------------- cgroup v2

// ParseKV lê arquivos `chave valor` do cgroup v2 (cpu.stat, memory.stat).
func ParseKV(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			out[f[0]] = v
		}
	}
	return out
}

// CPUPercent converte a diferença de usage_usec em percentual de um núcleo no intervalo dado (em µs).
func CPUPercent(prevUsec, curUsec, intervalUsec int64) float64 {
	if intervalUsec <= 0 || curUsec < prevUsec {
		return 0
	}
	return 100 * float64(curUsec-prevUsec) / float64(intervalUsec)
}

// ProcStatCPU lê a linha agregada `cpu` do /proc/stat e devolve (ocupado, total, steal) em jiffies.
func ProcStatCPU(text string) (busy, total, steal int64, err error) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] != "cpu" {
			continue
		}
		var v [8]int64
		for i := range v {
			if v[i], err = strconv.ParseInt(f[i+1], 10, 64); err != nil {
				return 0, 0, 0, err
			}
		}
		// user nice system idle iowait irq softirq steal
		idle := v[3] + v[4]
		for _, x := range v {
			total += x
		}
		return total - idle, total, v[7], nil
	}
	return 0, 0, 0, fmt.Errorf("/proc/stat sem a linha cpu")
}
