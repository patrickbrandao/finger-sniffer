package loadstat

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Causas de uma conexão encerrada sem linha de resposta na carga do orçamento (task 220).
const (
	CauseServerFIN          = "server_fin"           // o servidor fechou (EOF na leitura)
	CauseServerRST          = "server_rst"           // o servidor resetou (ECONNRESET/EPIPE)
	CauseClientWriteTimeout = "client_write_timeout" // a escrita do cliente venceu o prazo (o servidor parou de ler)
	CauseClientReadTimeout  = "client_read_timeout"  // a leitura da resposta venceu o prazo
	CauseClientHoldExpired  = "client_hold_expired"  // o cliente desistiu depois de segurar o cabeçalho inteiro
	CauseOther              = "other_error"
)

// CloseCauses lista as causas na ordem do summary.json.
var CloseCauses = []string{
	CauseServerFIN, CauseServerRST, CauseClientWriteTimeout, CauseClientReadTimeout, CauseClientHoldExpired, CauseOther,
}

// CloseCause classifica o erro de uma operação de rede do cliente; write diz se o erro veio da escrita (o prazo
// vencido vira client_write_timeout) ou da leitura (client_read_timeout). nil devolve "".
func CloseCause(err error, write bool) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return CauseServerFIN
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNABORTED):
		return CauseServerRST
	case errors.As(err, &ne) && ne.Timeout():
		if write {
			return CauseClientWriteTimeout
		}
		return CauseClientReadTimeout
	default:
		return CauseOther
	}
}

// MemWindow é o máximo da memória de uma unit numa janela de tempo do cgroup.csv do loadmon: memory.current,
// anon e a memória de kernel estimada (memory.current − anon − file: buffers de socket, slab, pilhas). Com o CSV
// de 10 colunas (task 215), também o máximo das chaves sock, kernel, slab e percpu do memory.stat; HasStat diz se
// alguma amostra da janela as trouxe.
type MemWindow struct {
	StartS, EndS          int
	Samples               int
	CurrentMax, AnonMax   int64
	KernelMax, KernelLast int64
	HasStat               bool
	SockMax, KStatMax     int64
	SlabMax, PercpuMax    int64
}

// MemWindows lê o cgroup.csv do loadmon (t_ns,unit,cpu_usec,mem_current,anon,file[,sock,kernel,slab,percpu[,nr_throttled
// [,shmem,memory_max,events_max,oom_kill]]]) e agrupa as amostras da unit em janelas de width a partir da primeira
// amostra. Aceita os formatos antigos, de 6, 10 e 11 colunas, dos brutos já gravados.
func MemWindows(r io.Reader, unit string, width time.Duration) ([]MemWindow, error) {
	sc := bufio.NewScanner(r)
	var (
		t0  int64
		out []MemWindow
	)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ",")
		if (len(f) != 6 && len(f) != 10 && len(f) != 11 && len(f) != 15) || f[1] != unit {
			continue
		}
		var v [15]int64
		bad := false
		for i, s := range f {
			if i == 1 {
				continue
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				bad = true
				break
			}
			v[i] = n
		}
		if bad {
			continue // cabeçalho
		}
		if t0 == 0 {
			t0 = v[0]
		}
		idx := int(time.Duration(v[0]-t0) / width)
		for len(out) <= idx {
			s := len(out) * int(width/time.Second)
			out = append(out, MemWindow{StartS: s, EndS: s + int(width/time.Second)})
		}
		w := &out[idx]
		kern := v[3] - v[4] - v[5]
		w.Samples++
		w.CurrentMax = max(w.CurrentMax, v[3])
		w.AnonMax = max(w.AnonMax, v[4])
		w.KernelMax = max(w.KernelMax, kern)
		w.KernelLast = kern
		if len(f) >= 10 {
			w.HasStat = true
			w.SockMax = max(w.SockMax, v[6])
			w.KStatMax = max(w.KStatMax, v[7])
			w.SlabMax = max(w.SlabMax, v[8])
			w.PercpuMax = max(w.PercpuMax, v[9])
		}
	}
	return out, sc.Err()
}

// PrintMemWindows escreve a tabela das janelas em MiB, em Markdown; as colunas do memory.stat só aparecem quando
// alguma janela as tem.
func PrintMemWindows(w io.Writer, ws []MemWindow) {
	mib := func(b int64) string { return strconv.FormatFloat(float64(b)/(1<<20), 'f', 1, 64) }
	stat := false
	for _, x := range ws {
		stat = stat || x.HasStat
	}
	if stat {
		_, _ = fmt.Fprintln(w, "| janela (s) | amostras | memory.current máx (MiB) | anon máx (MiB) | kernel máx (MiB) | "+
			"sock máx (MiB) | stat kernel máx (MiB) | slab máx (MiB) | percpu máx (MiB) |")
		_, _ = fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	} else {
		_, _ = fmt.Fprintln(w, "| janela (s) | amostras | memory.current máx (MiB) | anon máx (MiB) | kernel máx (MiB) |")
		_, _ = fmt.Fprintln(w, "| --- | --- | --- | --- | --- |")
	}
	for _, x := range ws {
		if x.Samples == 0 {
			continue
		}
		_, _ = fmt.Fprintf(w, "| %d–%d | %d | %s | %s | %s |", x.StartS, x.EndS, x.Samples, mib(x.CurrentMax),
			mib(x.AnonMax), mib(x.KernelMax))
		if stat {
			_, _ = fmt.Fprintf(w, " %s | %s | %s | %s |", mib(x.SockMax), mib(x.KStatMax), mib(x.SlabMax), mib(x.PercpuMax))
		}
		_, _ = fmt.Fprintln(w)
	}
}

// NstatKeys são os contadores do nstat cujos deltas a carga do orçamento registra (task 215, ADR 0037).
var NstatKeys = []string{
	"TcpExtTCPRcvQDrop", "TcpExtTCPMemoryPressures", "TcpExtPruneCalled", "TcpExtRcvPruned",
	"TcpExtTCPOFODrop", "TcpExtTCPZeroWindowDrop", "UdpRcvbufErrors",
}

// ParseNstat lê a saída de "nstat -asz" (nome, valor absoluto, taxa; "#kernel" no topo).
func ParseNstat(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			out[f[0]] = v
		}
	}
	return out
}

// NstatDelta escreve, para cada chave de NstatKeys, "chave antes → depois (delta)"; chave ausente vale 0.
func NstatDelta(w io.Writer, before, after string) {
	b, a := ParseNstat(before), ParseNstat(after)
	for _, k := range NstatKeys {
		_, _ = fmt.Fprintf(w, "%s %d → %d (delta %d)\n", k, b[k], a[k], a[k]-b[k])
	}
}

// MemWindowsFile é MemWindows sobre um arquivo.
func MemWindowsFile(path, unit string, width time.Duration) ([]MemWindow, error) {
	f, err := os.Open(path) //nolint:gosec // caminho do operador
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // só leitura
	return MemWindows(f, unit, width)
}
