package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Parada do escritor durante o expurgo (task 248). Reproduz, sem NATS, o escritor do store na carga 200/50: um
// banco com a retenção cheia (as conexões antigas vencendo no ritmo em que chegam as novas), o ingest de verdade
// (Ingestor.process e afterBatch) recebendo o mix da carga oficial a 50 conexões/s no relógio de parede, leitores
// da API e o laço do store (maintain: expurgo com orçamento e checkpoint do WAL a cada segundo). Mede o atraso de
// cada mensagem (do instante em que entraria no stream até o commit do lote, o que o feed e o registro esperam).
//
// Variáveis (para rodar no disco do servidor com o binário de teste, go test -c):
//
//	FS_STALL_DIR    pasta do banco (padrão: temporária do teste)
//	FS_STALL_SECS   duração da carga (padrão 8 s)
//	FS_STALL_CONNS  conexões no banco antes da carga (padrão 3000; 30000 = 10 min a 50/s)
//	FS_STALL_MAX_MS limite do pior atraso de mensagem (padrão 1000)
//	FS_STALL_RATE   conexões novas por segundo (padrão 50; 100 = perfil 400/100 da task 246)
//	FS_STALL_OLD=1  comportamento de antes da task 248, para comparar: pacotes pela tabela packets, checkpoint
//	                automático a cada 16384 quadros dentro do COMMIT e expurgo com lote fixo

type stallCfg struct {
	dir   string
	secs  int
	conns int
	maxMs int
	rate  int
	old   bool
}

func stallConfig(t *testing.T) stallCfg {
	c := stallCfg{secs: 8, conns: 3000, maxMs: 1000, rate: 50, old: os.Getenv("FS_STALL_OLD") == "1"}
	for _, v := range []struct {
		env string
		dst *int
	}{{"FS_STALL_SECS", &c.secs}, {"FS_STALL_CONNS", &c.conns}, {"FS_STALL_MAX_MS", &c.maxMs}, {"FS_STALL_RATE", &c.rate}} {
		if s := os.Getenv(v.env); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("%s: %v", v.env, err)
			}
			*v.dst = n
		}
	}
	if s := os.Getenv("FS_STALL_JSL"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("FS_STALL_JSL: %v", err)
		}
		old := WALJournalLimit
		WALJournalLimit = n
		t.Cleanup(func() { WALJournalLimit = old })
	}
	c.dir = os.Getenv("FS_STALL_DIR")
	if c.dir == "" {
		c.dir = t.TempDir()
	} else {
		d, err := os.MkdirTemp(c.dir, "stall-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(d) })
		c.dir = d
	}
	return c
}

// stallStats junta as durações observadas por operação.
type stallStats struct {
	mu  sync.Mutex
	ops map[string][]time.Duration
}

func (s *stallStats) add(op string, d time.Duration) {
	s.mu.Lock()
	if s.ops == nil {
		s.ops = map[string][]time.Duration{}
	}
	s.ops[op] = append(s.ops[op], d)
	s.mu.Unlock()
}

func (s *stallStats) summary(op string) (n int, p50, p99, worst time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := append([]time.Duration(nil), s.ops[op]...)
	if len(v) == 0 {
		return 0, 0, 0, 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return len(v), v[len(v)/2], v[len(v)*99/100], v[len(v)-1]
}

// over conta as durações de op acima de d.
func (s *stallStats) over(op string, d time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.ops[op] {
		if v > d {
			n++
		}
	}
	return n
}

func (s *stallStats) report(t *testing.T) {
	s.mu.Lock()
	names := make([]string, 0, len(s.ops))
	for k := range s.ops {
		names = append(names, k)
	}
	s.mu.Unlock()
	sort.Strings(names)
	for _, op := range names {
		n, p50, p99, worst := s.summary(op)
		t.Logf("%-14s n=%-6d p50=%-10v p99=%-10v max=%v", op, n, p50.Round(10*time.Microsecond), p99.Round(10*time.Microsecond), worst.Round(10*time.Microsecond))
	}
}

// stallFill grava n conexões encerradas (registro, pcap e eventos como as da carga), a primeira começando em
// startNs, uma a cada stepNs; cada uma termina 4 s depois de começar (insertConn).
func stallFill(t *testing.T, db *sql.DB, n int, startNs, stepNs int64) {
	t.Helper()
	ctx := context.Background()
	rec, ev := strings.Repeat("r", 3000), strings.Repeat("e", 600)
	pcap := make([]byte, 12000)
	_, _ = rand.Read(pcap)
	for from := 0; from < n; from += 500 {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := from; i < min(n, from+500); i++ {
			if err := insertConn(ctx, tx, fmt.Sprintf("old%08d", i), startNs+int64(i)*stepNs, rec, pcap, ev, 4); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestWriterNoStallDuringPurge: com a retenção cheia e as conexões vencendo no ritmo da carga, nenhuma mensagem
// espera o commit mais que o limite enquanto o expurgo e o checkpoint do WAL rodam (task 248).
func TestWriterNoStallDuringPurge(t *testing.T) {
	if testing.Short() {
		t.Skip("enche o banco")
	}
	if raceEnabled {
		t.Skip("com -race o SQLite em Go puro não acompanha 50 conexões/s")
	}
	cfg := stallConfig(t)
	path := filepath.Join(cfg.dir, "store.sqlite")
	ctx := context.Background()
	db, err := OpenDB(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rdb, err := OpenReadDB(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rdb.Close() }()
	cdb, err := OpenCheckpointDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cdb.Close() }()

	const retention = 10 * time.Minute
	rate := cfg.rate // conexões novas/s
	// No relógio da carga (base + parede desde o início), a conexão antiga i vence em i*20 ms: dali em diante
	// vencem 50/s, como no fim do pré-aquecimento da carga oficial.
	step := int64(time.Second) / int64(rate)
	t0 := time.Now()
	stallFill(t, db, cfg.conns, base-retention.Nanoseconds()-int64(4*time.Second), step)
	if _, _, err := Checkpoint(ctx, cdb); err != nil {
		t.Fatal(err)
	}
	fillTook := time.Since(t0)
	msgs, at := benchWorkloadRate(t, rate*(cfg.secs+5), rate)

	icfg := IngestConfig{
		PcapMax: 16 << 20, TCPIdle: 630 * time.Second, QUICIdle: 330 * time.Second, UDPIdle: 30 * time.Second,
		CloseGrace: DefaultCloseGrace, MaxOpen: 1000, MaxNewPerS: 150, Snaplen: 65535, SegmentsTracked: 32,
	}
	in := NewIngestor(db, icfg, slog.New(slog.NewTextHandler(io.Discard, nil)), service.NewMetrics())
	r := NewRetention(db, retention, 8<<30)
	r.Budget = DefaultRetentionBudget
	r.Tracked, r.OrphanIdle = in.flows.tracked, icfg.TCPIdle
	var stats stallStats
	r.Observe = stats.add
	if cfg.old {
		in.pktConnMax = 0 // todo pacote vai para a tabela, como antes
		if _, err := db.ExecContext(ctx, "PRAGMA wal_autocheckpoint=16384"); err != nil {
			t.Fatal(err)
		}
	} else {
		r.StepTarget = DefaultRetentionStep
	}

	io0 := procWrites()
	start := time.Now()
	clock := func() time.Time { return time.Unix(0, base).Add(time.Since(start)) }
	in.now = clock
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errc := make(chan error, 3)

	// ingest: a cada volta, as mensagens que já "entraram no stream", até 64 por lote como no Run
	wg.Add(1)
	go func() {
		defer wg.Done()
		next := 0
		for next < len(msgs) {
			select {
			case <-stop:
				return
			default:
			}
			el := int(time.Since(start) / time.Millisecond)
			if at[next] > el {
				time.Sleep(time.Duration(min(at[next]-el, 5)) * time.Millisecond)
				continue
			}
			j := next
			for j < len(msgs) && j-next < 64 && at[j] <= el {
				j++
			}
			src := make([]msgSource, j-next)
			for k := range src {
				src[k] = msgs[next+k]
			}
			tt := time.Now()
			if err := in.process(ctx, src); err != nil {
				errc <- err
				return
			}
			done := time.Since(start)
			for k := next; k < j; k++ {
				stats.add("msg_delay", done-time.Duration(at[k])*time.Millisecond)
			}
			in.afterBatch(ctx)
			stats.add("ingest_batch", time.Since(tt))
			next = j
		}
	}()

	// leitores da API: a lista, como os clientes da carga
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			tt := time.Now()
			var n int
			if err := rdb.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT conn_id FROM connections ORDER BY started_ns DESC LIMIT 50)").Scan(&n); err != nil {
				errc <- err
				return
			}
			stats.add("api_read", time.Since(tt))
		}
	}()

	// laço do store
	var purged int64
	var walTrail []int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		tk := time.NewTicker(RetentionInterval)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			tt := time.Now()
			var n, wal int64
			var rerr, cerr error
			if cfg.old {
				n, rerr = r.RunOnce(ctx, clock())
				t1 := time.Now()
				wal, _, cerr = Checkpoint(ctx, cdb)
				stats.add(opCheckpoint, time.Since(t1))
			} else {
				n, wal, rerr, cerr = maintain(ctx, r, db, cdb, path, clock(), stats.add)
			}
			if rerr != nil || cerr != nil {
				errc <- fmt.Errorf("retention %w, checkpoint %w", rerr, cerr)
				return
			}
			purged += n
			walTrail = append(walTrail, wal)
			stats.add("maintain", time.Since(tt))
		}
	}()

	select {
	case err := <-errc:
		close(stop)
		wg.Wait()
		t.Fatal(err)
	case <-time.After(time.Duration(cfg.secs) * time.Second):
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errc:
		t.Fatal(err)
	default:
	}
	written := procWrites() - io0
	var walBytes int64
	if st, err := os.Stat(path + "-wal"); err == nil {
		walBytes = st.Size()
	}
	t.Logf("old=%v fill %d conns in %v; load %ds at %d/s; purged %d; db %d MiB, wal file %d MiB; written %d MiB (%d KiB per new connection); wal frames per second %v",
		cfg.old, cfg.conns, fillTook.Round(time.Millisecond), cfg.secs, rate, purged, dbFileSize(path)>>20, walBytes>>20,
		written>>20, written>>10/int64(rate*cfg.secs), walTrail)
	stats.report(t)
	limit := time.Duration(cfg.maxMs) * time.Millisecond
	t.Logf("msg_delay over 500 ms: %d, over 1 s: %d", stats.over("msg_delay", 500*time.Millisecond), stats.over("msg_delay", time.Second))
	if purged == 0 {
		t.Fatal("nothing purged during the load")
	}
	if n, _, _, worst := stats.summary("msg_delay"); n == 0 || worst > limit {
		t.Fatalf("worst message delay %v (n=%d), limit %v", worst, n, limit)
	}
}

// procWrites devolve os bytes escritos pelo processo (wchar de /proc/self/io; 0 fora do Linux).
func procWrites() int64 {
	data, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "wchar: "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return 0
}

// TestRetentionAdaptsBatch: o passo acima do prazo divide o lote por 2 até o mínimo; o rápido dobra até o máximo.
func TestRetentionAdaptsBatch(t *testing.T) {
	r := NewRetention(nil, time.Minute, 1)
	r.adapt(time.Second) // sem prazo: lote fixo
	if r.batch != DefaultRetentionBatch {
		t.Fatal(r.batch)
	}
	r.StepTarget = 20 * time.Millisecond
	for _, c := range []struct {
		d    time.Duration
		want int
	}{
		{30 * time.Millisecond, 50},
		{30 * time.Millisecond, 25},
		{30 * time.Millisecond, 12},
		{30 * time.Millisecond, minRetentionBatch},
		{30 * time.Millisecond, minRetentionBatch},
		{10 * time.Millisecond, minRetentionBatch},
		{time.Millisecond, 20},
		{time.Millisecond, 40},
		{time.Millisecond, 80},
		{time.Millisecond, DefaultRetentionBatch},
		{time.Millisecond, DefaultRetentionBatch},
	} {
		r.adapt(c.d)
		if r.batch != c.want {
			t.Fatalf("after %v: batch %d, want %d", c.d, r.batch, c.want)
		}
	}
}

// TestCheckpointRestartResetsWAL: com o WAL acima do limiar, CheckpointRestart copia tudo e a próxima escrita
// recomeça o WAL do início (o arquivo não cresce); abaixo do limiar, só a passada sem trava.
func TestCheckpointRestartResetsWAL(t *testing.T) {
	db, path := testDB(t)
	cdb, err := OpenCheckpointDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cdb.Close() }()
	ctx := t.Context()
	if _, err := db.ExecContext(ctx, "CREATE TABLE blob_t (b BLOB)"); err != nil {
		t.Fatal(err)
	}
	fill := func() {
		for range 50 {
			if _, err := db.ExecContext(ctx, "INSERT INTO blob_t VALUES (zeroblob(16384))"); err != nil {
				t.Fatal(err)
			}
		}
	}
	fill()
	var ops []string
	obs := func(op string, _ time.Duration) { ops = append(ops, op) }
	wal, err := CheckpointRestart(ctx, db, cdb, path, 1<<20, obs)
	if err != nil || wal < 100 || len(ops) != 1 || ops[0] != opCheckpoint {
		t.Fatalf("below the threshold: wal %d, ops %v, err %v", wal, ops, err)
	}
	ops = nil
	if _, err := CheckpointRestart(ctx, db, cdb, path, 100, obs); err != nil || ops[len(ops)-1] != opWALRestart {
		t.Fatalf("restart: ops %v, err %v", ops, err)
	}
	// a próxima escrita recomeça o WAL: o checkpoint seguinte vê só os quadros dela
	if _, err := db.ExecContext(ctx, "INSERT INTO blob_t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if wal, _, err := Checkpoint(ctx, cdb); err != nil || wal > 20 {
		t.Fatalf("WAL must restart from the beginning: %d frames, err %v", wal, err)
	}
}
