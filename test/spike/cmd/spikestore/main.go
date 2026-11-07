//go:build spike

// Comando spikestore: consumidor do stream FS_EVENTS que grava pacotes e pcaps como BLOB no SQLite,
// com correlação por fluxo, materialização do pcap no fechamento e expurgo por retenção (task 006).
package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oklog/ulid/v2"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/patrickbrandao/finger-sniffer/database/sqlite/migrations"
	"github.com/patrickbrandao/finger-sniffer/test/spike/flow"
	"github.com/patrickbrandao/finger-sniffer/test/spike/fspb"
)

type conn struct {
	id           string
	started      int64
	lastSeen     int64
	finIn        bool
	finOut       bool
	closeAt      int64 // ns; 0 = aberta
	pcapBytes    int64
	truncated    bool
	packets      int
	materialized bool
}

// reservoir guarda uma amostra uniforme de até n valores (ms).
type reservoir struct {
	mu   sync.Mutex
	n    int
	seen int64
	vals []float64
}

func (r *reservoir) add(v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen++
	if len(r.vals) < r.n {
		r.vals = append(r.vals, v)
		return
	}
	if j := rand.Int64N(r.seen); j < int64(r.n) { //nolint:gosec // amostragem, não criptografia
		r.vals[j] = v
	}
}

func (r *reservoir) pct(ps ...float64) []float64 {
	r.mu.Lock()
	v := append([]float64(nil), r.vals...)
	r.mu.Unlock()
	out := make([]float64, len(ps))
	if len(v) == 0 {
		return out
	}
	sort.Float64s(v)
	for i, p := range ps {
		out[i] = v[min(len(v)-1, int(p*float64(len(v))))]
	}
	return out
}

func (r *reservoir) reset() { r.mu.Lock(); r.vals, r.seen = r.vals[:0], 0; r.mu.Unlock() }

func main() {
	natsURL := flag.String("nats", "nats://127.0.0.1:4222", "NATS URL")
	dbPath := flag.String("db", "/finger-sniffer/var/spike/spike.sqlite", "SQLite")
	retention := flag.Duration("retention", 2*time.Minute, "retenção")
	pcapMax := flag.Int64("pcap-max", 16<<20, "teto do pcap por conexão")
	idleClose := flag.Duration("idle-close", 30*time.Second, "fecha conexão ociosa")
	memStream := flag.Bool("mem-stream", false, "stream FS_EVENTS em memória (32 MiB) em vez de arquivo")
	noVacuum := flag.Bool("no-vacuum", false, "não roda incremental_vacuum no expurgo")
	deleteStream := flag.Bool("delete-stream", false, "apaga o stream FS_EVENTS e sai (limpeza)")
	flag.Parse()

	if *deleteStream {
		nc, err := nats.Connect(*natsURL)
		if err != nil {
			log.Fatalf("nats: %v", err)
		}
		js, _ := jetstream.New(nc)
		if err := js.DeleteStream(context.Background(), "FS_EVENTS"); err != nil {
			log.Fatalf("delete stream: %v", err)
		}
		nc.Close()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, r := openDB(ctx, *dbPath)
	defer func() { _ = w.Close(); _ = r.Close() }()

	nc, err := nats.Connect(*natsURL)
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	scfg := jetstream.StreamConfig{
		Name: "FS_EVENTS", Subjects: []string{"fs.v1.>"}, MaxAge: 60 * time.Second, MaxBytes: 64 << 20,
		Storage: jetstream.FileStorage, Discard: jetstream.DiscardOld,
	}
	if *memStream {
		scfg.Storage, scfg.MaxBytes = jetstream.MemoryStorage, 32<<20
	}
	_ = js.DeleteStream(ctx, "FS_EVENTS") // o tipo de armazenamento não muda com update
	if _, err := js.CreateOrUpdateStream(ctx, scfg); err != nil {
		log.Fatalf("stream: %v", err)
	}
	cons, err := js.CreateOrUpdateConsumer(ctx, "FS_EVENTS", jetstream.ConsumerConfig{
		Durable: "store", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: "fs.v1.capture.packet",
		MaxAckPending: 4096,
	})
	if err != nil {
		log.Fatalf("consumer: %v", err)
	}

	var (
		mu                          sync.Mutex
		conns                       = map[string]*conn{}
		recent                      []string
		ingestLat                   = &reservoir{n: 200000}
		ingestWin                   = &reservoir{n: 20000}
		queryLat                    = &reservoir{n: 50000}
		queryWin                    = &reservoir{n: 5000}
		capLat                      = &reservoir{n: 200000} // kernel → lote publicado
		busLat                      = &reservoir{n: 200000} // lote publicado → commit no SQLite
		capWin                      = &reservoir{n: 20000}
		commitWin                   = &reservoir{n: 5000} // duração do commit do lote
		commitAll                   = &reservoir{n: 100000}
		busWin                      = &reservoir{n: 20000}
		msgs, pkts, newConns, stray int64
		retentionMs, matMs          float64
		deleted                     int64
	)

	// Amostrador de consultas: simula GET /connections/{id} + pcap.
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for ctx.Err() == nil {
			<-t.C
			mu.Lock()
			if len(recent) == 0 {
				mu.Unlock()
				continue
			}
			id := recent[rand.IntN(len(recent))] //nolint:gosec // amostragem, não criptografia
			mu.Unlock()
			t0 := time.Now()
			var rec string
			_ = r.QueryRowContext(ctx, "SELECT record_json FROM connections WHERE conn_id = ?", id).Scan(&rec)
			var blob []byte
			if err := r.QueryRowContext(ctx, "SELECT data FROM pcaps WHERE conn_id = ?", id).Scan(&blob); err != nil {
				rows, err := r.QueryContext(ctx, "SELECT ts_ns, frame FROM packets WHERE conn_id = ? ORDER BY ts_ns", id)
				if err == nil {
					for rows.Next() {
						var ts int64
						var f []byte
						_ = rows.Scan(&ts, &f)
					}
					_ = rows.Close()
				}
			}
			ms := float64(time.Since(t0).Microseconds()) / 1000
			queryLat.add(ms)
			queryWin.add(ms)
		}
	}()

	report := time.NewTicker(5 * time.Second)
	retain := time.NewTicker(10 * time.Second)
	defer report.Stop()
	defer retain.Stop()
	start := time.Now()

	for ctx.Err() == nil {
		select {
		case <-report.C:
			info, _ := cons.Info(ctx)
			var pending uint64
			if info != nil {
				pending = info.NumPending
			}
			mu.Lock()
			open := len(conns)
			mu.Unlock()
			iw, qw := ingestWin.pct(0.5, 0.95, 0.99), queryWin.pct(0.5, 0.95, 0.99)
			cw, bw := capWin.pct(0.5, 0.95, 0.99), busWin.pct(0.5, 0.95, 0.99)
			mw := commitWin.pct(0.5, 0.99, 0.9999)
			commitWin.reset()
			capWin.reset()
			busWin.reset()
			ingestWin.reset()
			queryWin.reset()
			out, _ := json.Marshal(map[string]any{
				"t": time.Since(start).Seconds(), "msgs": msgs, "packets": pkts, "new_conns": newConns,
				"tracked_conns": open, "stray": stray, "deleted_conns": deleted, "consumer_pending": pending,
				"ingest_ms_p50": iw[0], "ingest_ms_p95": iw[1], "ingest_ms_p99": iw[2],
				"query_ms_p50": qw[0], "query_ms_p95": qw[1], "query_ms_p99": qw[2],
				"commit_ms_p50": mw[0], "commit_ms_p99": mw[1], "commit_ms_max": mw[2],
				"cap_ms_p95": cw[1], "cap_ms_p99": cw[2], "bus_ms_p95": bw[1], "bus_ms_p99": bw[2],
				"retention_ms": retentionMs, "materialize_ms": matMs, "db_bytes": dbSize(*dbPath),
			})
			fmt.Println(string(out))
		case <-retain.C:
			t0 := time.Now()
			cut := time.Now().Add(-*retention).UnixNano()
			for {
				res, err := w.ExecContext(ctx, "DELETE FROM connections WHERE conn_id IN (SELECT conn_id FROM connections WHERE started_ns < ? LIMIT 500)", cut)
				if err != nil {
					log.Printf("retention: %v", err)
					break
				}
				n, _ := res.RowsAffected()
				deleted += n
				if n < 500 {
					break
				}
			}
			if !*noVacuum {
				_, _ = w.ExecContext(ctx, "PRAGMA incremental_vacuum(4096)")
			}
			mu.Lock()
			for k, c := range conns {
				if c.started < cut {
					delete(conns, k)
				}
			}
			if len(recent) > 2000 {
				recent = append([]string(nil), recent[len(recent)-2000:]...)
			}
			mu.Unlock()
			retentionMs = float64(time.Since(t0).Microseconds()) / 1000
		default:
		}

		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(100*time.Millisecond))
		if err != nil {
			continue
		}
		var got []jetstream.Msg
		for m := range batch.Messages() {
			got = append(got, m)
		}
		if len(got) == 0 {
			continue
		}

		tx, err := w.BeginTx(ctx, nil)
		if err != nil {
			log.Fatalf("begin: %v", err)
		}
		insConn, _ := tx.PrepareContext(ctx, `INSERT INTO connections (conn_id, l4, family, src_ip, src_port, dst_ip, dst_port, proto, started_ns, record_json, updated_ns) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
		insPkt, _ := tx.PrepareContext(ctx, `INSERT INTO packets (conn_id, ts_ns, dir, wire_len, frame) VALUES (?,?,?,?,?)`)
		insStray, _ := tx.PrepareContext(ctx, `INSERT INTO stray_packets (ts_ns, dir, l4, record_json, frame) VALUES (?,?,?,?,?)`)
		var tss []int64
		var batchNs []int64
		mu.Lock()
		for _, m := range got {
			msgs++
			bns, _ := strconv.ParseInt(m.Headers().Get("Fs-Batch-Ns"), 10, 64)
			_, derr := fspb.Decode(m.Data(), func(rec fspb.Record) error {
				pkts++
				tss = append(tss, rec.TsNs)
				batchNs = append(batchNs, bns)
				fi := flow.Parse(rec.Frame)
				if !fi.OK {
					stray++
					_, err := insStray.ExecContext(ctx, rec.TsNs, int(rec.Dir), "other", "{}", rec.Frame)
					return err
				}
				cip, cport, sip, sport := fi.Src, fi.SrcPort, fi.Dst, fi.DstPort
				if rec.Dir == fspb.DirOut {
					cip, cport, sip, sport = fi.Dst, fi.DstPort, fi.Src, fi.SrcPort
				}
				key := strconv.Itoa(int(fi.L4)) + "|" + cip.String() + "|" + strconv.Itoa(int(cport)) + "|" + sip.String() + "|" + strconv.Itoa(int(sport))
				c := conns[key]
				if c == nil || c.materialized {
					c = &conn{id: ulid.Make().String(), started: rec.TsNs}
					conns[key] = c
					newConns++
					l4 := "tcp"
					if fi.L4 == 17 {
						l4 = "udp"
					}
					fam := 4
					if cip.Is6() && !cip.Is4In6() {
						fam = 6
					}
					if _, err := insConn.ExecContext(ctx, c.id, l4, fam, cip.String(), int(cport), sip.String(), int(sport), l4, rec.TsNs, "{}", rec.TsNs); err != nil {
						return err
					}
				}
				c.lastSeen = rec.TsNs
				c.packets++
				frame := rec.Frame
				c.pcapBytes += int64(len(frame)) + 16
				if c.pcapBytes > *pcapMax {
					c.truncated = true
					frame = frame[:min(len(frame), 128)]
				}
				if fi.TCPFlags&flow.FIN != 0 {
					if rec.Dir == fspb.DirIn {
						c.finIn = true
					} else {
						c.finOut = true
					}
				}
				if c.closeAt == 0 && (fi.TCPFlags&flow.RST != 0 || (c.finIn && c.finOut)) {
					c.closeAt = rec.TsNs + int64(time.Second)
				}
				_, err := insPkt.ExecContext(ctx, c.id, rec.TsNs, int(rec.Dir), int(rec.WireLen), frame)
				return err
			})
			if derr != nil {
				log.Printf("decode/insert: %v", derr)
			}
		}
		mu.Unlock()
		tc := time.Now()
		if err := tx.Commit(); err != nil {
			log.Fatalf("commit: %v", err)
		}
		cms := float64(time.Since(tc).Microseconds()) / 1000
		commitWin.add(cms)
		commitAll.add(cms)
		now := time.Now().UnixNano()
		for i, ts := range tss {
			ms := float64(now-ts) / 1e6
			ingestLat.add(ms)
			ingestWin.add(ms)
			if b := batchNs[i]; b > 0 {
				c, d := float64(b-ts)/1e6, float64(now-b)/1e6
				capLat.add(c)
				capWin.add(c)
				busLat.add(d)
				busWin.add(d)
			}
		}
		for _, m := range got {
			_ = m.Ack()
		}

		// Materializa pcaps de conexões fechadas ou ociosas.
		t0 := time.Now()
		var due []*conn
		mu.Lock()
		for _, c := range conns {
			if c.materialized {
				continue
			}
			if (c.closeAt != 0 && now >= c.closeAt) || now-c.lastSeen > idleClose.Nanoseconds() {
				due = append(due, c)
			}
		}
		mu.Unlock()
		if len(due) > 0 {
			materialize(ctx, w, due)
			mu.Lock()
			for _, c := range due {
				c.materialized = true
				recent = append(recent, c.id)
			}
			mu.Unlock()
			matMs = float64(time.Since(t0).Microseconds()) / 1000
		}
	}

	all, q := ingestLat.pct(0.5, 0.95, 0.99, 0.999), queryLat.pct(0.5, 0.95, 0.99)
	ca, ba := capLat.pct(0.5, 0.95, 0.99), busLat.pct(0.5, 0.95, 0.99)
	ma := commitAll.pct(0.5, 0.99, 0.9999)
	out, _ := json.Marshal(map[string]any{
		"summary": true, "seconds": time.Since(start).Seconds(), "msgs": msgs, "packets": pkts,
		"new_conns": newConns, "stray": stray, "deleted_conns": deleted, "db_bytes": dbSize(*dbPath),
		"ingest_ms_p50": all[0], "ingest_ms_p95": all[1], "ingest_ms_p99": all[2], "ingest_ms_p999": all[3],
		"query_ms_p50": q[0], "query_ms_p95": q[1], "query_ms_p99": q[2],
		"cap_ms_p50": ca[0], "cap_ms_p95": ca[1], "cap_ms_p99": ca[2],
		"commit_ms_p50": ma[0], "commit_ms_p99": ma[1], "commit_ms_max": ma[2],
		"bus_ms_p50": ba[0], "bus_ms_p95": ba[1], "bus_ms_p99": ba[2],
	})
	fmt.Println(string(out))
}

// materialize monta o pcap (formato libpcap com ns) de cada conexão, grava em pcaps e apaga os pacotes.
func materialize(ctx context.Context, w *sql.DB, due []*conn) {
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	for _, c := range due {
		rows, err := tx.QueryContext(ctx, "SELECT ts_ns, wire_len, frame FROM packets WHERE conn_id = ? ORDER BY id", c.id)
		if err != nil {
			continue
		}
		pcap := make([]byte, 24, 24+c.pcapBytes)
		binary.LittleEndian.PutUint32(pcap[0:4], 0xa1b23c4d) // nanossegundos
		binary.LittleEndian.PutUint16(pcap[4:6], 2)
		binary.LittleEndian.PutUint16(pcap[6:8], 4)
		binary.LittleEndian.PutUint32(pcap[16:20], 65535)
		binary.LittleEndian.PutUint32(pcap[20:24], 1)
		var last int64
		for rows.Next() {
			var ts, wire int64
			var f []byte
			if err := rows.Scan(&ts, &wire, &f); err != nil {
				continue
			}
			var h [16]byte
			binary.LittleEndian.PutUint32(h[0:4], uint32(ts/1e9))  //nolint:gosec // segundos
			binary.LittleEndian.PutUint32(h[4:8], uint32(ts%1e9))  //nolint:gosec // ns
			binary.LittleEndian.PutUint32(h[8:12], uint32(len(f))) //nolint:gosec // frame
			binary.LittleEndian.PutUint32(h[12:16], uint32(wire))  //nolint:gosec // frame
			pcap = append(append(pcap, h[:]...), f...)
			last = ts
		}
		_ = rows.Close()
		trunc := 0
		if c.truncated {
			trunc = 1
		}
		_, _ = tx.ExecContext(ctx, "INSERT OR REPLACE INTO pcaps (conn_id, data, truncated) VALUES (?,?,?)", c.id, pcap, trunc)
		_, _ = tx.ExecContext(ctx, "DELETE FROM packets WHERE conn_id = ?", c.id)
		_, _ = tx.ExecContext(ctx, "UPDATE connections SET ended_ns = ?, pcap_truncated = ?, updated_ns = ? WHERE conn_id = ?", last, trunc, last, c.id)
	}
	_ = tx.Commit()
}

func openDB(ctx context.Context, path string) (w, r *sql.DB) {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		log.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal(err)
	}
	w.SetMaxOpenConns(1)
	// auto_vacuum precisa vir antes da primeira tabela.
	for _, p := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL"} {
		if _, err := w.ExecContext(ctx, p); err != nil {
			log.Fatalf("%s: %v", p, err)
		}
	}
	prov, err := goose.NewProvider(goose.DialectSQLite3, w, migrations.FS)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := prov.Up(ctx); err != nil {
		log.Fatal(err)
	}
	r, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal(err)
	}
	r.SetMaxOpenConns(2)
	return w, r
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

func dbSize(path string) int64 {
	var total int64
	for _, s := range []string{"", "-wal"} {
		if st, err := os.Stat(path + s); err == nil {
			total += st.Size()
		}
	}
	return total
}
