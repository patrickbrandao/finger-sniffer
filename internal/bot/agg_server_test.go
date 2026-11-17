package bot

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/agg"
	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// TestAggRetentionServer: relógio falso de ponta a ponta no serviço (Observe → flush → expurgo): nada com IP no
// banco nem na memória passa de 7 dias e 1 hora; o expurgo por idade conta bot_purged_total{reason="age"}.
func TestAggRetentionServer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.srv
	ip := netip.MustParseAddr("192.0.2.33")
	start := f.clock.Now()
	s.Agg().Observe(agg.Request{
		Time: start, IP: ip, Site: "s.com", Path: "/", Class: agg.ClassHuman,
		UAFamily: "curl", Fingerprints: []agg.Fingerprint{{Kind: "ja4t", Value: "64240_2-4-8-1-3_1460_7"}},
	})
	if err := s.flushAgg(ctx); err != nil {
		t.Fatal(err)
	}
	count := func(q string) (n int) {
		t.Helper()
		if err := f.db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("SELECT count(*) FROM ip_hourly") != 1 || count("SELECT count(*) FROM fp_daily") != 1 {
		t.Fatal("flush não gravou")
	}
	for h := 1; h <= 7*24+1; h++ {
		f.clock.Advance(time.Hour)
		if err := s.flushAgg(ctx); err != nil {
			t.Fatal(err)
		}
		s.purge(ctx)
		now := f.clock.Now()
		var oldest *int64
		_ = f.db.QueryRow("SELECT min(hour) FROM ip_hourly").Scan(&oldest)
		if oldest != nil && now.Sub(time.Unix(*oldest*3600, 0)) > MaxAggRetention+time.Hour {
			t.Fatalf("hora %d: linha com IP de %s", h, now.Sub(time.Unix(*oldest*3600, 0)))
		}
		if s.Agg().Query(ip, "s.com", now).Known && now.Sub(start) > 24*time.Hour {
			t.Fatalf("hora %d: IP ainda no cache", h)
		}
	}
	// o dia do fp_daily começou às 00:00 e o relógio às 12:00: depois de 7 dias e 1 hora ele também já saiu
	if count("SELECT count(*) FROM ip_hourly") != 0 || count("SELECT count(*) FROM fp_daily") != 0 {
		t.Fatal("ip_hourly ou fp_daily não expurgado")
	}
	if got := f.metrics.Get(`bot_purged_total{reason="age"}`); got != 2 {
		t.Fatalf(`bot_purged_total{reason="age"} = %v`, got)
	}
	s.updateMetrics()
	if _, ok := f.metrics.Snapshot()["bot_agg_dropped_total"]; !ok {
		t.Fatal("bot_agg_dropped_total ausente")
	}
}

// TestPurgeSize: banco acima do teto expurga as horas mais antigas até caber e conta reason="size".
func TestPurgeSize(t *testing.T) {
	db, path := testDB(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC).Unix() / 3600
	pad := strings.Repeat("x", 200)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for h := range int64(48) {
		for i := range 200 {
			ip := ipKey(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
			if _, err := tx.Exec("INSERT INTO ip_hourly (ip, site, hour, requests) VALUES (?, ?, ?, 1)",
				ip, fmt.Sprintf("%s-%d.example", pad, i), base+h); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := tx.Exec("INSERT INTO fp_daily (kind, value, day, ua_family) VALUES ('ja4', 'a', ?, 'x'), ('ja4', 'b', ?, 'x')",
		base/24-1, base/24+1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	full := dbFileSize(path)
	maxBytes := full / 2

	cfg := testConfig(path)
	cfg.MaxBytes = maxBytes
	m := service.NewMetrics()
	s := New(cfg, Deps{DB: db, Metrics: m})
	s.purgeSize(ctx)

	if size := dbFileSize(path); size > maxBytes {
		t.Fatalf("banco com %d bytes, teto %d (antes %d)", size, maxBytes, full)
	}
	var minHour, maxHour int64
	var rows int
	if err := db.QueryRow("SELECT min(hour), max(hour), count(*) FROM ip_hourly").Scan(&minHour, &maxHour, &rows); err != nil {
		t.Fatal(err)
	}
	if maxHour != base+47 || minHour <= base || rows != int(maxHour-minHour+1)*200 {
		t.Fatalf("horas %d..%d (%d linhas): não saíram só as mais antigas", minHour-base, maxHour-base, rows)
	}
	var fp int
	_ = db.QueryRow("SELECT count(*) FROM fp_daily").Scan(&fp)
	if fp != 1 {
		t.Fatalf("fp_daily %d (o dia anterior às horas devia sair)", fp)
	}
	want := float64(48*200 - rows + 1)
	if got := m.Get(`bot_purged_total{reason="size"}`); got != want {
		t.Fatalf(`bot_purged_total{reason="size"} = %v, quer %v`, got, want)
	}
	// Abaixo do teto não apaga nada.
	if n, err := PurgeSize(ctx, db, path, full*4); err != nil || n != 0 {
		t.Fatalf("purge abaixo do teto: %d %v", n, err)
	}
}
