package bot

import (
	"context"
	"testing"
	"time"

	"github.com/patrickbrandao/finger-sniffer/internal/bot/lists"
)

// Chaves das listas (ADR 0050 e 0056 item 1): ja4db desligada por padrão, URL padrão, pasta ao lado do banco,
// URLs trocáveis e só HTTPS.
func TestLoadConfigLists(t *testing.T) {
	for _, k := range []string{
		"FS_LISTEN_IPV4", "FS_LISTEN_IPV6", "FS_BOT_INTERNAL_LISTEN", "FS_BOT_INTERNAL_ALLOW",
		"FS_BOT_JA4DB_ENABLE", "FS_BOT_JA4DB_URL", "FS_BOT_DB",
	} {
		t.Setenv(k, "")
	}
	for _, s := range lists.Catalog {
		t.Setenv(lists.EnvKey(s.Name), "")
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.JA4DBEnable || c.JA4DBURL != "https://ja4db.com/api/read/" || c.ListsDir != "/finger-sniffer/var/bot/lists" ||
		len(c.ListURLs) != 0 {
		t.Fatalf("padrões: enable=%v url=%q dir=%q urls=%v", c.JA4DBEnable, c.JA4DBURL, c.ListsDir, c.ListURLs)
	}

	t.Setenv("FS_BOT_JA4DB_ENABLE", "true")
	t.Setenv("FS_BOT_DB", "/tmp/x/bot.db")
	t.Setenv("FS_BOT_LIST_AWS_URL", "https://mirror.example/aws.json")
	if c, err = LoadConfig(); err != nil {
		t.Fatal(err)
	}
	if !c.JA4DBEnable || c.ListsDir != "/tmp/x/lists" || c.ListURLs["aws"] != "https://mirror.example/aws.json" {
		t.Fatalf("trocados: %+v", c)
	}

	for k, v := range map[string]string{
		"FS_BOT_JA4DB_ENABLE":     "talvez",
		"FS_BOT_JA4DB_URL":        "http://ja4db.example/",
		"FS_BOT_LIST_GCP_URL":     "http://mirror.example/cloud.json",
		"FS_BOT_LIST_BINGBOT_URL": "ftp://x/",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := LoadConfig(); err == nil {
				t.Errorf("%s=%s aceito", k, v)
			}
		})
	}
}

// O serviço monta o gerenciador: health com a base própria e lists_version; sem ListsDir nada é baixado nem
// vence.
func TestServerLists(t *testing.T) {
	db, path := testDB(t)
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	s := New(testConfig(path), Deps{DB: db, Now: clock.Now})
	if s.Lists() == nil {
		t.Fatal("sem gerenciador de listas")
	}
	h := s.Health()
	if h.ListsVersion == "" || h.ListsVersion == "none" || len(h.Lists) != 1 || h.Lists[0].Name != lists.KnownClientsName ||
		h.Lists[0].Entries == 0 || h.Lists[0].FetchedAt != nil {
		t.Fatalf("health: %+v", h)
	}
	clock.Advance(100 * time.Hour)
	if st, reasons := s.Status(); len(reasons) != 0 {
		t.Errorf("status %s %v sem listas baixadas", st, reasons)
	}
	s.updateMetrics()
	if s.deps.Metrics.Get(`bot_list_entries{list="known_clients"}`) == 0 {
		t.Error("bot_list_entries da base própria")
	}
}

// Com a pasta de listas, uma lista vencida deixa o health degraded com `list <nome> stale`.
func TestServerListsStale(t *testing.T) {
	db, path := testDB(t)
	clock := newFakeClock(time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC))
	cfg := testConfig(path)
	cfg.ListsDir = t.TempDir() // sem cópias; Run não é chamado, então nada é baixado
	s := New(cfg, Deps{DB: db, Now: clock.Now})
	s.Lists().Load(context.Background())
	if st, _ := s.Status(); st != "ok" {
		t.Fatalf("status na partida %s", st)
	}
	clock.Advance(73 * time.Hour)
	st, reasons := s.Status()
	if st != "degraded" || len(reasons) != len(lists.Catalog) || reasons[0] != "list googlebot stale" {
		t.Fatalf("status %s %v", st, reasons)
	}
	for _, l := range s.Health().Lists {
		if l.Name != lists.KnownClientsName && !l.Stale {
			t.Errorf("%s não vencida", l.Name)
		}
		if l.Name == lists.JA4DBName {
			t.Error("ja4db desligada no health")
		}
	}
}
