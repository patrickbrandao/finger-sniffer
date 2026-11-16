package store

import (
	"database/sql"
	"os"
	"testing"
)

// Pragmas do banco no tmpfs (ADR 0045 item 4): escritor e conexão de checkpoint com synchronous=OFF,
// wal_autocheckpoint de 16384 quadros, journal_size_limit de 64 MiB e o recomeço do WAL (task 248) abaixo do
// checkpoint automático.
func TestTmpfsPragmas(t *testing.T) {
	if WALJournalLimit != 64<<20 || walAutocheckpoint != 16384 {
		t.Fatalf("WALJournalLimit %d, walAutocheckpoint %d", WALJournalLimit, walAutocheckpoint)
	}
	if WALRestartFrames >= walAutocheckpoint {
		t.Fatalf("WALRestartFrames %d must stay below wal_autocheckpoint %d", WALRestartFrames, walAutocheckpoint)
	}
	db, path := testDB(t)
	cdb, err := OpenCheckpointDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cdb.Close() }()
	for _, c := range []struct {
		db     *sql.DB
		pragma string
		want   int64
	}{
		{db, "synchronous", 0},
		{db, "wal_autocheckpoint", walAutocheckpoint},
		{db, "journal_size_limit", WALJournalLimit},
		{cdb, "synchronous", 0},
	} {
		var got int64
		if err := c.db.QueryRowContext(t.Context(), "PRAGMA "+c.pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("PRAGMA %s = %d, want %d", c.pragma, got, c.want)
		}
	}
}

// walSizeAfterRestart enche o WAL com ~3 MiB, faz o recomeço (CheckpointRestart) e uma escrita, e devolve o
// tamanho do arquivo do WAL depois dela.
func walSizeAfterRestart(t *testing.T) int64 {
	t.Helper()
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
	for range 200 {
		if _, err := db.ExecContext(ctx, "INSERT INTO blob_t VALUES (zeroblob(16384))"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CheckpointRestart(ctx, db, cdb, 100, nil); err != nil {
		t.Fatal(err)
	}
	// a escrita depois do checkpoint completo recomeça o WAL (e o corta ao journal_size_limit)
	if _, err := db.ExecContext(ctx, "INSERT INTO blob_t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if wal, _, err := Checkpoint(ctx, cdb); err != nil || wal > 20 {
		t.Fatalf("WAL must restart from the beginning: %d frames, err %v", wal, err)
	}
	st, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// Com o limite padrão o arquivo do WAL guarda o tamanho depois do recomeço (sem blocos novos no próximo ciclo);
// com um limite menor que ele, é cortado, como antes da task 246.
func TestWALKeepsSizeOnRestart(t *testing.T) {
	if size := walSizeAfterRestart(t); size < 3<<20 {
		t.Fatalf("WAL file truncated to %d bytes on restart with the default limit", size)
	}
	old := WALJournalLimit
	WALJournalLimit = 1 << 20
	t.Cleanup(func() { WALJournalLimit = old })
	if size := walSizeAfterRestart(t); size > 1<<20 {
		t.Fatalf("WAL file %d bytes, want ≤ 1 MiB with journal_size_limit 1 MiB", size)
	}
}
