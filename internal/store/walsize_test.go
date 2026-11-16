package store

import (
	"os"
	"testing"
)

// O WAL não é cortado quando recomeça no uso normal (task 246): o journal_size_limit fica acima do maior WAL
// normal, o do wal_autocheckpoint.
func TestWALJournalLimitAboveAutocheckpoint(t *testing.T) {
	const autocheckpointBytes = 65536 * 4096 // wal_autocheckpoint(65536) do OpenDB, páginas de 4 KiB
	if WALJournalLimit < autocheckpointBytes || WALJournalLimit < WALRestartFrames*4096 {
		t.Fatalf("WALJournalLimit %d below the normal WAL size (%d)", WALJournalLimit, autocheckpointBytes)
	}
	db, _ := testDB(t)
	var got int64
	if err := db.QueryRowContext(t.Context(), "PRAGMA journal_size_limit").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != WALJournalLimit {
		t.Fatalf("journal_size_limit %d, want %d", got, WALJournalLimit)
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
	if _, err := CheckpointRestart(ctx, db, cdb, path, 100, nil); err != nil {
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
